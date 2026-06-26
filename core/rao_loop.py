"""RAOLoop — Reason-Act-Observe autonomous exploit-discovery loop.

Each iteration:
  Reason  — RAOBrain generates ranked hypotheses from contract + KG
  Act     — Run top hypothesis through Gate 0 + partial VerificationLoop
  Observe — Record verdict, refine brain scores, decide whether to continue
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.rao_brain import RAOBrain
from core.gates.gate0_novelty import Gate0Novelty
from core.gates.verification_loop import VerificationLoop
from core.analysis.findingsdb import FindingsDB
from core.models import CURATED_MODELS


@dataclass
class RAOIteration:
    iteration: int
    hypothesis: str
    pattern_id: str
    prior_score: float
    gate0_result: dict = field(default_factory=dict)
    gate_results: list = field(default_factory=list)
    verdict: str = "PENDING"
    final_gate: int = 0

    def to_dict(self) -> dict:
        return {
            "iteration": self.iteration,
            "hypothesis": self.hypothesis,
            "pattern_id": self.pattern_id,
            "prior_score": round(self.prior_score, 3),
            "gate0_novel": self.gate0_result.get("novel", None),
            "verdict": self.verdict,
            "final_gate": self.final_gate,
        }


class RAOLoop:
    """Autonomous Reason-Act-Observe vulnerability discovery loop."""

    def __init__(
        self,
        contract_path: str,
        block_number: Optional[int] = None,
        mode: str = "default",
        baseline: Optional[str] = None,
        max_iterations: int = 5,
        model: Optional[str] = None,
        db_path: Optional[str] = None,
    ):
        self.contract_path = contract_path
        self.block_number = block_number
        self.mode = mode
        self.baseline = baseline
        self.max_iterations = max_iterations
        self.model = model or CURATED_MODELS[0]

        self._brain = RAOBrain(db_path=db_path)
        self._gate0 = Gate0Novelty()
        self._vloop = VerificationLoop()
        self._db = FindingsDB()
        self._tried: set = set()

    async def run(self) -> dict:
        start = datetime.utcnow()
        iterations: List[RAOIteration] = []
        verified_findings: List[dict] = []

        for i in range(1, self.max_iterations + 1):
            print(f"\n[RAO iter {i}/{self.max_iterations}] Reasoning...")

            # Reason: get ranked hypotheses, skip already tried
            candidates = self._brain.generate(
                self.contract_path,
                top_n=self.max_iterations * 3,
            )
            untried = [h for h in candidates if h.pattern_id not in self._tried]
            if not untried:
                print("  No untried hypotheses remaining — loop complete.")
                break

            top = untried[0]
            self._tried.add(top.pattern_id)

            print(f"  Act: [{top.score:.2f}] {top.pattern_id}: {top.text[:80]}...")

            rao_iter = RAOIteration(
                iteration=i,
                hypothesis=top.text,
                pattern_id=top.pattern_id,
                prior_score=top.score,
            )

            # Gate 0 first
            g0 = self._gate0.check(top.text)
            rao_iter.gate0_result = g0
            if not g0.get("novel", True):
                print(f"  Gate 0: NOT NOVEL — skipping")
                rao_iter.verdict = "BLOCKED"
                rao_iter.final_gate = 0
                self._brain.observe(top.pattern_id, "BLOCKED", 0, "not novel")
                iterations.append(rao_iter)
                continue

            # Run pipeline gates
            result = await self._vloop.run(
                hypothesis=top.text,
                contract=self.contract_path,
                block=self.block_number,
                model=self.model,
            )

            rao_iter.gate_results = result.get("gates", [])
            rao_iter.verdict = result.get("verdict", "BLOCKED")
            rao_iter.final_gate = result.get("final_gate", 0)

            # Observe
            self._brain.observe(
                top.pattern_id,
                rao_iter.verdict,
                rao_iter.final_gate,
                result.get("summary", ""),
            )

            if rao_iter.verdict == "VERIFIED":
                print(f"  VERIFIED — saving to findings DB")
                fid = self._db.add(
                    title=f"RAO-{top.pattern_id}: {top.rationale}",
                    severity=self._pattern_severity(top.pattern_id),
                    contract=self.contract_path,
                    hypothesis=top.text,
                    gate_status=str(rao_iter.final_gate),
                )
                verified_findings.append({"finding_id": fid, **result})
            else:
                print(f"  BLOCKED at gate {rao_iter.final_gate}: {result.get('summary', '')[:60]}")

            iterations.append(rao_iter)

        elapsed = (datetime.utcnow() - start).total_seconds()

        return {
            "contract": self.contract_path,
            "model": self.model,
            "mode": self.mode,
            "max_iterations": self.max_iterations,
            "iterations_run": len(iterations),
            "verified_count": len(verified_findings),
            "verified_findings": verified_findings,
            "iterations": [it.to_dict() for it in iterations],
            "elapsed_seconds": round(elapsed, 1),
            "summary": (
                f"{len(verified_findings)} verified finding(s) in "
                f"{len(iterations)} iteration(s) over {elapsed:.1f}s"
            ),
        }

    def _pattern_severity(self, pattern_id: str) -> str:
        try:
            p = self._brain._kg.get_pattern(pattern_id)
            return p["severity"] if p else "Medium"
        except Exception:
            return "Medium"
