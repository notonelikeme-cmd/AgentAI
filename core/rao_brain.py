"""RAOBrain — hypothesis generator for the Reason-Act-Observe loop.

Combines the DeFi knowledge graph with CFG analysis to rank hypotheses
by likelihood for a given contract. Each iteration refines the ranked list
based on what was verified or blocked in prior observations.
"""
from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.analysis.defi_kg import DeFiKnowledgeGraph
from core.analysis.cfg_builder import CFGBuilder


@dataclass
class Hypothesis:
    text: str
    pattern_id: str
    score: float          # 0.0 – 1.0 prior probability
    rationale: str = ""
    evidence_hints: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "pattern_id": self.pattern_id,
            "score": round(self.score, 3),
            "rationale": self.rationale,
            "evidence_hints": self.evidence_hints,
        }


# Severity → base prior probability
_SEVERITY_PRIOR = {
    "Critical": 0.45,
    "High":     0.30,
    "Medium":   0.20,
    "Low":      0.10,
    "Info":     0.05,
}

# CFG signal → score multiplier
_CFG_MULTIPLIERS = {
    "has_payable":          1.4,
    "no_access_control":    1.3,
    "has_unchecked":        1.2,
    "direct_balance_of":    1.3,
    "external_call_before": 1.5,
    "has_selfdestruct":     2.0,
    "has_delegation":       1.3,
}


class RAOBrain:
    """Generates and ranks hypotheses from contract structure + KG patterns."""

    def __init__(self, db_path: Optional[str] = None, hf_db_path: Optional[str] = None):
        self._kg = DeFiKnowledgeGraph(db_path=db_path)
        self._cfg_builder = CFGBuilder()
        self._observation_log: List[dict] = []
        # Optional: HF empirical severity cache  {mechanism: high_rate 0.0-1.0}
        self._hf_boost_cache: Dict[str, float] = {}
        self._hf_db_path = hf_db_path

    def generate(
        self,
        contract_path: str,
        context: Optional[Dict[str, Any]] = None,
        top_n: int = 10,
        use_llm: bool = True,
    ) -> List[Hypothesis]:
        """Return top-N ranked hypotheses.

        Priority order:
          1. LLM-derived from real source (LLMAuditor) — contract-specific
          2. KG template hypotheses — generic fallback
        """
        llm_hypotheses: List[Hypothesis] = []
        if use_llm:
            try:
                from core.llm_auditor import LLMAuditor
                auditor = LLMAuditor(max_functions=12)
                raw = auditor.analyze(contract_path, verbose=True)
                llm_hypotheses = [h.to_hypothesis() for h in raw]
                print(f"[RAOBrain] LLMAuditor: {len(llm_hypotheses)} contract-specific hypothesis(es)")
            except Exception as e:
                print(f"[RAOBrain] LLMAuditor unavailable ({e}) — falling back to KG templates")

        # If LLM gave us enough, return those first (padded with KG if needed)
        if len(llm_hypotheses) >= top_n:
            return llm_hypotheses[:top_n]

        # KG template fallback (or padding)
        try:
            cfg = self._cfg_builder.build(contract_path)
        except Exception:
            cfg = {}

        signals = self._extract_signals(cfg)

        all_patterns = self._kg._con.execute(
            "SELECT * FROM patterns ORDER BY severity"
        ).fetchall()

        # Parallel scoring across all CPU cores (M5 Max: 18 cores)
        workers = min(len(all_patterns), os.cpu_count() or 4)

        def score_pattern(row) -> Optional[Hypothesis]:
            p = dict(row)
            score = _SEVERITY_PRIOR.get(p["severity"], 0.1)
            # Boost from HF empirical data
            score *= (1.0 + self._hf_severity_boost(p["mechanism"]))
            hints = []
            for signal, mult in _CFG_MULTIPLIERS.items():
                if signals.get(signal) and self._signal_matches(signal, p):
                    score = min(score * mult, 0.95)
                    hints.append(signal)
            score = self._adjust_for_observations(score, p["id"])
            if score < 0.08:
                return None
            return Hypothesis(
                text=self._format_hypothesis(p, contract_path),
                pattern_id=p["id"],
                score=score,
                rationale=f"[{p['severity']}] {p['mechanism']}/{p['class']}",
                evidence_hints=hints,
            )

        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(score_pattern, all_patterns))

        kg_hypotheses = [h for h in results if h is not None]
        kg_hypotheses.sort(key=lambda h: h.score, reverse=True)

        # Merge: LLM first (already contract-specific), then KG padding
        llm_ids = {h.pattern_id for h in llm_hypotheses}
        kg_pad = [h for h in kg_hypotheses if h.pattern_id not in llm_ids]
        merged = llm_hypotheses + kg_pad

        # Elevate chained vulnerability pairs before returning
        if len(merged) > 1:
            merged = self.chain_score(merged)

        return merged[:top_n]

    def _hf_severity_boost(self, mechanism: str) -> float:
        """Return empirical High/Critical rate for a mechanism from HF training data."""
        if mechanism in self._hf_boost_cache:
            return self._hf_boost_cache[mechanism]

        try:
            import sqlite3
            from pathlib import Path
            db = self._hf_db_path or str(
                Path.home() / "AgentAI" / "training_data" / "hf_training.db"
            )
            con = sqlite3.connect(db, check_same_thread=False, timeout=5)
            # Count High/Critical vs total in severity-classification dataset
            kw = f"%{mechanism.replace('_', ' ')}%"
            total = con.execute(
                "SELECT COUNT(*) FROM hf_samples WHERE lower(data) LIKE ?", (kw,)
            ).fetchone()[0]
            high = con.execute(
                "SELECT COUNT(*) FROM hf_samples WHERE lower(data) LIKE ? "
                "AND (lower(data) LIKE '%\"high\"%' OR lower(data) LIKE '%\"critical\"%')",
                (kw,),
            ).fetchone()[0]
            con.close()
            rate = (high / total) if total > 0 else 0.0
            self._hf_boost_cache[mechanism] = rate
            return rate
        except Exception:
            return 0.0

    def observe(self, pattern_id: str, verdict: str, gate: int, details: str = ""):
        """Record a gate result to refine future hypothesis scoring."""
        self._observation_log.append({
            "pattern_id": pattern_id,
            "verdict": verdict,   # VERIFIED | BLOCKED
            "gate": gate,
            "details": details,
        })

    def reset_observations(self):
        self._observation_log = []

    def chain_score(self, hypotheses: List[Hypothesis]) -> List[Hypothesis]:
        """
        Detect dangerous hypothesis chains and elevate combined scores.

        If hypothesis A identifies missing access control AND hypothesis B
        identifies reentrancy in the same contract, their combination is
        Critical-class even if each individually scores Medium.

        Chain rules:
          access_control + reentrancy   → multiply both by 1.6
          oracle_manipulation + flash_loan → multiply both by 1.5
          missing_check + external_call → multiply both by 1.4
        """
        _CHAIN_RULES = [
            ({"access_control", "missing_access_control"}, {"reentrancy"},         1.6),
            ({"oracle", "oracle_manipulation"},             {"flash_loan"},          1.5),
            ({"missing_check", "access_control"},           {"external_call"},       1.4),
            ({"share_inflation", "donation"},               {"vault_accounting"},    1.4),
        ]

        def _keywords(h: Hypothesis) -> set:
            text = (h.text + " " + h.pattern_id + " " + h.rationale).lower()
            # Keep both compound forms (access_control) and split forms (access, control)
            words = re.split(r"[\s\-/]", text)
            result = set()
            for w in words:
                w = w.strip(".,;:()")
                if len(w) > 3:
                    result.add(w)
                    # Also add split-by-underscore variants
                    for part in w.split("_"):
                        if len(part) > 3:
                            result.add(part)
            return result

        kw_sets = [_keywords(h) for h in hypotheses]
        boosted = set()

        for i, h_a in enumerate(hypotheses):
            for j, h_b in enumerate(hypotheses):
                if i >= j:
                    continue
                kw_a, kw_b = kw_sets[i], kw_sets[j]
                for set_a, set_b, mult in _CHAIN_RULES:
                    a_match = set_a & kw_a
                    b_match = set_b & kw_b
                    if a_match and b_match and (i, j) not in boosted:
                        hypotheses[i].score = min(hypotheses[i].score * mult, 0.97)
                        hypotheses[j].score = min(hypotheses[j].score * mult, 0.97)
                        hypotheses[i].rationale += f" [CHAIN→{list(b_match)[0]}]"
                        hypotheses[j].rationale += f" [CHAIN→{list(a_match)[0]}]"
                        boosted.add((i, j))
                        print(f"[ChainScore] {h_a.pattern_id} ⟷ {h_b.pattern_id}: x{mult}")

        hypotheses.sort(key=lambda h: h.score, reverse=True)
        return hypotheses

    # ── Internals ──────────────────────────────────────────────────────────

    def _extract_signals(self, cfg: dict) -> Dict[str, bool]:
        signals: Dict[str, bool] = {}
        if not cfg or "contracts" not in cfg:
            return signals

        for contract in cfg.get("contracts", {}).values():
            for fn in contract.get("functions", {}).values():
                if fn.get("is_payable"):
                    signals["has_payable"] = True
                if not fn.get("modifiers") and fn.get("visibility") in ("public", "external"):
                    if fn.get("mutability") not in ("view", "pure"):
                        signals["no_access_control"] = True
                for call in fn.get("calls", []):
                    if any(k in call.lower() for k in (".call", "transfer", "transferfrom")):
                        if fn.get("state_writes"):
                            signals["external_call_before"] = True

        # Signals from state vars / summary
        entry_points = cfg.get("summary", {}).get("external_entry_points", [])
        if len(entry_points) > 8:
            signals["many_entry_points"] = True

        return signals

    def _signal_matches(self, signal: str, pattern: dict) -> bool:
        class_ = pattern.get("class", "")
        mech = pattern.get("mechanism", "")
        mapping = {
            "has_payable":          lambda: "lending" in class_ or "vault" in class_,
            "no_access_control":    lambda: "access_control" in class_,
            "has_unchecked":        lambda: "arithmetic" in class_,
            "direct_balance_of":    lambda: "conservation" in class_ or "vault" in class_,
            "external_call_before": lambda: "reentrancy" in class_ or "reentrancy" in mech,
            "has_selfdestruct":     lambda: "frozen_funds" in class_ or "proxy" in class_,
            "has_delegation":       lambda: "proxy" in class_ or "storage_collision" in class_,
        }
        fn = mapping.get(signal)
        return fn() if fn else False

    def _adjust_for_observations(self, score: float, pattern_id: str) -> float:
        for obs in self._observation_log:
            if obs["pattern_id"] != pattern_id:
                continue
            if obs["verdict"] == "VERIFIED":
                score = min(score * 1.5, 0.99)
            elif obs["verdict"] == "BLOCKED":
                gate = obs.get("gate", 7)
                # Blocked early = strong signal against; blocked late = mild
                penalty = 0.5 if gate <= 2 else (0.7 if gate <= 5 else 0.9)
                score *= penalty
        return score

    def _format_hypothesis(self, pattern: dict, contract_path: str) -> str:
        return (
            f"IF {pattern['mechanism']} vulnerability exists in {contract_path} "
            f"THEN attacker can {pattern['impact']} "
            f"BECAUSE {pattern['description']} — see <contract>.sol:<line>"
        )

    def enrich_hypothesis(self, hypothesis: "Hypothesis", router=None) -> "Hypothesis":
        """Use ModelRouter to rewrite hypothesis into precise Gate 1 format (IF/THEN/BECAUSE)."""
        if router is None:
            try:
                from core.model_router import ModelRouter
                router = ModelRouter()
            except Exception:
                return hypothesis

        system = (
            "You are a DeFi security auditor. Rewrite the given vulnerability hypothesis "
            "into exactly this format: "
            "IF [specific condition in the contract] "
            "THEN [attacker action and profit mechanism] "
            "BECAUSE [root cause — the exact code flaw]. "
            "One sentence. No preamble."
        )
        try:
            enriched_text = router.complete(hypothesis.text, system=system, gate=1)
            hypothesis.text = enriched_text.strip()
        except Exception:
            pass
        return hypothesis
