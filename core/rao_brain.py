"""RAOBrain — hypothesis generator for the Reason-Act-Observe loop.

Combines the DeFi knowledge graph with CFG analysis to rank hypotheses
by likelihood for a given contract. Each iteration refines the ranked list
based on what was verified or blocked in prior observations.
"""
from __future__ import annotations

import re
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

    def __init__(self, db_path: Optional[str] = None):
        self._kg = DeFiKnowledgeGraph(db_path=db_path)
        self._cfg_builder = CFGBuilder()
        self._observation_log: List[dict] = []

    def generate(
        self,
        contract_path: str,
        context: Optional[Dict[str, Any]] = None,
        top_n: int = 10,
    ) -> List[Hypothesis]:
        """Return top-N ranked hypotheses for the given contract."""
        # Build CFG signals
        try:
            cfg = self._cfg_builder.build(contract_path)
        except Exception:
            cfg = {}

        signals = self._extract_signals(cfg)

        # All KG patterns → scored hypotheses
        all_patterns = self._kg._con.execute(
            "SELECT * FROM patterns ORDER BY severity"
        ).fetchall()

        hypotheses = []
        for row in all_patterns:
            p = dict(row)
            score = _SEVERITY_PRIOR.get(p["severity"], 0.1)
            hints = []

            # Boost based on CFG signals matching this pattern class
            for signal, mult in _CFG_MULTIPLIERS.items():
                if signals.get(signal) and self._signal_matches(signal, p):
                    score = min(score * mult, 0.95)
                    hints.append(signal)

            # Adjust based on prior observations
            score = self._adjust_for_observations(score, p["id"])

            # Filter out very low confidence
            if score < 0.08:
                continue

            text = self._format_hypothesis(p, contract_path)
            hypotheses.append(Hypothesis(
                text=text,
                pattern_id=p["id"],
                score=score,
                rationale=f"[{p['severity']}] {p['mechanism']}/{p['class']}",
                evidence_hints=hints,
            ))

        # Sort by score descending
        hypotheses.sort(key=lambda h: h.score, reverse=True)
        return hypotheses[:top_n]

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
