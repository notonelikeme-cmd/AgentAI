"""VerificationLoop — orchestrates all 7 gates in sequence."""
import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.models import CURATED_MODELS, model_profile


@dataclass
class GateData:
    gate: int
    status: str  # PASS / FAIL / SKIP
    reason: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


class VerificationLoop:
    """Chains gates 1-7, halts on first failure."""

    async def run(
        self,
        hypothesis: str,
        contract: str,
        block: Optional[int] = None,
        model: Optional[str] = None,
    ) -> dict:
        model = model or CURATED_MODELS[0]
        gate_data: Dict[str, Any] = {
            "hypothesis": hypothesis,
            "contract": contract,
            "block": block,
            "model": model,
            "model_profile": model_profile(model),
        }
        results: List[GateData] = []

        gates = [
            self._gate1_hypothesis,
            self._gate2_evidence,
            self._gate3_simulation,
            self._gate4_replay,
            self._gate5_economics,
            self._gate6_adversarial,
            self._gate7_reproducibility,
        ]

        for i, gate_fn in enumerate(gates, start=1):
            print(f"[Gate {i}] Running...")
            result = await gate_fn(gate_data)
            results.append(result)
            gate_data[f"gate{i}"] = result.data
            print(f"[Gate {i}] {result.status}: {result.reason}")

            if result.status == "FAIL":
                return self._format_result(hypothesis, results, "BLOCKED", i)

        return self._format_result(hypothesis, results, "VERIFIED", 7)

    async def _gate1_hypothesis(self, data: dict) -> GateData:
        h = data["hypothesis"]
        if not h or len(h) < 20:
            return GateData(1, "FAIL", "Hypothesis too vague")
        required = ["if", "then", "because"]
        h_lower = h.lower()
        missing = [k for k in required if k not in h_lower]
        if missing:
            return GateData(
                1, "FAIL",
                f"Hypothesis missing keywords: {missing}. Format: IF [condition] THEN [impact] BECAUSE [mechanism]"
            )
        return GateData(1, "PASS", "Falsifiable hypothesis", {"hypothesis": h})

    async def _gate2_evidence(self, data: dict) -> GateData:
        # Check if citations are embedded in hypothesis or provided separately
        h = data["hypothesis"]
        import re
        citations = re.findall(r'\w+\.sol:\d+', h)
        if not citations:
            return GateData(
                2, "FAIL",
                "No code citations found. Format: src/Contract.sol:142. "
                "Run grep to find exact locations before proceeding."
            )
        return GateData(2, "PASS", f"Found {len(citations)} citation(s)", {"citations": citations})

    async def _gate3_simulation(self, data: dict) -> GateData:
        # Check if simulation results are provided
        sim_data = data.get("gate3_simulation_result")
        if sim_data:
            balance_delta = sim_data.get("balance_delta", 0)
            if balance_delta <= 0:
                return GateData(3, "FAIL", f"balance_delta={balance_delta} — not exploitable")
            return GateData(3, "PASS", f"PoC executed: balance_delta={balance_delta}", sim_data)
        return GateData(
            3, "FAIL",
            "No simulation result provided. Run: trinity.py simulate --contract <path> --block <N>"
        )

    async def _gate4_replay(self, data: dict) -> GateData:
        replay = data.get("gate4_replay_results", [])
        if len(replay) < 2:
            return GateData(4, "FAIL", "Need ≥2 simulation runs for determinism check")
        deltas = [r.get("balance_delta") for r in replay]
        if len(set(deltas)) > 1:
            return GateData(4, "FAIL", f"Non-deterministic: deltas={deltas}")
        return GateData(4, "PASS", f"Deterministic across {len(replay)} runs: delta={deltas[0]}")

    async def _gate5_economics(self, data: dict) -> GateData:
        econ = data.get("gate5_economics", {})
        if not econ:
            return GateData(
                5, "FAIL",
                "No economics data. Provide: balance_delta, gas_cost, flash_loan_fee, slippage"
            )
        balance_delta = econ.get("balance_delta", 0)
        gas_cost = econ.get("gas_cost", 0)
        flash_fee = econ.get("flash_loan_fee", 0)
        slippage = econ.get("slippage", 0)
        net_profit = balance_delta - gas_cost - flash_fee - slippage
        econ["net_profit"] = net_profit
        if net_profit <= 0:
            return GateData(5, "FAIL", f"Economically nonviable: net_profit=${net_profit:.2f}", econ)
        return GateData(5, "PASS", f"Economically viable: net_profit=${net_profit:.2f}", econ)

    async def _gate6_adversarial(self, data: dict) -> GateData:
        adv = data.get("gate6_adversarial_result", {})
        if not adv:
            return GateData(
                6, "FAIL",
                "No adversarial review. Launch verification-adversary agent to attempt refutation."
            )
        if adv.get("refuted"):
            return GateData(6, "FAIL", f"Refuted: {adv.get('reason', 'see adversarial review')}")
        return GateData(6, "PASS", "Survived adversarial challenge", adv)

    async def _gate7_reproducibility(self, data: dict) -> GateData:
        repro = data.get("gate7_reproduction_guide")
        if not repro:
            return GateData(
                7, "FAIL",
                "No reproduction guide. Document exact steps: fork block, calldata, expected result."
            )
        if len(repro) < 100:
            return GateData(7, "FAIL", "Reproduction guide too brief — must be independently executable")
        return GateData(7, "PASS", "Reproduction guide complete", {"guide_length": len(repro)})

    def _format_result(self, hypothesis: str, results: List[GateData], verdict: str, final_gate: int) -> dict:
        return {
            "hypothesis": hypothesis,
            "verdict": verdict,
            "final_gate": final_gate,
            "gates": [
                {
                    "gate": r.gate,
                    "status": r.status,
                    "reason": r.reason,
                }
                for r in results
            ],
            "summary": (
                f"VERIFIED — passed all {final_gate} gates"
                if verdict == "VERIFIED"
                else f"BLOCKED at Gate {final_gate}: {results[-1].reason}"
            ),
        }
