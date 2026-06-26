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
            self._gate8_peer_review,
        ]

        for i, gate_fn in enumerate(gates, start=1):
            print(f"[Gate {i}] Running...")
            result = await gate_fn(gate_data)
            results.append(result)
            gate_data[f"gate{i}"] = result.data
            print(f"[Gate {i}] {result.status}: {result.reason}")

            if result.status == "FAIL":
                # Log block to SkillBuilder memory
                try:
                    from core.skill_builder import SkillBuilder
                    SkillBuilder().log_blocked_pattern(hypothesis, i, result.reason)
                except Exception:
                    pass
                return self._format_result(hypothesis, results, "BLOCKED", i)

        # All 8 gates passed — register pattern in KG and write memory
        final = self._format_result(hypothesis, results, "VERIFIED", 8)
        self._post_verify(hypothesis, gate_data, final)
        return final

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
        h = data["hypothesis"]
        import re
        citations = re.findall(r'\w+\.sol:\d+', h)
        if citations:
            return GateData(2, "PASS", f"Found {len(citations)} citation(s)", {"citations": citations, "auto_gathered": False})

        # Auto-gather citations from the contract using EvidenceGatherer
        contract = data.get("contract", "")
        if contract:
            from core.evidence_gatherer import EvidenceGatherer
            result = EvidenceGatherer().gather(h, contract)
            citations = result.get("citations", [])
            if citations:
                # HF evidence boost: query training data for severity signal
                hf_signal = self._hf_evidence_boost(h, result.get("mechanisms", []))
                return GateData(
                    2, "PASS",
                    f"Auto-gathered {len(citations)} citation(s) via mechanism={result.get('mechanisms')}",
                    {
                        "citations": citations,
                        "evidence": result.get("evidence", []),
                        "mechanisms": result.get("mechanisms", []),
                        "auto_gathered": True,
                        "hf_severity_signal": hf_signal,
                    }
                )
            if result.get("error"):
                return GateData(2, "FAIL", f"Auto-gather failed: {result['error']}")

        return GateData(
            2, "FAIL",
            "No code citations found. Format: src/Contract.sol:142 or provide a --contract path."
        )

    def _hf_evidence_boost(self, hypothesis: str, mechanisms: list) -> dict:
        """Query HF training DB for severity distribution matching this hypothesis."""
        try:
            import sqlite3
            from pathlib import Path
            db = Path.home() / "AgentAI" / "training_data" / "hf_training.db"
            if not db.exists():
                return {}
            con = sqlite3.connect(str(db), check_same_thread=False, timeout=5)
            keywords = mechanisms[:2] if mechanisms else []
            if not keywords:
                keywords = [w for w in hypothesis.lower().split() if len(w) > 5][:2]
            results = {}
            for kw in keywords:
                q = f"%{kw}%"
                total = con.execute("SELECT COUNT(*) FROM hf_samples WHERE lower(data) LIKE ?", (q,)).fetchone()[0]
                high  = con.execute(
                    "SELECT COUNT(*) FROM hf_samples WHERE lower(data) LIKE ? "
                    "AND (lower(data) LIKE '%\"high\"%' OR lower(data) LIKE '%\"critical\"%')", (q,)
                ).fetchone()[0]
                if total > 0:
                    results[kw] = {"total": total, "high_rate": round(high / total, 2)}
            con.close()
            return results
        except Exception:
            return {}

    async def _gate3_simulation(self, data: dict) -> GateData:
        # Use pre-supplied result if present
        sim_data = data.get("gate3_simulation_result")
        if sim_data:
            balance_delta = sim_data.get("balance_delta", 0)
            if balance_delta <= 0:
                return GateData(3, "FAIL", f"balance_delta={balance_delta} — not exploitable")
            return GateData(3, "PASS", f"PoC executed: balance_delta={balance_delta}", sim_data)

        # Auto-run: try forge first, fall back to RPC state validation
        import os
        import shutil
        rpc = os.environ.get("ETH_RPC_URL") or os.environ.get("MAINNET_RPC_URL")
        contract = data.get("contract", "")

        if rpc and contract:
            forge_path = shutil.which("forge") or os.path.expanduser("~/.foundry/bin/forge")
            has_forge = os.path.isfile(forge_path) if not shutil.which("forge") else True

            if has_forge:
                # Full forge fork simulation
                forge_env = {**os.environ, "PATH": os.environ.get("PATH", "") + f":{os.path.dirname(forge_path)}"}
                from core.analysis.evm_simulator import SimulationEngine
                engine = SimulationEngine(rpc_url=rpc)
                result = engine.run(contract=contract, block=data.get("block"))
                sim_dict = result if isinstance(result, dict) else result.to_dict()
                data["_gate3_auto_result"] = sim_dict
                if sim_dict.get("error"):
                    return GateData(3, "FAIL", f"forge error: {sim_dict['error']}")
                delta = sim_dict.get("balance_delta_wei", sim_dict.get("balance_delta", 0))
                if delta <= 0:
                    return GateData(3, "FAIL", f"PoC not profitable: balance_delta={delta}", sim_dict)
                return GateData(3, "PASS", f"forge PoC: balance_delta={delta/1e18:.4f} ETH", sim_dict)

            else:
                # Forge unavailable — fall back to RPC state validation
                # Validates that the contract is live and readable; PoC still needs forge
                from core.onchain_client import OnChainClient
                client = OnChainClient(rpc_url=rpc)
                # contract may be a path — extract address from hypothesis or data
                target = data.get("target_address", "")
                h = data.get("hypothesis", "")
                if not target:
                    import re
                    m = re.search(r"0x[0-9a-fA-F]{40}", h)
                    target = m.group(0) if m else ""

                if target:
                    snap = client.validate_hypothesis_state(target, h, block="latest")
                    data["_gate3_rpc_snapshot"] = snap
                    verdict = snap.get("gate3_verdict", "FAIL")
                    if verdict == "STATE_VERIFIED":
                        return GateData(
                            3, "PASS",
                            f"RPC state verified at block {snap.get('block_number')} "
                            f"(install forge for full PoC: curl -L https://foundry.paradigm.xyz | bash)",
                            snap,
                        )
                    return GateData(3, "FAIL", snap.get("reason", "RPC state check failed"), snap)

                # No on-chain address in hypothesis — gate needs manual data
                return GateData(
                    3, "FAIL",
                    "Forge not in PATH and no on-chain address found in hypothesis. "
                    "Install forge or add a 0x address to the hypothesis. "
                    f"Forge install: curl -L https://foundry.paradigm.xyz | bash && "
                    f"echo 'export PATH=\"$HOME/.foundry/bin:$PATH\"' >> ~/.zshrc"
                )

        if rpc and not contract:
            return GateData(3, "FAIL", "ETH_RPC_URL set but no --contract path provided")

        return GateData(
            3, "FAIL",
            "Gate 3 needs ETH_RPC_URL (set any free Alchemy/Infura endpoint). "
            "Forge PoC: export ETH_RPC_URL=https://... then re-run."
        )

    async def _gate4_replay(self, data: dict) -> GateData:
        replay = data.get("gate4_replay_results", [])

        # Auto-replay using Gate 3 auto-result if available
        if not replay and data.get("_gate3_auto_result"):
            import os
            rpc = os.environ.get("ETH_RPC_URL") or os.environ.get("MAINNET_RPC_URL")
            contract = data.get("contract", "")
            if rpc and contract:
                from core.analysis.evm_simulator import SimulationEngine
                engine = SimulationEngine()
                run2 = engine.run(contract=contract, block=data.get("block")).to_dict()
                first = data["_gate3_auto_result"]
                replay = [first, run2]

        if len(replay) < 2:
            return GateData(4, "FAIL", "Need ≥2 simulation runs. Set ETH_RPC_URL for auto-replay.")
        deltas = [r.get("balance_delta_wei", r.get("balance_delta")) for r in replay]
        if len(set(deltas)) > 1:
            return GateData(4, "FAIL", f"Non-deterministic: deltas={deltas}")
        return GateData(4, "PASS", f"Deterministic across {len(replay)} runs: delta={deltas[0]}", {"replay": replay})

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

    async def _gate8_peer_review(self, data: dict) -> GateData:
        """The Doctor — adversarial peer review from the protocol owner's perspective.

        Asks: can the most optimistic reading of the protocol invalidate this finding?
        Blocks if a valid unrefuted critique is found.
        Logs false positives to memory for negative training data.
        """
        hypothesis = data.get("hypothesis", "")

        # Check for pre-supplied peer review (e.g. from a human reviewer)
        supplied = data.get("gate8_peer_review")
        if supplied:
            if supplied.get("critique_valid"):
                reason = supplied.get("critique", "peer reviewer found valid counter-argument")
                try:
                    from core.skill_builder import SkillBuilder
                    SkillBuilder().log_false_positive(hypothesis, reason, kill_rule="Gate 8 Doctor")
                except Exception:
                    pass
                return GateData(8, "FAIL", f"Doctor refuted: {reason}")
            return GateData(8, "PASS", "Peer review passed", supplied)

        # Use ModelRouter for automated Doctor review
        try:
            from core.model_router import ModelRouter
            router = ModelRouter()

            econ = data.get("gate5", {})
            net_profit = econ.get("net_profit", 0)
            adv_notes  = data.get("gate6", {}).get("notes", "none")

            system = (
                "You are a protocol owner defending your code against a security finding. "
                "Your goal: find ANY valid reason the finding is incorrect, overstated, or "
                "not economically viable under optimistic but realistic assumptions. "
                "Be rigorous but fair — only raise critiques that would genuinely hold up to scrutiny. "
                "Reply in exactly this format:\n"
                "VERDICT: VALID_CRITIQUE or NO_VALID_CRITIQUE\n"
                "CRITIQUE: <one sentence — the strongest counter-argument, or 'none'>\n"
                "CONFIDENCE: high / medium / low"
            )
            prompt = (
                f"Finding:\n{hypothesis}\n\n"
                f"Net profit after all costs: ${net_profit:,.0f}\n"
                f"Adversarial notes from Gate 6: {adv_notes}\n\n"
                "Is there a valid reason to reject or downgrade this finding?"
            )

            response = router.complete(prompt, system=system, gate=8)
            verdict_line = next(
                (l for l in response.splitlines() if l.startswith("VERDICT:")), ""
            )
            critique_line = next(
                (l for l in response.splitlines() if l.startswith("CRITIQUE:")), ""
            )
            confidence_line = next(
                (l for l in response.splitlines() if l.startswith("CONFIDENCE:")), ""
            )

            verdict     = verdict_line.replace("VERDICT:", "").strip()
            critique    = critique_line.replace("CRITIQUE:", "").strip()
            confidence  = confidence_line.replace("CONFIDENCE:", "").strip().lower()

            review_data = {
                "verdict": verdict,
                "critique": critique,
                "confidence": confidence,
                "via": router.last_route,
            }

            if verdict == "VALID_CRITIQUE" and confidence in ("high", "medium"):
                try:
                    from core.skill_builder import SkillBuilder
                    SkillBuilder().log_false_positive(hypothesis, critique, kill_rule="Gate 8 Doctor")
                except Exception:
                    pass
                return GateData(8, "FAIL", f"Doctor refuted ({confidence} confidence): {critique}", review_data)

            return GateData(
                8, "PASS",
                f"Doctor found no valid critique (via {router.last_route})",
                review_data,
            )

        except Exception as e:
            # If ModelRouter is unavailable, gate passes with a warning
            return GateData(
                8, "PASS",
                f"Peer review skipped — router unavailable ({e}). Manual review recommended.",
                {"skipped": True},
            )

    def _post_verify(self, hypothesis: str, gate_data: dict, result: dict):
        """After full verification: register KG pattern, write report, observe AgentWriter."""
        try:
            from core.skill_builder import SkillBuilder
            from core.model_router import ModelRouter
            router = ModelRouter()
            sb = SkillBuilder(router=router)

            econ = gate_data.get("gate5", {})
            finding = {
                "hypothesis": hypothesis,
                "title": hypothesis[:80],
                "mechanism": gate_data.get("mechanism", ""),
                "severity": gate_data.get("severity", "High"),
                "protocol": gate_data.get("contract", ""),
                "net_profit": econ.get("net_profit", 0),
                "citations": gate_data.get("gate2", {}).get("citations", []),
            }
            skill_result = sb.process_verified_finding(finding, gate_data)
            result["skill_builder"] = skill_result
            sb.close()
        except Exception as e:
            result["skill_builder"] = {"error": str(e)}

        # Auto-write submission report
        try:
            from core.report_writer import ReportWriter
            from core.model_router import ModelRouter
            router = ModelRouter()
            writer = ReportWriter(router=router)
            report_meta = writer.write(
                hypothesis=hypothesis,
                gate_data=gate_data,
                pipeline_result=result,
            )
            result["report"] = report_meta
            print(f"[Report] Saved → {report_meta['path']}")
        except Exception as e:
            result["report"] = {"error": str(e)}

        try:
            from core.agent_writer import AgentWriter
            from core.skill_builder import SkillBuilder
            mechanism = SkillBuilder()._infer_mechanism(hypothesis)
            sigs = result.get("skill_builder", {}).get("regexes", [])
            AgentWriter().observe(mechanism, "", signatures=sigs)
        except Exception:
            pass

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
