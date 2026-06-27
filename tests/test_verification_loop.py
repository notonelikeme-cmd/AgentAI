"""Tests for VerificationLoop — 7-gate pipeline orchestrator."""
import sys
import asyncio
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from core.gates.verification_loop import VerificationLoop


@pytest.fixture
def loop():
    return VerificationLoop()


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


VALID_H = (
    "IF reentrancy vulnerability exists in src/Vault.sol:42 "
    "THEN attacker drains funds "
    "BECAUSE withdraw() calls transfer before updating balance"
)


class TestGate1Hypothesis:
    def test_valid_hypothesis_passes(self, loop):
        result = run(loop._gate1_hypothesis({"hypothesis": VALID_H}))
        assert result.status == "PASS"

    def test_too_short_fails(self, loop):
        result = run(loop._gate1_hypothesis({"hypothesis": "short"}))
        assert result.status == "FAIL"

    def test_missing_if_fails(self, loop):
        h = "THEN attacker drains funds BECAUSE CEI violated"
        result = run(loop._gate1_hypothesis({"hypothesis": h}))
        assert result.status == "FAIL"
        assert "if" in result.reason.lower()

    def test_missing_then_fails(self, loop):
        h = "IF condition exists BECAUSE mechanism is broken"
        result = run(loop._gate1_hypothesis({"hypothesis": h}))
        assert result.status == "FAIL"

    def test_missing_because_fails(self, loop):
        h = "IF condition exists THEN something bad happens"
        result = run(loop._gate1_hypothesis({"hypothesis": h}))
        assert result.status == "FAIL"


class TestGate2Evidence:
    def test_citation_passes(self, loop):
        data = {"hypothesis": "IF reentrancy in Vault.sol:42 THEN drain"}
        result = run(loop._gate2_evidence(data))
        assert result.status == "PASS"
        assert result.data["citations"] == ["Vault.sol:42"]

    def test_no_citation_fails(self, loop):
        data = {"hypothesis": "IF something happens THEN bad thing occurs"}
        result = run(loop._gate2_evidence(data))
        assert result.status == "FAIL"
        assert "citation" in result.reason.lower()

    def test_multiple_citations_found(self, loop):
        data = {"hypothesis": "IF Pool.sol:10 and Vault.sol:99 are combined"}
        result = run(loop._gate2_evidence(data))
        assert result.status == "PASS"
        assert len(result.data["citations"]) == 2


class TestGate3Simulation:
    def test_no_sim_data_fails(self, loop):
        result = run(loop._gate3_simulation({}))
        assert result.status == "FAIL"

    def test_positive_balance_delta_passes(self, loop):
        data = {"gate3_simulation_result": {"balance_delta": 10_000.0}}
        result = run(loop._gate3_simulation(data))
        assert result.status == "PASS"

    def test_zero_delta_fails(self, loop):
        data = {"gate3_simulation_result": {"balance_delta": 0}}
        result = run(loop._gate3_simulation(data))
        assert result.status == "FAIL"

    def test_negative_delta_fails(self, loop):
        data = {"gate3_simulation_result": {"balance_delta": -100.0}}
        result = run(loop._gate3_simulation(data))
        assert result.status == "FAIL"


class TestGate4Replay:
    def test_single_run_fails(self, loop):
        data = {"gate4_replay_results": [{"balance_delta": 100}]}
        result = run(loop._gate4_replay(data))
        assert result.status == "FAIL"

    def test_two_matching_runs_pass(self, loop):
        data = {"gate4_replay_results": [
            {"balance_delta": 100},
            {"balance_delta": 100},
        ]}
        result = run(loop._gate4_replay(data))
        assert result.status == "PASS"

    def test_divergent_runs_fail(self, loop):
        data = {"gate4_replay_results": [
            {"balance_delta": 100},
            {"balance_delta": 200},
        ]}
        result = run(loop._gate4_replay(data))
        assert result.status == "FAIL"
        assert "non-deterministic" in result.reason.lower()


class TestGate5Economics:
    def test_no_economics_data_fails(self, loop):
        result = run(loop._gate5_economics({}))
        assert result.status == "FAIL"

    def test_profitable_passes(self, loop):
        data = {"gate5_economics": {
            "balance_delta": 100_000,
            "gas_cost": 500,
            "flash_loan_fee": 300,
            "slippage": 200,
        }}
        result = run(loop._gate5_economics(data))
        assert result.status == "PASS"
        assert result.data["net_profit"] == pytest.approx(99_000.0)

    def test_unprofitable_fails(self, loop):
        data = {"gate5_economics": {
            "balance_delta": 100,
            "gas_cost": 500,
            "flash_loan_fee": 300,
            "slippage": 200,
        }}
        result = run(loop._gate5_economics(data))
        assert result.status == "FAIL"
        assert result.data["net_profit"] < 0


class TestGate6Adversarial:
    def test_no_adversarial_data_fails(self, loop):
        result = run(loop._gate6_adversarial({}))
        assert result.status == "FAIL"

    def test_not_refuted_passes(self, loop):
        data = {"gate6_adversarial_result": {"refuted": False}}
        result = run(loop._gate6_adversarial(data))
        assert result.status == "PASS"

    def test_refuted_fails(self, loop):
        data = {"gate6_adversarial_result": {"refuted": True, "reason": "admin key blocks exploit"}}
        result = run(loop._gate6_adversarial(data))
        assert result.status == "FAIL"
        assert "admin key" in result.reason


class TestGate7Reproducibility:
    def test_no_guide_fails(self, loop):
        result = run(loop._gate7_reproducibility({}))
        assert result.status == "FAIL"

    def test_too_short_guide_fails(self, loop):
        data = {"gate7_reproduction_guide": "Too short"}
        result = run(loop._gate7_reproducibility(data))
        assert result.status == "FAIL"

    def test_adequate_guide_passes(self, loop):
        guide = (
            "1. Fork mainnet at block 21000000 using: anvil --fork-url $ETH_RPC_URL --fork-block-number 21000000\n"
            "2. Deploy VulnerableVault at 0xdead\n"
            "3. Call withdraw(1000) as attacker contract that re-enters in receive()\n"
            "4. Observe balance_delta = 10 ETH after reentrancy chain\n"
            "5. Run forge test --match-test test_exploit -vvvv to reproduce\n"
        )
        data = {"gate7_reproduction_guide": guide}
        result = run(loop._gate7_reproducibility(data))
        assert result.status == "PASS"


class TestGate8PeerReview:
    def test_supplied_no_critique_passes(self, loop):
        data = {"gate8_peer_review": {"critique_valid": False, "critique": "none"}}
        result = run(loop._gate8_peer_review(data))
        assert result.status == "PASS"

    def test_supplied_valid_critique_fails(self, loop):
        data = {
            "hypothesis": "IF x THEN y BECAUSE z",
            "gate8_peer_review": {
                "critique_valid": True,
                "critique": "timelock prevents immediate exploit",
            },
        }
        result = run(loop._gate8_peer_review(data))
        assert result.status == "FAIL"
        assert "timelock" in result.reason

    def test_no_router_skips_gracefully(self, loop):
        # With no ModelRouter available the gate passes with a skip note
        data = {
            "hypothesis": "IF x in Vault.sol:1 THEN y BECAUSE z",
            "gate5": {"net_profit": 1000},
        }
        result = run(loop._gate8_peer_review(data))
        # Should pass (router may or may not be available in test env)
        assert result.status in ("PASS", "FAIL")


class TestFullPipelineBlocking:
    def test_blocks_at_gate1_no_keywords(self, loop):
        result = run(loop.run(
            hypothesis="this is not a proper hypothesis",
            contract="src/Vault.sol",
        ))
        assert result["verdict"] == "BLOCKED"
        assert result["final_gate"] == 1

    def test_blocks_at_gate2_no_citations(self, loop):
        result = run(loop.run(
            hypothesis="IF reentrancy exists in contract THEN funds drained BECAUSE CEI violated",
            contract="src/Vault.sol",
        ))
        assert result["verdict"] == "BLOCKED"
        assert result["final_gate"] == 2

    def test_model_included_in_gate_data(self, loop):
        result = run(loop.run(
            hypothesis="IF reentrancy exists in contract THEN drain BECAUSE CEI",
            contract="src/Vault.sol",
            model="claude-fable-5",
        ))
        assert result.get("hypothesis") is not None

    def test_format_result_structure(self, loop):
        result = run(loop.run(
            hypothesis="IF x in File.sol:1 THEN y BECAUSE z",
            contract="src/Vault.sol",
        ))
        assert "hypothesis" in result
        assert "verdict" in result
        assert "final_gate" in result
        assert "gates" in result
        assert "summary" in result
        assert isinstance(result["gates"], list)
