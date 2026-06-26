"""Tests for SimulationEngine — Gate 3 Foundry fork executor."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from unittest.mock import patch, MagicMock
from core.analysis.evm_simulator import SimulationEngine, SimResult, _has_foundry


class TestStubResults:
    def test_stub_positive_profit(self):
        engine = SimulationEngine()
        result = engine.stub_result(balance_delta=10.5, gas_used=500_000)
        assert result["success"] is True
        assert result["balance_delta"] == 10.5
        assert result["gas_used"] == 500_000
        assert result["mode"] == "stub"
        assert result["gas_cost_eth"] > 0

    def test_stub_zero_profit_not_success(self):
        engine = SimulationEngine()
        result = engine.stub_result(balance_delta=0.0)
        assert result["success"] is False

    def test_stub_negative_not_success(self):
        engine = SimulationEngine()
        result = engine.stub_result(balance_delta=-1.0)
        assert result["success"] is False


class TestUnavailableFallback:
    def test_returns_unavailable_when_no_foundry(self):
        with patch("core.analysis.evm_simulator._has_foundry", return_value=False):
            engine = SimulationEngine()
            result = engine.run(contract="src/Vault.sol")
            assert result["mode"] == "unavailable"
            assert result["success"] is False
            assert "foundry" in result["error"].lower() or "forge" in result["error"].lower()

    def test_unavailable_result_has_required_keys(self):
        with patch("core.analysis.evm_simulator._has_foundry", return_value=False):
            engine = SimulationEngine()
            result = engine.run(contract="src/Vault.sol")
            assert "mode" in result
            assert "success" in result
            assert "error" in result


class TestNoRpcUrl:
    def test_missing_rpc_returns_error(self):
        with patch("core.analysis.evm_simulator._has_foundry", return_value=True):
            with patch.dict("os.environ", {}, clear=True):
                engine = SimulationEngine(rpc_url="")
                result = engine.run(contract="src/Vault.sol")
                assert result["success"] is False
                assert "ETH_RPC_URL" in result["error"]


class TestSimResult:
    def test_to_dict_has_required_keys(self):
        r = SimResult(success=True, balance_delta=5.0, gas_used=200_000, mode="stub")
        d = r.to_dict()
        assert "success" in d
        assert "balance_delta" in d
        assert "gas_used" in d
        assert "mode" in d
        assert "error" in d

    def test_default_mode_is_forge(self):
        r = SimResult(success=False)
        assert r.mode == "forge"


class TestForgeOutputParsing:
    def test_parse_json_success(self):
        with patch("core.analysis.evm_simulator._has_foundry", return_value=True):
            engine = SimulationEngine(rpc_url="http://localhost:8545")
            import subprocess
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = '{"test/T.t.sol": {"test_exploit": {"status": "Success", "gasUsed": 100000, "logs": ["balance_delta_wei: 5000000000000000000"]}}}'
            mock_proc.stderr = ""
            result = engine._parse_forge_output(mock_proc, "test/T.t.sol")
            assert result.success is True
            assert result.balance_delta == pytest.approx(5.0, abs=0.001)
            assert result.gas_used == 100_000

    def test_parse_revert_reason(self):
        with patch("core.analysis.evm_simulator._has_foundry", return_value=True):
            engine = SimulationEngine(rpc_url="http://localhost:8545")
            mock_proc = MagicMock()
            mock_proc.returncode = 1
            mock_proc.stdout = ""
            mock_proc.stderr = "Error: Reason: insufficient balance"
            result = engine._parse_forge_output(mock_proc, "test/T.t.sol")
            assert result.success is False
            assert "insufficient balance" in result.revert_reason
