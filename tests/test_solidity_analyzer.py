"""Tests for SolidityAnalyzer — pattern-based vulnerability scanner."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from core.analysis.solidity_analyzer import SolidityAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_SOL = str(FIXTURES / "sample.sol")
CLEAN_SOL = str(FIXTURES / "clean.sol")


@pytest.fixture
def analyzer():
    return SolidityAnalyzer()


class TestVulnerableScan:
    def test_scan_returns_list(self, analyzer):
        results = analyzer.scan(SAMPLE_SOL)
        assert isinstance(results, list)
        assert len(results) > 0

    def test_finds_reentrancy(self, analyzer):
        results = analyzer.scan(SAMPLE_SOL)
        ids = [r["id"] for r in results]
        assert "REENTRANT_TRANSFER_BEFORE_UPDATE" in ids

    def test_finds_missing_access_control(self, analyzer):
        results = analyzer.scan(SAMPLE_SOL)
        ids = [r["id"] for r in results]
        assert "MISSING_ACCESS_CONTROL" in ids

    def test_finds_direct_balance_of(self, analyzer):
        results = analyzer.scan(SAMPLE_SOL)
        ids = [r["id"] for r in results]
        assert "DIRECT_BALANCE_OF" in ids

    def test_finds_unchecked_arithmetic(self, analyzer):
        results = analyzer.scan(SAMPLE_SOL)
        ids = [r["id"] for r in results]
        assert "UNCHECKED_ARITHMETIC" in ids

    def test_finds_tx_origin(self, analyzer):
        results = analyzer.scan(SAMPLE_SOL)
        ids = [r["id"] for r in results]
        assert "TX_ORIGIN_AUTH" in ids

    def test_finds_block_timestamp(self, analyzer):
        results = analyzer.scan(SAMPLE_SOL)
        ids = [r["id"] for r in results]
        assert "BLOCK_TIMESTAMP" in ids

    def test_severity_sorted(self, analyzer):
        results = analyzer.scan(SAMPLE_SOL)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        severities = [severity_order[r["severity"]] for r in results]
        assert severities == sorted(severities)

    def test_each_result_has_required_fields(self, analyzer):
        results = analyzer.scan(SAMPLE_SOL)
        for r in results:
            assert "id" in r
            assert "severity" in r
            assert "location" in r
            assert "description" in r
            assert "advice" in r

    def test_location_includes_line_number(self, analyzer):
        results = analyzer.scan(SAMPLE_SOL)
        for r in results:
            assert ":" in r["location"]
            parts = r["location"].split(":")
            assert parts[-1].isdigit()


class TestDirectoryScan:
    def test_scans_directory(self, analyzer, tmp_path):
        sol = tmp_path / "test.sol"
        sol.write_text("pragma solidity ^0.8.0;\ncontract T { function f() public { selfdestruct(payable(msg.sender)); } }")
        results = analyzer.scan(str(tmp_path))
        assert len(results) > 0

    def test_skips_node_modules(self, analyzer, tmp_path):
        node_mod = tmp_path / "node_modules"
        node_mod.mkdir()
        sol = node_mod / "evil.sol"
        sol.write_text("pragma solidity ^0.8.0;\ncontract T { function f() public { selfdestruct(payable(msg.sender)); } }")
        results = analyzer.scan(str(tmp_path))
        assert all("node_modules" not in r["location"] for r in results)


class TestInlineScanning:
    @pytest.mark.parametrize("source,expected_id", [
        (
            "pragma solidity ^0.8.0;\ncontract T {}",
            "FLOATING_PRAGMA",
        ),
        (
            "pragma solidity 0.8.20;\ncontract T { function f() external { selfdestruct(payable(address(0))); } }",
            "SELFDESTRUCT",
        ),
        (
            "pragma solidity 0.8.20;\ncontract T { function f() external { require(tx.origin == msg.sender); } }",
            "TX_ORIGIN_AUTH",
        ),
    ])
    def test_specific_patterns(self, analyzer, tmp_path, source, expected_id):
        sol = tmp_path / "t.sol"
        sol.write_text(source)
        results = analyzer.scan(str(sol))
        ids = [r["id"] for r in results]
        assert expected_id in ids


class TestNonExistentPath:
    def test_nonexistent_file_returns_empty(self, analyzer):
        results = analyzer.scan("/nonexistent/path/contract.sol")
        assert results == []
