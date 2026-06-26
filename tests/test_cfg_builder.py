"""Tests for CFGBuilder — Solidity control-flow and call graph extraction."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from core.analysis.cfg_builder import CFGBuilder

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def builder():
    return CFGBuilder()


class TestContractExtraction:
    def test_extracts_contract_name(self, builder):
        cfg = builder.build_from_source(
            "pragma solidity 0.8.20;\ncontract MyVault { }",
            "test.sol"
        )
        assert "MyVault" in cfg["contracts"]

    def test_detects_interface(self, builder):
        cfg = builder.build_from_source(
            "interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }",
            "t.sol"
        )
        assert "IERC20" in cfg["contracts"]
        assert cfg["contracts"]["IERC20"]["kind"] == "interface"

    def test_detects_library(self, builder):
        cfg = builder.build_from_source(
            "library SafeMath { function add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; } }",
            "t.sol"
        )
        assert "SafeMath" in cfg["contracts"]
        assert cfg["contracts"]["SafeMath"]["kind"] == "library"

    def test_detects_inheritance(self, builder):
        cfg = builder.build_from_source(
            "contract Token is Ownable, ERC20 { }",
            "t.sol"
        )
        assert "Token" in cfg["contracts"]
        assert "Ownable" in cfg["contracts"]["Token"]["inherits"]
        assert "ERC20" in cfg["contracts"]["Token"]["inherits"]


class TestFunctionExtraction:
    def test_extracts_public_function(self, builder):
        src = """
        contract T {
            function deposit(uint256 amount) external { }
        }
        """
        cfg = builder.build_from_source(src, "t.sol")
        assert "deposit" in cfg["contracts"]["T"]["functions"]

    def test_detects_visibility(self, builder):
        src = """
        contract T {
            function pub() public { }
            function ext() external { }
            function priv() private { }
            function intl() internal { }
        }
        """
        cfg = builder.build_from_source(src, "t.sol")
        fns = cfg["contracts"]["T"]["functions"]
        assert fns["pub"]["visibility"] == "public"
        assert fns["ext"]["visibility"] == "external"
        assert fns["priv"]["visibility"] == "private"
        assert fns["intl"]["visibility"] == "internal"

    def test_detects_payable(self, builder):
        src = """
        contract T {
            function pay() external payable { }
            function nopay() external { }
        }
        """
        cfg = builder.build_from_source(src, "t.sol")
        fns = cfg["contracts"]["T"]["functions"]
        assert fns["pay"]["is_payable"] is True
        assert fns["nopay"]["is_payable"] is False

    def test_detects_view_and_pure(self, builder):
        src = """
        contract T {
            function getVal() external view returns (uint256) { return 0; }
            function compute(uint256 x) external pure returns (uint256) { return x * 2; }
        }
        """
        cfg = builder.build_from_source(src, "t.sol")
        fns = cfg["contracts"]["T"]["functions"]
        assert fns["getVal"]["mutability"] == "view"
        assert fns["compute"]["mutability"] == "pure"


class TestSummary:
    def test_summary_has_entry_points(self, builder):
        src = """
        contract T {
            function a() public { }
            function b() external { }
            function c() internal { }
        }
        """
        cfg = builder.build_from_source(src, "t.sol")
        eps = cfg["summary"]["external_entry_points"]
        assert "T.a" in eps
        assert "T.b" in eps
        assert "T.c" not in eps

    def test_summary_counts_functions(self, builder):
        src = """
        contract T {
            function a() public { }
            function b() external { }
        }
        """
        cfg = builder.build_from_source(src, "t.sol")
        assert cfg["summary"]["total_functions"] == 2

    def test_payable_functions_in_summary(self, builder):
        src = """
        contract T {
            function deposit() external payable { }
            function withdraw() external { }
        }
        """
        cfg = builder.build_from_source(src, "t.sol")
        assert "T.deposit" in cfg["summary"]["payable_functions"]
        assert "T.withdraw" not in cfg["summary"]["payable_functions"]


class TestFileBuilding:
    def test_build_sample_sol(self, builder):
        cfg = builder.build(str(FIXTURES / "sample.sol"))
        assert "VulnerableVault" in cfg["contracts"]
        fns = cfg["contracts"]["VulnerableVault"]["functions"]
        assert "withdraw" in fns
        assert "deposit" in fns

    def test_nonexistent_file_returns_error(self, builder):
        cfg = builder.build("/nonexistent/path.sol")
        assert "error" in cfg
