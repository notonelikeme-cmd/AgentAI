"""Tests for DeFiKnowledgeGraph — attack pattern library."""
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from core.analysis.defi_kg import DeFiKnowledgeGraph


@pytest.fixture
def kg(tmp_path):
    db = tmp_path / "test_kg.db"
    instance = DeFiKnowledgeGraph(db_path=str(db))
    yield instance
    instance.close()


class TestSeeding:
    def test_patterns_seeded_on_init(self, kg):
        patterns = kg.list_patterns()
        assert len(patterns) >= 10

    def test_fla001_present(self, kg):
        p = kg.get_pattern("FLA-001")
        assert p is not None
        assert p["mechanism"] == "flash_loan"
        assert p["severity"] == "Critical"

    def test_all_critical_patterns_present(self, kg):
        criticals = kg.by_severity("Critical")
        ids = [p["id"] for p in criticals]
        assert "FLA-001" in ids
        assert "RE-001" in ids
        assert "PRX-001" in ids


class TestSearch:
    def test_search_reentrancy(self, kg):
        results = kg.retrieve("reentrancy")
        assert len(results) > 0
        assert all("reentranc" in r["description"].lower() or
                   "reentranc" in r["mechanism"].lower() or
                   "reentranc" in r["class"].lower()
                   for r in results)

    def test_search_oracle(self, kg):
        results = kg.retrieve("oracle")
        assert len(results) > 0

    def test_search_nonexistent(self, kg):
        results = kg.retrieve("xyzzy_nonexistent_12345")
        assert results == []

    def test_search_case_insensitive(self, kg):
        results_lower = kg.retrieve("flash loan")
        results_upper = kg.retrieve("FLASH LOAN")
        assert len(results_lower) == len(results_upper)


class TestByClass:
    def test_by_class_state_update(self, kg):
        # RE-001 has mechanism=reentrancy, class=state_update
        patterns = kg.by_class("state_update")
        assert len(patterns) > 0
        assert all(p["class"] == "state_update" for p in patterns)

    def test_by_class_proxy(self, kg):
        patterns = kg.by_class("proxy")
        assert len(patterns) > 0

    def test_by_class_nonexistent(self, kg):
        assert kg.by_class("nonexistent_class") == []


class TestBySeverity:
    def test_critical_patterns(self, kg):
        criticals = kg.by_severity("Critical")
        assert all(p["severity"] == "Critical" for p in criticals)
        assert len(criticals) >= 4

    def test_high_patterns(self, kg):
        highs = kg.by_severity("High")
        assert all(p["severity"] == "High" for p in highs)
        assert len(highs) >= 5


class TestByProtocol:
    def test_uniswap_v4_patterns(self, kg):
        results = kg.by_protocol("Uniswap V4")
        assert len(results) > 0

    def test_amm_patterns(self, kg):
        results = kg.by_protocol("AMM")
        assert len(results) > 0


class TestHypothesisGeneration:
    def test_generates_hypothesis(self, kg):
        hyps = kg.hypotheses_for_pattern("RE-001")
        assert len(hyps) == 1
        h = hyps[0]
        assert "IF " in h
        assert " THEN " in h
        assert " BECAUSE " in h

    def test_nonexistent_pattern_returns_empty(self, kg):
        assert kg.hypotheses_for_pattern("NONEXISTENT") == []


class TestAddPattern:
    def test_add_and_retrieve_custom_pattern(self, kg):
        kg.add_pattern(
            id="CUSTOM-001",
            mechanism="custom_mech",
            vuln_class="custom_class",
            severity="High",
            description="Custom test pattern",
            impact="funds drained",
            protocol="TestProtocol",
        )
        p = kg.get_pattern("CUSTOM-001")
        assert p is not None
        assert p["mechanism"] == "custom_mech"
        assert p["protocol"] == "TestProtocol"

    def test_add_upserts_on_duplicate_id(self, kg):
        kg.add_pattern("FLA-001", "flash_loan", "price_manipulation", "Critical",
                       "Updated description", "updated impact")
        p = kg.get_pattern("FLA-001")
        assert p["description"] == "Updated description"
