"""Tests for Gate 0 — novelty check."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from core.gates.gate0_novelty import Gate0Novelty


@pytest.fixture
def gate():
    return Gate0Novelty()


class TestNovelHypotheses:
    def test_novel_hypothesis_passes(self, gate):
        h = "IF custom hook callback allows re-entry into PoolManager.swap THEN fee accounting is corrupted BECAUSE lock is cleared before hook returns"
        result = gate.check(h)
        assert result["novel"] is True
        assert result["recommendation"] == "proceed"

    def test_result_has_required_keys(self, gate):
        result = gate.check("some hypothesis about a novel finding")
        assert "hypothesis" in result
        assert "novel" in result
        assert "matches" in result
        assert "recommendation" in result


class TestKnownPatternMatches:
    def test_flash_loan_reentrancy_flagged(self, gate):
        h = "IF flash loan reentrancy in withdraw THEN funds drained BECAUSE CEI violated"
        result = gate.check(h)
        # Should match known pattern but still be "novel" (pattern != exact duplicate)
        pattern_matches = [m for m in result["matches"] if m["type"] == "known_pattern"]
        assert len(pattern_matches) > 0

    def test_price_manipulation_oracle_flagged(self, gate):
        h = "IF price manipulation via oracle spot read THEN liquidation triggered BECAUSE no TWAP"
        result = gate.check(h)
        pattern_matches = [m for m in result["matches"] if m["type"] == "known_pattern"]
        assert len(pattern_matches) > 0

    def test_first_deposit_inflation_flagged(self, gate):
        h = "IF first deposit inflation attack on ERC4626 THEN shares minted to zero BECAUSE rounding"
        result = gate.check(h)
        pattern_matches = [m for m in result["matches"] if m["type"] == "known_pattern"]
        assert len(pattern_matches) > 0

    def test_known_pattern_still_novel_unless_db_duplicate(self, gate):
        h = "IF donation attack on vault balanceOf THEN inflation BECAUSE accounting"
        result = gate.check(h)
        # Pattern match alone doesn't block — needs 2+ DB duplicates
        assert result["novel"] is True

    def test_recommendation_changes_on_match(self, gate):
        h = "IF signature replay attack occurs THEN funds stolen BECAUSE nonce not tracked"
        result = gate.check(h)
        if result["matches"]:
            assert "verify_novelty" in result["recommendation"]


class TestEdgeCases:
    def test_empty_hypothesis(self, gate):
        result = gate.check("")
        assert isinstance(result, dict)
        assert result["novel"] is True  # empty = no matches, passes through

    def test_short_hypothesis(self, gate):
        result = gate.check("reentrancy")
        assert isinstance(result, dict)

    def test_case_insensitive_matching(self, gate):
        h = "IF FLASH LOAN REENTRANCY then funds drained BECAUSE no CEI"
        result = gate.check(h)
        pattern_matches = [m for m in result["matches"] if m["type"] == "known_pattern"]
        assert len(pattern_matches) > 0

    def test_returns_dict_always(self, gate):
        for text in ["", "x", "normal hypothesis about something"]:
            result = gate.check(text)
            assert isinstance(result, dict)
