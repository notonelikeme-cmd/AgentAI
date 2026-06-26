"""Tests for RAOBrain — hypothesis generator."""
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from core.rao_brain import RAOBrain, Hypothesis

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def brain(tmp_path):
    db = tmp_path / "test_kg.db"
    return RAOBrain(db_path=str(db))


class TestHypothesisGeneration:
    def test_generates_hypotheses(self, brain):
        hyps = brain.generate(str(FIXTURES / "sample.sol"))
        assert isinstance(hyps, list)
        assert len(hyps) > 0

    def test_returns_hypothesis_objects(self, brain):
        hyps = brain.generate(str(FIXTURES / "sample.sol"))
        for h in hyps:
            assert isinstance(h, Hypothesis)

    def test_hypothesis_has_gate1_format(self, brain):
        hyps = brain.generate(str(FIXTURES / "sample.sol"))
        for h in hyps:
            assert "IF " in h.text
            assert " THEN " in h.text
            assert " BECAUSE " in h.text

    def test_score_in_valid_range(self, brain):
        hyps = brain.generate(str(FIXTURES / "sample.sol"))
        for h in hyps:
            assert 0.0 <= h.score <= 1.0

    def test_sorted_by_score_descending(self, brain):
        hyps = brain.generate(str(FIXTURES / "sample.sol"))
        scores = [h.score for h in hyps]
        assert scores == sorted(scores, reverse=True)

    def test_top_n_respected(self, brain):
        hyps = brain.generate(str(FIXTURES / "sample.sol"), top_n=3)
        assert len(hyps) <= 3

    def test_each_has_pattern_id(self, brain):
        hyps = brain.generate(str(FIXTURES / "sample.sol"))
        for h in hyps:
            assert h.pattern_id
            assert len(h.pattern_id) > 0


class TestObservations:
    def test_verified_boosts_score(self, brain):
        hyps_before = brain.generate(str(FIXTURES / "sample.sol"))
        pattern = hyps_before[0].pattern_id
        score_before = next(h.score for h in hyps_before if h.pattern_id == pattern)

        brain.observe(pattern, "VERIFIED", 7, "found it")
        hyps_after = brain.generate(str(FIXTURES / "sample.sol"))
        score_after = next((h.score for h in hyps_after if h.pattern_id == pattern), 0)
        assert score_after >= score_before

    def test_blocked_early_penalizes_score(self, brain):
        hyps_before = brain.generate(str(FIXTURES / "sample.sol"))
        pattern = hyps_before[-1].pattern_id if len(hyps_before) > 1 else hyps_before[0].pattern_id
        score_before = next((h.score for h in hyps_before if h.pattern_id == pattern), 0.5)

        brain.observe(pattern, "BLOCKED", 1, "too vague")
        hyps_after = brain.generate(str(FIXTURES / "sample.sol"))
        score_after = next((h.score for h in hyps_after if h.pattern_id == pattern), 0)
        assert score_after <= score_before

    def test_reset_clears_observations(self, brain):
        brain.observe("FLA-001", "VERIFIED", 7)
        brain.reset_observations()
        assert brain._observation_log == []


class TestToDict:
    def test_to_dict_has_required_keys(self, brain):
        hyps = brain.generate(str(FIXTURES / "sample.sol"), top_n=1)
        if hyps:
            d = hyps[0].to_dict()
            assert "text" in d
            assert "pattern_id" in d
            assert "score" in d
            assert "rationale" in d
            assert "evidence_hints" in d


class TestNonexistentContract:
    def test_generates_from_kg_even_without_file(self, brain):
        hyps = brain.generate("/nonexistent/path/contract.sol")
        # Should still generate from KG patterns even if CFG fails
        assert isinstance(hyps, list)
