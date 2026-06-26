"""Tests for core/models.py — Fable 5 / Mythos-class capability profiles."""
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import (
    CURATED_MODELS,
    supports_adaptive_thinking,
    reasoning_is_mandatory,
    supports_xhigh_effort,
    get_output_limit,
    resolve_effort,
    model_profile,
)


# ── Fable 5 / Mythos-class ───────────────────────────────────────────────────

class TestFable5:
    def test_is_first_in_curated_list(self):
        assert CURATED_MODELS[0] == "claude-fable-5"

    def test_adaptive_thinking(self):
        assert supports_adaptive_thinking("claude-fable-5") is True

    def test_reasoning_mandatory(self):
        assert reasoning_is_mandatory("claude-fable-5") is True

    def test_xhigh_effort(self):
        assert supports_xhigh_effort("claude-fable-5") is True

    def test_output_limit_128k(self):
        assert get_output_limit("claude-fable-5") == 128_000

    def test_effort_levels_include_xhigh(self):
        profile = model_profile("claude-fable-5")
        assert "xhigh" in profile["effort_levels"]

    def test_openrouter_prefixed_model(self):
        assert supports_adaptive_thinking("anthropic/claude-fable-5") is True
        assert get_output_limit("anthropic/claude-fable-5") == 128_000


# ── Opus 4.8 ─────────────────────────────────────────────────────────────────

class TestOpus48:
    def test_adaptive_thinking(self):
        assert supports_adaptive_thinking("claude-opus-4-8") is True

    def test_xhigh_effort(self):
        assert supports_xhigh_effort("claude-opus-4-8") is True

    def test_output_limit(self):
        assert get_output_limit("claude-opus-4-8") == 128_000


# ── Sonnet 4.6 — adaptive but no xhigh ───────────────────────────────────────

class TestSonnet46:
    def test_adaptive_thinking(self):
        assert supports_adaptive_thinking("claude-sonnet-4-6") is True

    def test_no_xhigh(self):
        assert supports_xhigh_effort("claude-sonnet-4-6") is False

    def test_output_limit_64k(self):
        assert get_output_limit("claude-sonnet-4-6") == 64_000

    def test_xhigh_resolves_to_max(self):
        assert resolve_effort("xhigh", "claude-sonnet-4-6") == "max"


# ── Legacy manual-thinking models ────────────────────────────────────────────

class TestLegacyModels:
    @pytest.mark.parametrize("model", [
        "claude-3-opus-20240229",
        "claude-3-5-sonnet-20241022",
        "claude-opus-4-5",
        "claude-sonnet-4-5",
        "claude-haiku-4-5",
        "claude-haiku-4-5-20251001",
    ])
    def test_no_adaptive_thinking(self, model):
        assert supports_adaptive_thinking(model) is False

    @pytest.mark.parametrize("model", [
        "claude-3-opus-20240229",
        "claude-opus-4-5",
    ])
    def test_no_xhigh(self, model):
        assert supports_xhigh_effort(model) is False


# ── Inverted allowlist: unknown future Claude defaults to modern contract ─────

class TestFutureModels:
    def test_unknown_claude_gets_adaptive_thinking(self):
        assert supports_adaptive_thinking("claude-future-9-99") is True

    def test_unknown_claude_gets_xhigh(self):
        assert supports_xhigh_effort("claude-future-9-99") is True

    def test_unknown_claude_gets_128k_output(self):
        assert get_output_limit("claude-future-9-99") == 128_000

    def test_non_claude_gets_no_adaptive_thinking(self):
        assert supports_adaptive_thinking("gpt-5") is False
        assert supports_adaptive_thinking("gemini-3-pro") is False

    def test_none_model_is_safe(self):
        assert supports_adaptive_thinking(None) is False
        assert get_output_limit(None) == 4_096


# ── Effort resolution ─────────────────────────────────────────────────────────

class TestEffortResolution:
    def test_xhigh_passthrough_on_fable(self):
        assert resolve_effort("xhigh", "claude-fable-5") == "xhigh"

    def test_xhigh_downgrade_on_sonnet46(self):
        assert resolve_effort("xhigh", "claude-sonnet-4-6") == "max"

    def test_minimal_alias_maps_to_low(self):
        assert resolve_effort("minimal", "claude-fable-5") == "low"

    def test_high_passthrough(self):
        assert resolve_effort("high", "claude-fable-5") == "high"


# ── Full profile ──────────────────────────────────────────────────────────────

class TestModelProfile:
    def test_profile_keys(self):
        p = model_profile("claude-fable-5")
        assert set(p.keys()) == {
            "model", "adaptive_thinking", "reasoning_mandatory",
            "xhigh_effort", "max_output_tokens", "effort_levels",
        }

    def test_all_curated_models_have_profiles(self):
        for model in CURATED_MODELS:
            p = model_profile(model)
            assert p["model"] == model
            assert isinstance(p["max_output_tokens"], int)
            assert isinstance(p["effort_levels"], list)
