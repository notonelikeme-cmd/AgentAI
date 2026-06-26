"""Model capability catalog for Nexus Trinity.

Design: default unknown Claude models to the modern contract (adaptive thinking,
reasoning mandatory, xhigh effort). Keep explicit legacy lists only for the
older families that need the old path. Each new Anthropic release works with
zero code changes.
"""
from __future__ import annotations

# ── Curated model list (ordered: newest / most capable first) ─────────────
CURATED_MODELS: list[str] = [
    "claude-fable-5",           # Mythos-class — 1M ctx, 128K out, adaptive
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-haiku-4-5",
]

# ── Adaptive thinking: legacy families that still need manual budget_tokens ──
# Everything Claude 4.6+ (including Fable / Mythos-class) uses adaptive
# thinking and rejects the old manual ``thinking`` block entirely.
_LEGACY_THINKING_SUBSTRINGS = (
    "claude-3",
    "claude-opus-4-0", "claude-opus-4.0", "claude-opus-4-1", "claude-opus-4.1",
    "claude-sonnet-4-0", "claude-sonnet-4.0",
    "claude-opus-4-2025", "claude-sonnet-4-2025",
    "claude-opus-4-5", "claude-opus-4.5",
    "claude-sonnet-4-5", "claude-sonnet-4.5",
    "claude-haiku-4-5", "claude-haiku-4.5",
)

# ── xhigh effort: only 4.6 models don't accept it; 4.7+ and Fable do ───────
_NO_XHIGH_SUBSTRINGS = (
    "claude-opus-4-6", "claude-opus-4.6",
    "claude-sonnet-4-6", "claude-sonnet-4.6",
)

# ── Max output tokens per model family ───────────────────────────────────────
# Prefix-matched longest-first. Unknown Claude defaults to 128K (safe for
# Fable / Mythos-class and any future model above that bar).
_OUTPUT_LIMITS: dict[str, int] = {
    "claude-fable":      128_000,   # Mythos-class named models
    "claude-opus-4-8":   128_000,
    "claude-opus-4-7":   128_000,
    "claude-opus-4-6":   128_000,
    "claude-sonnet-4-6":  64_000,
    "claude-opus-4-5":    64_000,
    "claude-sonnet-4-5":  64_000,
    "claude-haiku-4-5":   64_000,
    "claude-opus-4":      32_000,
    "claude-sonnet-4":    64_000,
    "claude-3-7-sonnet": 128_000,
    "claude-3-5-sonnet":   8_192,
    "claude-3-5-haiku":    8_192,
    "claude-3-opus":       4_096,
    "claude-3-sonnet":     4_096,
    "claude-3-haiku":      4_096,
}
_DEFAULT_OUTPUT_LIMIT = 128_000

# Effort level map: Hermes/Trinity label → Anthropic output_config.effort
EFFORT_MAP: dict[str, str] = {
    "max":     "max",
    "xhigh":   "xhigh",
    "high":    "high",
    "medium":  "medium",
    "low":     "low",
    "minimal": "low",
}


def _is_claude(model: str | None) -> bool:
    return "claude" in (model or "").lower()


def supports_adaptive_thinking(model: str | None) -> bool:
    """True for Claude 4.6+, Fable, Mythos-class, and any unknown future Claude.

    Unknown Claude models default to True (modern contract). Only the explicit
    legacy list returns False.
    """
    if not _is_claude(model):
        return False
    m = (model or "").lower()
    return not any(sub in m for sub in _LEGACY_THINKING_SUBSTRINGS)


def reasoning_is_mandatory(model: str | None) -> bool:
    """True for models that reject any disable-thinking request (4.6+, Fable).

    Same inverted-allowlist as supports_adaptive_thinking — they move together.
    """
    return supports_adaptive_thinking(model)


def supports_xhigh_effort(model: str | None) -> bool:
    """True for Claude 4.7+, Fable, and unknown future Claude. False for 4.6."""
    if not supports_adaptive_thinking(model):
        return False
    m = (model or "").lower()
    return not any(sub in m for sub in _NO_XHIGH_SUBSTRINGS)


def get_output_limit(model: str | None) -> int:
    """Return max_tokens for the given model. Unknown Claude → 128K."""
    m = (model or "").lower()
    for prefix, limit in _OUTPUT_LIMITS.items():
        if prefix in m:
            return limit
    if _is_claude(m):
        return _DEFAULT_OUTPUT_LIMIT
    return 4_096


def resolve_effort(effort: str, model: str | None) -> str:
    """Map a Hermes/Trinity effort label to the Anthropic API effort value.

    Downgrades xhigh → max on 4.6 models that don't support xhigh.
    """
    mapped = EFFORT_MAP.get(effort, effort)
    if mapped == "xhigh" and not supports_xhigh_effort(model):
        return "max"
    return mapped


def model_profile(model: str | None) -> dict:
    """Return a full capability profile for a model — used by status and MCP."""
    return {
        "model": model,
        "adaptive_thinking": supports_adaptive_thinking(model),
        "reasoning_mandatory": reasoning_is_mandatory(model),
        "xhigh_effort": supports_xhigh_effort(model),
        "max_output_tokens": get_output_limit(model),
        "effort_levels": (
            ["low", "medium", "high", "xhigh", "max"]
            if supports_xhigh_effort(model)
            else (
                ["low", "medium", "high", "max"]
                if supports_adaptive_thinking(model)
                else ["low", "medium", "high"]
            )
        ),
    }
