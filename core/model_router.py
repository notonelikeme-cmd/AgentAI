"""ModelRouter — four-tier LLM routing with circuit breakers.

Routing chain:
  1. Anthropic claude-fable-5       (primary — all gates)
  2. Ollama deepseek-r1:14b         (reasoning fallback — gates 3-8)
  3. Ollama qwen2.5-coder:14b       (code reading fallback — LLMAuditor, gate 2)
  4. Ollama gemma4:latest           (fast fallback — gates 1-2, or last resort)

Gate routing logic:
  - Gates 1-2 (cheap, high-volume): Gemma4 by default
  - Gates 3-8 (reasoning-heavy): DeepSeek-R1 when Anthropic is unavailable
  - code=True: Qwen2.5-Coder for source reading and PoC generation
  - prefer_local=True: DeepSeek-R1 for all gates (skip Anthropic)

Circuit breakers prevent cascading failures:
  - Anthropic: opens after 3 failures, resets after 60s
  - DeepSeek:  opens after 3 failures, resets after 45s
  - Qwen:      opens after 3 failures, resets after 45s
  - Gemma4:    opens after 5 failures, resets after 30s
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional

from core.models import CURATED_MODELS, model_profile, resolve_effort

_OLLAMA_BASE    = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
_GEMMA_MODEL    = os.environ.get("OLLAMA_MODEL", "gemma4:latest")
_DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-r1:14b")
_QWEN_MODEL     = os.environ.get("QWEN_MODEL", "qwen2.5-coder:14b")
_EMBED_MODEL    = os.environ.get("EMBED_MODEL", "nomic-embed-text")

# Gates cheap enough for Gemma4 (fast, low reasoning demand)
_LOCAL_GATES = {1, 2}
# Gates that need DeepSeek-R1 reasoning when Anthropic unavailable
_REASONING_GATES = {3, 4, 5, 6, 7, 8}


def _ollama_available() -> bool:
    try:
        req = urllib.request.Request(f"{_OLLAMA_BASE}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def _model_pulled(model_name: str) -> bool:
    """Check if a specific Ollama model is available locally."""
    try:
        req = urllib.request.Request(f"{_OLLAMA_BASE}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=2) as r:
            data = json.loads(r.read())
            names = [m["name"] for m in data.get("models", [])]
            # Match on base name (strip :tag if needed for partial match)
            return any(model_name in n or n in model_name for n in names)
    except Exception:
        return False


def _ollama_chat(
    prompt: str,
    system: Optional[str] = None,
    model: str = _GEMMA_MODEL,
    temperature: float = 0.2,
    think: bool = False,
    timeout: int = 180,
    num_ctx: int = 32768,
) -> str:
    """Call Ollama /api/chat. Returns assistant content string."""
    messages: List[Dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_ctx": num_ctx,
            "num_predict": -1,
        },
    }
    if think:
        payload["think"] = True

    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{_OLLAMA_BASE}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read())

    content = data.get("message", {}).get("content", "")
    if "<think>" in content and "</think>" in content:
        content = content[content.index("</think>") + 8:].strip()
    return content


def _ollama_embed(text: str, model: str = _EMBED_MODEL) -> List[float]:
    """Get embedding vector from Ollama. Returns float list."""
    payload = {"model": model, "prompt": text}
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{_OLLAMA_BASE}/api/embeddings",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    return data.get("embedding", [])


def _anthropic_chat(
    prompt: str,
    system: Optional[str] = None,
    model: str = CURATED_MODELS[0],
    max_tokens: int = 4096,
) -> str:
    """Call Anthropic API. Returns text content."""
    import anthropic  # type: ignore

    profile = model_profile(model)
    client = anthropic.Anthropic()

    kwargs: Dict[str, Any] = {
        "model": model,
        "max_tokens": min(max_tokens, profile["max_output_tokens"]),
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system

    if profile["adaptive_thinking"]:
        effort = resolve_effort(model, "high")
        kwargs["output_config"] = {"effort": effort}
    elif profile.get("manual_thinking"):
        kwargs["thinking"] = {"type": "enabled", "budget_tokens": 8192}

    response = client.messages.create(**kwargs)
    parts = []
    for block in response.content:
        if hasattr(block, "text"):
            parts.append(block.text)
    return "\n".join(parts)


class _CircuitBreaker:
    """Open/half-open/closed circuit breaker for a single LLM backend."""

    def __init__(self, name: str, threshold: int = 3, reset_seconds: int = 60):
        self.name = name
        self.threshold = threshold
        self.reset_seconds = reset_seconds
        self._failures = 0
        self._opened_at: float = 0.0

    @property
    def is_open(self) -> bool:
        if self._failures >= self.threshold:
            if time.time() - self._opened_at > self.reset_seconds:
                self._failures = 0  # half-open probe
                return False
            return True
        return False

    def record_failure(self):
        self._failures += 1
        if self._failures >= self.threshold:
            self._opened_at = time.time()
            print(f"[CircuitBreaker] {self.name} OPEN after {self._failures} failures "
                  f"— pausing {self.reset_seconds}s")

    def record_success(self):
        self._failures = 0


class ModelRouter:
    """
    Three-tier LLM router.

    Priority:
      1. Anthropic (claude-fable-5)
      2. DeepSeek-R1:70b via Ollama   (reasoning-heavy gates 3-8)
      3. Gemma4:latest via Ollama     (fast gates 1-2, or last resort)
    """

    def __init__(
        self,
        primary_model: str = CURATED_MODELS[0],
        prefer_local: bool = False,
    ):
        self.primary_model = primary_model
        self.prefer_local  = prefer_local
        self._last_route: str = "none"

        self._cb_anthropic = _CircuitBreaker("anthropic", threshold=3, reset_seconds=60)
        self._cb_deepseek  = _CircuitBreaker("deepseek",  threshold=3, reset_seconds=45)
        self._cb_qwen      = _CircuitBreaker("qwen",      threshold=3, reset_seconds=45)
        self._cb_gemma     = _CircuitBreaker("gemma",     threshold=5, reset_seconds=30)

        # Cache which Ollama models are available (checked once per instance)
        self._deepseek_available: Optional[bool] = None
        self._qwen_available:     Optional[bool] = None
        self._embed_available:    Optional[bool] = None

    @property
    def last_route(self) -> str:
        return self._last_route

    # ── Availability checks (cached per instance) ─────────────────────────────

    def _has_deepseek(self) -> bool:
        if self._deepseek_available is None:
            self._deepseek_available = _ollama_available() and _model_pulled(_DEEPSEEK_MODEL)
        return self._deepseek_available

    def _has_qwen(self) -> bool:
        if self._qwen_available is None:
            self._qwen_available = _ollama_available() and _model_pulled(_QWEN_MODEL)
        return self._qwen_available

    def _has_embed(self) -> bool:
        if self._embed_available is None:
            self._embed_available = _ollama_available() and _model_pulled(_EMBED_MODEL)
        return self._embed_available

    # ── Main completion entry ──────────────────────────────────────────────────

    def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        gate: Optional[int] = None,
        max_tokens: int = 4096,
        think: bool = False,
        code: bool = False,
    ) -> str:
        """
        Route a completion. Gate and task type determine which local model to use.

        Gates 1-2    → Gemma4 (fast, no reasoning needed)
        Gates 3-8    → DeepSeek-R1 when Anthropic unavailable
        code=True    → Qwen2.5-Coder (Solidity reading, PoC generation)
        prefer_local → DeepSeek-R1 for everything
        """
        is_cheap_gate     = gate in _LOCAL_GATES
        is_reasoning_gate = gate in _REASONING_GATES

        # Code tasks → Qwen2.5-Coder when Anthropic unavailable
        if code and not self.prefer_local and not os.environ.get("ANTHROPIC_API_KEY"):
            if self._has_qwen() and not self._cb_qwen.is_open:
                return self._call_qwen(prompt, system, think)

        # Fast path: cheap gates go straight to Gemma4
        if is_cheap_gate and not self.prefer_local and _ollama_available():
            return self._call_gemma(prompt, system, think)

        # Prefer local: use DeepSeek for everything if available
        if self.prefer_local:
            if self._has_deepseek():
                return self._call_deepseek(prompt, system, think)
            if _ollama_available():
                return self._call_gemma(prompt, system, think)

        # No Anthropic key → local fallback
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return self._local_fallback(prompt, system, think, is_reasoning_gate)

        # Try Anthropic (primary)
        if not self._cb_anthropic.is_open:
            try:
                result = _anthropic_chat(prompt, system, self.primary_model, max_tokens)
                self._cb_anthropic.record_success()
                self._last_route = "anthropic"
                return result
            except Exception as e:
                err = str(e).lower()
                if any(k in err for k in ("rate_limit", "overloaded", "connection", "529", "timeout")):
                    self._cb_anthropic.record_failure()
                    print(f"[ModelRouter] Anthropic {type(e).__name__} — falling back to local")
                else:
                    raise
        else:
            print(f"[ModelRouter] Anthropic circuit OPEN — routing locally")

        return self._local_fallback(prompt, system, think, is_reasoning_gate)

    def _local_fallback(
        self, prompt: str, system: Optional[str], think: bool, prefer_reasoning: bool
    ) -> str:
        """Choose between DeepSeek, Qwen, and Gemma4 based on task type."""
        if prefer_reasoning and self._has_deepseek() and not self._cb_deepseek.is_open:
            return self._call_deepseek(prompt, system, think)
        if self._has_qwen() and not self._cb_qwen.is_open:
            return self._call_qwen(prompt, system, think)
        if _ollama_available() and not self._cb_gemma.is_open:
            return self._call_gemma(prompt, system, think)
        if self._has_deepseek() and not self._cb_deepseek.is_open:
            return self._call_deepseek(prompt, system, think)
        raise RuntimeError(
            "[ModelRouter] All backends unavailable. "
            "Check: ANTHROPIC_API_KEY, ollama serve, "
            "ollama pull deepseek-r1:14b, ollama pull qwen2.5-coder:14b"
        )

    def _call_qwen(self, prompt: str, system: Optional[str], think: bool) -> str:
        if self._cb_qwen.is_open:
            raise RuntimeError("[ModelRouter] Qwen circuit OPEN")
        try:
            result = _ollama_chat(prompt, system, _QWEN_MODEL, think=think, timeout=180)
            self._cb_qwen.record_success()
            self._last_route = "qwen"
            return result
        except Exception as e:
            self._cb_qwen.record_failure()
            raise

    def _call_deepseek(self, prompt: str, system: Optional[str], think: bool) -> str:
        if self._cb_deepseek.is_open:
            raise RuntimeError("[ModelRouter] DeepSeek circuit OPEN")
        try:
            # DeepSeek-R1 takes longer — extend timeout to 300s
            result = _ollama_chat(prompt, system, _DEEPSEEK_MODEL, think=think, timeout=300)
            self._cb_deepseek.record_success()
            self._last_route = "deepseek"
            return result
        except Exception as e:
            self._cb_deepseek.record_failure()
            raise

    def _call_gemma(self, prompt: str, system: Optional[str], think: bool) -> str:
        if self._cb_gemma.is_open:
            raise RuntimeError("[ModelRouter] Gemma4 circuit OPEN")
        try:
            result = _ollama_chat(prompt, system, _GEMMA_MODEL, think=think, timeout=120)
            self._cb_gemma.record_success()
            self._last_route = "gemma4"
            return result
        except Exception as e:
            self._cb_gemma.record_failure()
            raise

    # ── Embedding ─────────────────────────────────────────────────────────────

    def embed(self, text: str) -> List[float]:
        """
        Return a semantic embedding vector using nomic-embed-text.
        Returns empty list if embedding model unavailable (fail-soft).
        """
        if not self._has_embed():
            return []
        try:
            return _ollama_embed(text, _EMBED_MODEL)
        except Exception as e:
            print(f"[ModelRouter] embed() failed: {e}")
            return []

    @staticmethod
    def cosine_similarity(a: List[float], b: List[float]) -> float:
        """Cosine similarity between two embedding vectors. Returns 0.0 on error."""
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        mag_a = sum(x * x for x in a) ** 0.5
        mag_b = sum(x * x for x in b) ** 0.5
        return dot / (mag_a * mag_b) if mag_a and mag_b else 0.0

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        ollama_up = _ollama_available()
        models_available = []
        if ollama_up:
            try:
                req = urllib.request.Request(f"{_OLLAMA_BASE}/api/tags")
                with urllib.request.urlopen(req, timeout=2) as r:
                    data = json.loads(r.read())
                    models_available = [m["name"] for m in data.get("models", [])]
            except Exception:
                pass

        return {
            "primary":           self.primary_model,
            "deepseek_model":    _DEEPSEEK_MODEL,
            "qwen_model":        _QWEN_MODEL,
            "gemma_model":       _GEMMA_MODEL,
            "embed_model":       _EMBED_MODEL,
            "anthropic_key":     bool(os.environ.get("ANTHROPIC_API_KEY")),
            "ollama_available":  ollama_up,
            "deepseek_pulled":   self._has_deepseek(),
            "qwen_pulled":       self._has_qwen(),
            "embed_pulled":      self._has_embed(),
            "ollama_models":     models_available,
            "prefer_local":      self.prefer_local,
            "cb_anthropic_open": self._cb_anthropic.is_open,
            "cb_deepseek_open":  self._cb_deepseek.is_open,
            "cb_qwen_open":      self._cb_qwen.is_open,
            "cb_gemma_open":     self._cb_gemma.is_open,
        }
