"""LLMAuditor — feeds real Solidity source to the ModelRouter and gets
contract-specific hypotheses back in Gate-1-ready IF/THEN/BECAUSE format.

This is the missing link between the KG-template RAOBrain and a real
autonomous auditor. Instead of filling mad-libs from the KG, it reads
actual function code and asks Pi/Gemma4 (or Anthropic) to reason about it.

Usage:
    from core.llm_auditor import LLMAuditor
    auditor = LLMAuditor()
    hypotheses = auditor.analyze("/tmp/morpho-blue/src/Morpho.sol")
    for h in hypotheses:
        print(h.text)
"""
from __future__ import annotations

import asyncio
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# ── System prompts ────────────────────────────────────────────────────────────

_SYSTEM_FUNCTION_AUDIT = """\
You are an elite DeFi smart contract security auditor. I will show you a Solidity function.

RULES:
1. NEVER claim a vulnerability without citing the exact line you can see in this snippet.
2. NEVER invent function names, variable names, or behavior not visible in the code.
3. Every claim must follow: EVIDENCE → REASONING → CONCLUSION.
4. Trusted role / owner findings are out of scope for Critical at Immunefi.
5. If there is NO vulnerability, output exactly: NONE

For each vulnerability you find, output ONE line in this exact format:
HYPOTHESIS: IF [specific on-chain condition] THEN [attacker action + quantified impact] BECAUSE [exact code flaw, filename:linenum]

Output ONLY hypothesis lines or NONE. No preamble, no explanation."""

_SYSTEM_CONTRACT_OVERVIEW = """\
You are a DeFi security auditor performing initial reconnaissance.
I will show you a Solidity contract. List the 3-5 highest-risk functions
that deserve deep manual review — functions that handle token transfers,
share accounting, external calls, or access control.

Output format (one line per function):
RISK: [function_name] — [one sentence on why it's high risk]

Output ONLY RISK lines. No preamble."""

# ── Prompt injection defense ─────────────────────────────────────────────────

_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior|above)\s+(rules?|instructions?|prompts?)|"
    r"disregard\s+(all\s+)?(previous|prior)\s+|"
    r"you\s+are\s+now\s+|"
    r"new\s+instruction|"
    r"system\s*:\s*you\s+|"
    r"<\s*system\s*>|"
    r"\[INST\]|\[\/INST\]|"
    r"###\s*(Instruction|System|Human|Assistant)\s*:)",
    re.IGNORECASE,
)

def _sanitize_source(source: str) -> str:
    """Strip prompt-injection attempts from contract source before LLM submission."""
    # Replace the injection phrase itself with [REDACTED], preserve surrounding code
    sanitized = _INJECTION_PATTERNS.sub("[REDACTED]", source)
    return sanitized


# ── Solidity function extractor ───────────────────────────────────────────────

_RE_FUNC = re.compile(
    r"(?:^|\n)(\s*(?:\/\/[^\n]*\n\s*)*)"  # optional leading comments
    r"(\s*function\s+(\w+)\s*\([^)]*\)"   # function signature
    r"[^{]*?\{)",                           # up to opening brace
    re.MULTILINE,
)


def _extract_functions(source: str) -> list[dict]:
    """Extract function name + body from Solidity source, with line numbers."""
    lines = source.splitlines()
    funcs = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"\s*function\s+(\w+)\s*\(", line)
        if m:
            name = m.group(1)
            start = i + 1  # 1-indexed
            depth = 0
            body_lines = []
            found_open = False
            end = start
            for j in range(i, min(i + 250, len(lines))):
                body_lines.append(f"{j+1:4d}: {lines[j]}")
                opens  = lines[j].count("{")
                closes = lines[j].count("}")
                depth += opens - closes
                if opens > 0:
                    found_open = True
                # Only close when we've seen at least one { and depth returns to 0
                if found_open and depth <= 0:
                    end = j + 1
                    funcs.append({
                        "name": name,
                        "start": start,
                        "end": end,
                        "body": "\n".join(body_lines),
                        "line_count": end - start,
                    })
                    i = j
                    break
        i += 1
    return funcs


def _skip_function(name: str) -> bool:
    """Skip trivial functions unlikely to have interesting bugs."""
    skip = {"constructor", "receive", "fallback", "name", "symbol", "decimals",
            "totalSupply", "balanceOf", "allowance", "version", "domainSeparator"}
    return name in skip or name.startswith("_get") or name.startswith("_set")


# ── Hypothesis parser ─────────────────────────────────────────────────────────

def _parse_hypotheses(llm_response: str, contract_name: str) -> list[str]:
    """Extract HYPOTHESIS: lines from LLM output, filter malformed ones."""
    results = []
    for line in llm_response.splitlines():
        line = line.strip()
        if not line.startswith("HYPOTHESIS:"):
            continue
        h = line[len("HYPOTHESIS:"):].strip()
        h_lower = h.lower()
        # Must have IF/THEN/BECAUSE
        if not ("if " in h_lower and "then " in h_lower and "because " in h_lower):
            continue
        # Must have a file:line citation
        if not re.search(r'\w+\.sol:\d+', h):
            continue
        # Must not be a template placeholder
        if "<contract>" in h or "<line>" in h or "contract_path" in h:
            continue
        results.append(h)
    return results


# ── Main class ────────────────────────────────────────────────────────────────

@dataclass
class LLMHypothesis:
    text: str
    source_function: str
    source_file: str
    confidence: str = "medium"
    citations: list = field(default_factory=list)

    def to_hypothesis(self):
        """Convert to RAOBrain Hypothesis, with context-bonus scoring."""
        from core.rao_brain import Hypothesis
        base = {"high": 0.75, "medium": 0.50, "low": 0.25}.get(self.confidence, 0.50)

        # Context bonus: critical DeFi keywords raise prior probability
        text_lower = self.text.lower()
        bonus = 0.0
        _CRITICAL_SIGNALS = {
            "flash loan": 0.15, "flashloan": 0.15,
            "token transfer": 0.10, "safeTransfer": 0.08,
            "totalassets": 0.10, "totalsupply": 0.08,
            "liquidat": 0.12, "borrow": 0.08, "collateral": 0.08,
            "reentr": 0.15, "callback": 0.08,
            "overflow": 0.10, "underflow": 0.10, "unchecked": 0.12,
            "governance": 0.08, "admin": 0.05, "owner": 0.03,
            "oracle": 0.12, "price": 0.08, "slot0": 0.15,
            "drain": 0.12, "steal": 0.12, "profit": 0.08,
        }
        for keyword, weight in _CRITICAL_SIGNALS.items():
            if keyword in text_lower:
                bonus = min(bonus + weight, 0.30)  # cap total bonus at +0.30

        final_score = min(base + bonus, 0.95)

        return Hypothesis(
            text=self.text,
            pattern_id=f"LLM-{self.source_function}",
            score=final_score,
            rationale=(
                f"LLM analysis of {self.source_function}() "
                f"[base={base:.2f} bonus={bonus:.2f}]"
            ),
            evidence_hints=self.citations,
        )


class LLMAuditor:
    """Feeds real Solidity source to an LLM and returns Gate-1-ready hypotheses."""

    def __init__(self, router=None, max_functions: int = 15):
        self._router = router
        self._max_functions = max_functions

    def _get_router(self):
        if self._router:
            return self._router
        from core.model_router import ModelRouter
        return ModelRouter()

    def analyze(
        self,
        contract_path: str,
        focus_functions: Optional[list[str]] = None,
        verbose: bool = True,
    ) -> List[LLMHypothesis]:
        """
        Read a Solidity file, extract functions, and ask the LLM to find bugs.

        Args:
            contract_path:    Path to .sol file or directory of .sol files
            focus_functions:  If given, only analyze these function names
            verbose:          Print progress to stdout

        Returns:
            List of LLMHypothesis objects, deduplicated
        """
        path = Path(contract_path)
        sol_files = (
            [path] if path.is_file() and path.suffix == ".sol"
            else sorted(path.rglob("*.sol"))
        )
        sol_files = [f for f in sol_files
                     if not any(skip in str(f) for skip in
                                ["test", "mock", "lib/openzeppelin", "node_modules", "out/", "cache/"])]

        all_hypotheses: List[LLMHypothesis] = []
        router = self._get_router()

        for sol_file in sol_files[:5]:  # cap at 5 files per run
            if verbose:
                print(f"[LLMAuditor] Analyzing {sol_file.name}...")

            try:
                raw_source = sol_file.read_text(errors="replace")
            except Exception as e:
                print(f"[LLMAuditor] Cannot read {sol_file}: {e}")
                continue

            source = _sanitize_source(raw_source)

            # Step 1: get high-risk function list from overview
            high_risk = self._overview(source, sol_file.name, router, verbose)

            # Step 2: extract all functions
            functions = _extract_functions(source)
            if verbose:
                print(f"[LLMAuditor] Found {len(functions)} functions, "
                      f"{len(high_risk)} flagged high-risk")

            # Prioritize: focus_functions > high_risk > all > skip trivial
            def priority(f):
                name = f["name"]
                if focus_functions and name in focus_functions:
                    return 0
                if name in high_risk:
                    return 1
                if _skip_function(name):
                    return 99
                return 2

            functions.sort(key=priority)
            functions = [f for f in functions if priority(f) < 99]
            functions = functions[:self._max_functions]

            # Step 3: analyze functions in parallel (M5 Max: 18 cores)
            # Cap workers at 4 to avoid hammering Ollama rate limits
            workers = min(4, len(functions))
            _print_lock = threading.Lock()

            def audit_fn(fn):
                result = self._analyze_function(fn, sol_file.name, router, verbose=False)
                if verbose:
                    with _print_lock:
                        count = len(result)
                        status = f"{count} hypothesis(es)" if count else "clean"
                        print(f"  → {fn['name']}() ({fn['line_count']} lines)... {status}")
                return result

            with ThreadPoolExecutor(max_workers=workers) as pool:
                for batch in pool.map(audit_fn, functions):
                    all_hypotheses.extend(batch)

        # Deduplicate by similarity
        return self._dedup(all_hypotheses)

    def _overview(self, source: str, filename: str, router, verbose: bool) -> set[str]:
        """Ask LLM which functions are highest risk. Returns set of names."""
        try:
            # Send first 4000 chars (contract skeleton) for overview
            snippet = source[:4000]
            prompt = f"File: {filename}\n\n```solidity\n{snippet}\n```"
            response = router.complete(
                prompt, system=_SYSTEM_CONTRACT_OVERVIEW, gate=1
            )
            names = set()
            for line in response.splitlines():
                m = re.match(r"RISK:\s*(\w+)", line.strip())
                if m:
                    names.add(m.group(1))
            if verbose and names:
                print(f"[LLMAuditor] High-risk functions: {sorted(names)}")
            return names
        except Exception as e:
            if verbose:
                print(f"[LLMAuditor] Overview failed: {e}")
            return set()

    def _analyze_function(
        self, fn: dict, filename: str, router, verbose: bool
    ) -> List[LLMHypothesis]:
        """Send one function body to the LLM and parse hypotheses from the response."""
        name = fn["name"]
        body = fn["body"]

        # Skip very short functions (getters, etc.)
        if fn["line_count"] < 4:
            return []

        prompt = (
            f"File: {filename}, function: {name}() "
            f"(lines {fn['start']}-{fn['end']})\n\n"
            f"```solidity\n{body}\n```"
        )

        if verbose:
            print(f"  → auditing {name}() ({fn['line_count']} lines)...", end=" ", flush=True)

        try:
            response = router.complete(prompt, system=_SYSTEM_FUNCTION_AUDIT, gate=1)
        except Exception as e:
            if verbose:
                print(f"ERROR: {e}")
            return []

        if verbose:
            stripped = response.strip()
            if stripped == "NONE" or not stripped:
                print("clean")
            else:
                count = sum(1 for l in response.splitlines() if l.startswith("HYPOTHESIS:"))
                print(f"{count} hypothesis(es)")

        raw = _parse_hypotheses(response, filename)
        results = []
        for h_text in raw:
            citations = re.findall(r'\w+\.sol:\d+', h_text)
            results.append(LLMHypothesis(
                text=h_text,
                source_function=name,
                source_file=filename,
                citations=citations,
            ))
        return results

    def _dedup(self, hypotheses: List[LLMHypothesis]) -> List[LLMHypothesis]:
        """Remove near-duplicate hypotheses (same function + similar IF clause)."""
        seen: set[str] = set()
        out = []
        for h in hypotheses:
            # Key on function name + first 60 chars of IF clause
            m = re.search(r"IF\s+(.{1,60})", h.text, re.IGNORECASE)
            key = f"{h.source_function}:{m.group(1).lower() if m else h.text[:60].lower()}"
            if key not in seen:
                seen.add(key)
                out.append(h)
        return out

    def quick_scan(self, contract_path: str) -> list[str]:
        """One-shot scan: returns list of hypothesis strings only. No verbose."""
        return [h.text for h in self.analyze(contract_path, verbose=False)]
