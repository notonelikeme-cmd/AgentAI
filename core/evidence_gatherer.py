"""EvidenceGatherer — auto-finds code citations for a hypothesis.

Gate 2 currently blocks if the hypothesis text doesn't already contain
file:line citations. This module greps the contract for signals matching
the hypothesis vocabulary and injects real citations automatically.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Dict, Any, Optional

# Keywords that suggest the relevant Solidity construct
_MECHANISM_KEYWORDS: dict[str, list[str]] = {
    "reentrancy":         ["transfer(", "call{", ".call(", "send(", "withdraw", "balances["],
    "flash_loan":         ["flashLoan", "flash_loan", "callback", "uniswapV3Flash", "executeOperation"],
    "oracle":             ["getPrice", "latestAnswer", "observe(", "slot0(", "sqrtPriceX96", "twap", "TWAP"],
    "price_manipulation": ["slot0", "sqrtPriceX96", "getAmountOut", "balanceOf(", "reserve0", "reserve1"],
    "access_control":     ["onlyOwner", "onlyRole", "require(msg.sender", "require(tx.origin", "admin"],
    "storage_collision":  ["delegatecall", "implementation", "upgradeToAndCall", "_implementation"],
    "inflation":          ["totalSupply", "totalAssets", "convertToShares", "previewDeposit", "shares"],
    "donation":           ["balanceOf(address(this))", "totalAssets", "donate"],
    "fee_on_transfer":    ["transfer(", "transferFrom(", "balanceBefore", "balanceAfter"],
    "selfdestruct":       ["selfdestruct", "SELFDESTRUCT"],
    "unchecked":          ["unchecked {", "unchecked{"],
    "timestamp":          ["block.timestamp", "now "],
    "tx_origin":          ["tx.origin"],
}

_H_VOCAB_RE = re.compile(r"\b(\w+)\b")


def _hypothesis_mechanisms(hypothesis: str) -> list[str]:
    """Infer mechanism keywords from the hypothesis text."""
    h_lower = hypothesis.lower()
    found = []
    for mech, _ in _MECHANISM_KEYWORDS.items():
        if mech.replace("_", " ") in h_lower or mech in h_lower:
            found.append(mech)
    # Also check individual words in hypothesis against mechanism names
    words = {w.lower() for w in _H_VOCAB_RE.findall(hypothesis) if len(w) > 4}
    for mech in _MECHANISM_KEYWORDS:
        if any(part in words for part in mech.split("_")):
            if mech not in found:
                found.append(mech)
    return found or list(_MECHANISM_KEYWORDS.keys())


def _search_file(path: Path, keywords: list[str]) -> list[dict]:
    """Grep a file for keywords; return [{file, line, snippet}]."""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except Exception:
        return []

    hits = []
    for lineno, text in enumerate(lines, start=1):
        for kw in keywords:
            if kw.lower() in text.lower():
                hits.append({
                    "file": str(path),
                    "line": lineno,
                    "citation": f"{path.name}:{lineno}",
                    "snippet": text.strip()[:120],
                    "keyword": kw,
                })
                break  # one hit per line
    return hits


class EvidenceGatherer:
    """Auto-collects code citations for a vulnerability hypothesis."""

    def gather(
        self,
        hypothesis: str,
        contract_path: str,
        max_citations: int = 5,
    ) -> dict:
        """
        Returns:
            {
                citations: ["File.sol:42", ...],
                evidence:  [{file, line, snippet, keyword}, ...],
                mechanisms: ["reentrancy", ...],
                auto_gathered: True/False,
            }
        """
        # Check if hypothesis already has citations
        existing = re.findall(r'\w+\.sol:\d+', hypothesis)
        if existing:
            return {
                "citations": existing,
                "evidence": [],
                "mechanisms": [],
                "auto_gathered": False,
            }

        # Determine mechanisms to search for
        mechanisms = _hypothesis_mechanisms(hypothesis)
        keywords = []
        for mech in mechanisms:
            keywords.extend(_MECHANISM_KEYWORDS.get(mech, []))
        keywords = list(dict.fromkeys(keywords))  # dedupe preserving order

        # Collect Solidity files to search
        contract = Path(contract_path)
        sol_files: list[Path] = []
        if contract.is_file() and contract.suffix == ".sol":
            sol_files = [contract]
        elif contract.is_dir():
            sol_files = [
                f for f in contract.rglob("*.sol")
                if not any(skip in str(f) for skip in ["node_modules", "lib/openzeppelin", ".venv"])
            ]
        elif contract.is_file():
            # Try to find .sol files adjacent to the given file
            sol_files = list(contract.parent.rglob("*.sol"))[:10]

        if not sol_files:
            return {
                "citations": [],
                "evidence": [],
                "mechanisms": mechanisms,
                "auto_gathered": True,
                "error": f"No .sol files found at {contract_path}",
            }

        # Gather hits across all files
        all_hits: list[dict] = []
        for sol in sol_files:
            all_hits.extend(_search_file(sol, keywords))

        # Score hits: prefer lines that match more keywords
        scored: dict[str, dict] = {}
        for hit in all_hits:
            key = hit["citation"]
            if key not in scored:
                scored[key] = {**hit, "score": 0}
            scored[key]["score"] += 1

        ranked = sorted(scored.values(), key=lambda h: h["score"], reverse=True)
        top = ranked[:max_citations]

        return {
            "citations": [h["citation"] for h in top],
            "evidence": top,
            "mechanisms": mechanisms,
            "auto_gathered": True,
        }
