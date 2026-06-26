"""Gate 0 — Novelty Check. MUST run before any other gate."""
import sqlite3
import re
from pathlib import Path

DB_PATH = Path.home() / "AgentAI" / ".claude" / "defi_kg.db"


class Gate0Novelty:
    """Checks if a finding hypothesis is novel (not already known/submitted)."""

    KNOWN_PATTERNS = [
        # AMM patterns
        r"flash.?loan.*reentr",
        r"price.?manipulat.*oracle",
        r"first.?deposit.*inflation",
        r"donation.?attack",
        # Proxy patterns
        r"storage.?collision.*proxy",
        r"uninitiali.*implementation",
        # Classic EVM
        r"integer.?overflow.*unchecked",
        r"reentr.*withdraw.*balances",
        r"reentr.*transfer.*before.*update",
        # Signature/auth
        r"signature.?replay",
        r"front.?run.*signature",
    ]

    def check(self, hypothesis: str) -> dict:
        h = hypothesis.lower()
        results = {
            "hypothesis": hypothesis,
            "novel": True,
            "matches": [],
            "recommendation": "proceed",
        }

        # Check against known patterns
        for pattern in self.KNOWN_PATTERNS:
            if re.search(pattern, h):
                results["matches"].append({
                    "type": "known_pattern",
                    "pattern": pattern,
                    "note": "Common vulnerability class — verify this specific instance is distinct",
                })

        # Check local findings DB
        if DB_PATH.exists():
            try:
                con = sqlite3.connect(str(DB_PATH))
                cur = con.cursor()
                # Simple substring match on existing findings
                words = [w for w in h.split() if len(w) > 5]
                for word in words[:5]:
                    cur.execute(
                        "SELECT title FROM findings WHERE LOWER(title) LIKE ?",
                        (f"%{word}%",)
                    )
                    rows = cur.fetchall()
                    for (title,) in rows:
                        results["matches"].append({
                            "type": "local_db_match",
                            "title": title,
                            "note": "Potential duplicate in local findings DB",
                        })
                con.close()
            except Exception as e:
                results["db_error"] = str(e)

        if results["matches"]:
            results["recommendation"] = "verify_novelty — check the matches above before proceeding"
            # Still novel unless we find exact duplicate
            # Gate 0 blocks only on certain duplicates, not pattern matches
            exact_dups = [m for m in results["matches"] if m["type"] == "local_db_match"]
            if len(exact_dups) >= 2:
                results["novel"] = False
                results["recommendation"] = "BLOCKED — likely duplicate, found in local DB"

        return results
