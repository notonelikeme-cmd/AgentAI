"""Gate 0 — Novelty Check. MUST run before any other gate.

Two-layer novelty detection:
  1. Regex pattern matching (always on, no dependencies)
  2. Semantic embedding similarity via nomic-embed-text (when available)
     — catches near-duplicates that differ in wording but mean the same thing
     — similarity > 0.92 with a known finding = BLOCKED
"""
import re
import sqlite3
from pathlib import Path
from typing import List

DB_PATH      = Path.home() / "AgentAI" / ".claude" / "defi_kg.db"
FINDINGS_DB  = Path.home() / "AgentAI" / "training_data" / "gate0_embeddings.db"

_EMBED_SCHEMA = """
CREATE TABLE IF NOT EXISTS hypothesis_embeddings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hypothesis  TEXT NOT NULL,
    embedding   BLOB NOT NULL,
    verdict     TEXT DEFAULT 'pending',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

# Similarity threshold: findings scoring above this are near-duplicates
_SIM_THRESHOLD = 0.92


class Gate0Novelty:
    """Checks if a finding hypothesis is novel (not already known/submitted)."""

    KNOWN_PATTERNS = [
        # AMM / flash loan
        r"flash.?loan.*reentr",
        r"price.?manipulat.*oracle",
        r"first.?deposit.*inflation",
        r"donation.?attack",
        # Proxy
        r"storage.?collision.*proxy",
        r"uninitiali.*implementation",
        # Classic EVM
        r"integer.?overflow.*unchecked",
        r"reentr.*withdraw.*balances",
        r"reentr.*transfer.*before.*update",
        # Signature / auth
        r"signature.?replay",
        r"front.?run.*signature",
        # Vault / share accounting
        r"share.*inflation.*virtual.*offset",
        r"totalassets.*donation.*manipul",
    ]

    def __init__(self):
        FINDINGS_DB.parent.mkdir(parents=True, exist_ok=True)
        self._emb_con = sqlite3.connect(str(FINDINGS_DB), check_same_thread=False)
        self._emb_con.executescript(_EMBED_SCHEMA)
        self._emb_con.commit()
        self._router = None  # lazy-loaded

    def _get_router(self):
        if self._router is None:
            try:
                from core.model_router import ModelRouter
                self._router = ModelRouter()
            except Exception:
                pass
        return self._router

    def check(self, hypothesis: str) -> dict:
        h = hypothesis.lower()
        results = {
            "hypothesis": hypothesis,
            "novel":          True,
            "matches":        [],
            "semantic_score": 0.0,
            "recommendation": "proceed",
        }

        # Layer 1: Regex pattern matching
        for pattern in self.KNOWN_PATTERNS:
            if re.search(pattern, h):
                results["matches"].append({
                    "type":    "known_pattern",
                    "pattern": pattern,
                    "note":    "Common vulnerability class — verify this specific instance is distinct",
                })

        # Layer 2: Local findings DB keyword match
        if DB_PATH.exists():
            try:
                con = sqlite3.connect(str(DB_PATH))
                words = [w for w in h.split() if len(w) > 5]
                for word in words[:5]:
                    con.execute(
                        "SELECT title FROM findings WHERE LOWER(title) LIKE ?",
                        (f"%{word}%",)
                    )
                    rows = con.fetchall() if hasattr(con, "fetchall") else \
                           con.execute("SELECT title FROM findings WHERE LOWER(title) LIKE ?",
                                       (f"%{word}%",)).fetchall()
                    for (title,) in rows:
                        results["matches"].append({
                            "type":  "local_db_match",
                            "title": title,
                            "note":  "Potential duplicate in local findings DB",
                        })
                con.close()
            except Exception as e:
                results["db_error"] = str(e)

        # Layer 3: Semantic embedding similarity (nomic-embed-text)
        semantic_blocked = False
        router = self._get_router()
        if router:
            emb = router.embed(hypothesis)
            if emb:
                score, match_text = self._semantic_check(hypothesis, emb)
                results["semantic_score"] = round(score, 4)
                if score >= _SIM_THRESHOLD:
                    results["matches"].append({
                        "type":  "semantic_duplicate",
                        "score": round(score, 4),
                        "match": match_text[:120],
                        "note":  f"Semantic similarity {score:.2%} ≥ {_SIM_THRESHOLD:.0%} — near-duplicate detected",
                    })
                    semantic_blocked = True
                # Store this embedding for future comparisons
                self._store_embedding(hypothesis, emb)

        # Decision
        exact_dups = [m for m in results["matches"] if m["type"] == "local_db_match"]
        if semantic_blocked:
            results["novel"] = False
            results["recommendation"] = "BLOCKED — semantic duplicate (cosine similarity ≥ 0.92)"
        elif len(exact_dups) >= 2:
            results["novel"] = False
            results["recommendation"] = "BLOCKED — likely duplicate, found in local DB"
        elif results["matches"]:
            results["recommendation"] = "verify_novelty — check matches above before proceeding"

        return results

    def _semantic_check(self, hypothesis: str, emb: List[float]) -> tuple[float, str]:
        """Compare against all stored embeddings. Returns (max_score, matching_text)."""
        import json as _json
        from core.model_router import ModelRouter

        rows = self._emb_con.execute(
            "SELECT hypothesis, embedding FROM hypothesis_embeddings"
        ).fetchall()

        best_score = 0.0
        best_text  = ""
        for stored_text, emb_blob in rows:
            try:
                stored_emb = _json.loads(emb_blob)
                score = ModelRouter.cosine_similarity(emb, stored_emb)
                if score > best_score:
                    best_score = score
                    best_text  = stored_text
            except Exception:
                continue
        return best_score, best_text

    def _store_embedding(self, hypothesis: str, emb: List[float]):
        """Persist embedding for future Gate 0 comparisons."""
        import json as _json
        self._emb_con.execute(
            "INSERT INTO hypothesis_embeddings (hypothesis, embedding) VALUES (?, ?)",
            (hypothesis, _json.dumps(emb)),
        )
        self._emb_con.commit()

    def record_verdict(self, hypothesis: str, verdict: str):
        """Update a stored hypothesis with its final pipeline verdict (VALID / FALSE_POSITIVE)."""
        self._emb_con.execute(
            "UPDATE hypothesis_embeddings SET verdict=? WHERE hypothesis=?",
            (verdict, hypothesis),
        )
        self._emb_con.commit()
