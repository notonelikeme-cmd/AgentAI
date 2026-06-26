"""DataIngestor — unified threat intelligence pipeline.

Pulls from multiple sources, normalizes to Hypothesis objects,
and seeds RAOBrain with real-world attack patterns.

Sources:
  - DeFiHackLabs (GitHub PoC contracts) → github_fetcher.py
  - HuggingFace datasets                → hf_fetcher.py
  - Manual JSON feed                    → load_feed()

Usage:
    from core.data_ingestor import DataIngestor
    ingestor = DataIngestor()
    hypotheses = ingestor.ingest_all(max_per_source=100)
    # → List[Hypothesis] enriched from real incidents
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


_DB_PATH = Path.home() / "AgentAI" / "training_data" / "ingestor_cache.db"
_SCHEMA  = """
CREATE TABLE IF NOT EXISTS ingested (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT DEFAULT 'High',
    mechanism   TEXT DEFAULT '',
    hypothesis  TEXT NOT NULL,
    raw_data    TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ingested_mechanism ON ingested(mechanism);
"""


@dataclass
class IngestedFinding:
    source:     str
    title:      str
    severity:   str
    mechanism:  str
    hypothesis: str           # IF/THEN/BECAUSE text
    raw:        dict = field(default_factory=dict)

    def to_hypothesis(self):
        """Convert to RAOBrain Hypothesis for direct pipeline injection."""
        from core.rao_brain import Hypothesis
        _SEVERITY_SCORE = {"Critical": 0.85, "High": 0.65, "Medium": 0.40, "Low": 0.20}
        return Hypothesis(
            text=self.hypothesis,
            pattern_id=f"ING-{re.sub(r'[^A-Z0-9]', '', self.mechanism.upper()[:8])}-{hash(self.title) % 9999:04d}",
            score=_SEVERITY_SCORE.get(self.severity, 0.50),
            rationale=f"[{self.severity}] {self.source}: {self.title[:60]}",
            evidence_hints=[self.mechanism],
        )


class DataIngestor:
    """Unified ingestion from DeFiHackLabs, HuggingFace, and manual feeds."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = Path(db_path) if db_path else _DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._con.executescript(_SCHEMA)
        self._con.commit()

    def close(self):
        self._con.close()

    # ── Public API ────────────────────────────────────────────────────────────

    def ingest_all(self, max_per_source: int = 200) -> List[IngestedFinding]:
        """Pull from all available sources and return normalized findings."""
        all_findings: List[IngestedFinding] = []

        # Source 1: DeFiHackLabs
        try:
            findings = self._ingest_github(max_per_source)
            all_findings.extend(findings)
            print(f"[DataIngestor] GitHub/DeFiHackLabs: {len(findings)} findings")
        except Exception as e:
            print(f"[DataIngestor] GitHub source failed: {e}")

        # Source 2: HuggingFace training DB
        try:
            findings = self._ingest_hf(max_per_source)
            all_findings.extend(findings)
            print(f"[DataIngestor] HuggingFace DB: {len(findings)} findings")
        except Exception as e:
            print(f"[DataIngestor] HuggingFace source failed: {e}")

        # Source 3: AgentAI memory (verified findings from prior audits)
        try:
            findings = self._ingest_memory()
            all_findings.extend(findings)
            print(f"[DataIngestor] AgentAI memory: {len(findings)} findings")
        except Exception as e:
            print(f"[DataIngestor] Memory source failed: {e}")

        # Cache to DB
        self._cache(all_findings)
        return all_findings

    def to_hypotheses(self, findings: Optional[List[IngestedFinding]] = None):
        """Convert findings to Hypothesis objects for RAOBrain injection."""
        if findings is None:
            findings = self._load_cached()
        return [f.to_hypothesis() for f in findings]

    def load_feed(self, path: str) -> List[IngestedFinding]:
        """Load a custom JSON feed of findings.

        Expected format: list of {title, severity, mechanism, description, impact}
        """
        data = json.loads(Path(path).read_text())
        findings = []
        for item in data:
            h = self._build_hypothesis(
                item.get("description", ""),
                item.get("impact", ""),
                item.get("mechanism", ""),
                item.get("title", ""),
            )
            if h:
                findings.append(IngestedFinding(
                    source="manual_feed",
                    title=item.get("title", "Unknown"),
                    severity=item.get("severity", "High"),
                    mechanism=item.get("mechanism", ""),
                    hypothesis=h,
                    raw=item,
                ))
        return findings

    # ── Private source adapters ───────────────────────────────────────────────

    def _ingest_github(self, max_count: int) -> List[IngestedFinding]:
        """Pull from DeFiHackLabs training DB (populated by github_fetcher.py)."""
        from core.github_fetcher import GitHubFetcher
        fetcher = GitHubFetcher()
        result  = fetcher.fetch(max_incidents=max_count, force_refresh=False, delay=0.0)

        findings = []
        incidents = result.get("incidents", [])
        for inc in incidents:
            mechanism = self._infer_mechanism(inc.get("title", "") + " " + inc.get("summary", ""))
            h = self._build_hypothesis(
                description=inc.get("summary", ""),
                impact=f"loss of {inc.get('amount', 'funds')}",
                mechanism=mechanism,
                title=inc.get("title", ""),
            )
            if h:
                findings.append(IngestedFinding(
                    source="DeFiHackLabs",
                    title=inc.get("title", "")[:80],
                    severity=self._severity_from_amount(inc.get("amount", "")),
                    mechanism=mechanism,
                    hypothesis=h,
                    raw=inc,
                ))
        return findings

    def _ingest_hf(self, max_count: int) -> List[IngestedFinding]:
        """Convert HuggingFace training samples to findings."""
        hf_db = Path.home() / "AgentAI" / "training_data" / "hf_training.db"
        if not hf_db.exists():
            return []

        con = sqlite3.connect(str(hf_db), check_same_thread=False, timeout=5)
        rows = con.execute(
            "SELECT dataset_id, data FROM hf_samples "
            "WHERE lower(data) LIKE '%critical%' OR lower(data) LIKE '%high%' "
            f"LIMIT {max_count}"
        ).fetchall()
        con.close()

        findings = []
        for dataset_id, raw_data in rows:
            try:
                item = json.loads(raw_data)
            except Exception:
                continue

            # Different schemas per dataset
            desc    = (item.get("description") or item.get("vulnerability_description")
                       or item.get("source_code", "")[:200] or "")
            sev     = (item.get("severity") or item.get("label") or "High")
            title   = item.get("title") or item.get("function_name") or "HF Finding"
            mechanism = self._infer_mechanism(desc + " " + title)

            h = self._build_hypothesis(
                description=desc[:300],
                impact=f"exploit yields {sev}-severity impact",
                mechanism=mechanism,
                title=title,
            )
            if h:
                findings.append(IngestedFinding(
                    source=dataset_id,
                    title=str(title)[:80],
                    severity=str(sev).capitalize() if sev else "High",
                    mechanism=mechanism,
                    hypothesis=h,
                    raw=item,
                ))
        return findings

    def _ingest_memory(self) -> List[IngestedFinding]:
        """Load verified findings from AgentAI findings_log.md."""
        findings_log = Path.home() / "AgentAI" / "memory" / "findings_log.md"
        if not findings_log.exists():
            return []

        text = findings_log.read_text()
        findings = []
        # Parse blocks like "## FLA-903: ..." + hypothesis text
        for block in re.split(r"\n## ", text):
            if not block.strip():
                continue
            lines = block.strip().splitlines()
            header = lines[0] if lines else ""
            body   = "\n".join(lines[1:])
            h_match = re.search(r"IF.+?THEN.+?BECAUSE.+", body, re.IGNORECASE | re.DOTALL)
            if h_match:
                mechanism = self._infer_mechanism(header + " " + body)
                findings.append(IngestedFinding(
                    source="agentai_memory",
                    title=header[:80],
                    severity="High",
                    mechanism=mechanism,
                    hypothesis=h_match.group(0)[:400].replace("\n", " "),
                    raw={"header": header},
                ))
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_hypothesis(
        self, description: str, impact: str, mechanism: str, title: str
    ) -> str:
        """Convert raw finding data into IF/THEN/BECAUSE format."""
        if not description or len(description) < 20:
            return ""
        desc = description[:250].replace("\n", " ").strip()
        mech = mechanism or "vulnerability"
        return (
            f"IF {mech} vulnerability exists "
            f"THEN attacker can {impact[:100]} "
            f"BECAUSE {desc} — see source:0"
        )

    def _infer_mechanism(self, text: str) -> str:
        """Quick keyword → mechanism mapping."""
        t = text.lower()
        if any(k in t for k in ("flash loan", "flashloan")):        return "flash_loan"
        if any(k in t for k in ("reentr", "re-entr")):              return "reentrancy"
        if any(k in t for k in ("oracle", "price manip", "twap")):  return "oracle_manipulation"
        if any(k in t for k in ("access control", "onlyowner")):    return "access_control"
        if any(k in t for k in ("overflow", "underflow")):          return "arithmetic"
        if any(k in t for k in ("inflation", "share", "vault")):    return "share_inflation"
        if any(k in t for k in ("proxy", "delegate", "storage")):   return "storage_collision"
        if any(k in t for k in ("governance", "vote")):             return "governance"
        if any(k in t for k in ("liquidat", "bad debt")):           return "liquidation"
        return "logic_flaw"

    def _severity_from_amount(self, amount_str: str) -> str:
        """Estimate severity from loss amount string."""
        amt = amount_str.lower().replace(",", "").replace("$", "")
        nums = re.findall(r"[\d.]+", amt)
        if nums:
            val = float(nums[0])
            if "m" in amt or "million" in amt: val *= 1_000_000
            if "k" in amt or "thousand" in amt: val *= 1_000
            if val >= 10_000_000: return "Critical"
            if val >= 1_000_000:  return "High"
            if val >= 100_000:    return "Medium"
        return "High"

    def _cache(self, findings: List[IngestedFinding]):
        """Cache normalized findings to SQLite."""
        rows = [
            (f.source, f.title, f.severity, f.mechanism, f.hypothesis, json.dumps(f.raw))
            for f in findings
        ]
        self._con.executemany(
            "INSERT OR IGNORE INTO ingested (source, title, severity, mechanism, hypothesis, raw_data) "
            "VALUES (?,?,?,?,?,?)",
            rows,
        )
        self._con.commit()

    def _load_cached(self) -> List[IngestedFinding]:
        """Load cached findings from SQLite."""
        rows = self._con.execute(
            "SELECT source, title, severity, mechanism, hypothesis, raw_data FROM ingested"
        ).fetchall()
        results = []
        for source, title, severity, mechanism, hypothesis, raw_data in rows:
            raw = {}
            try:
                raw = json.loads(raw_data) if raw_data else {}
            except Exception:
                pass
            results.append(IngestedFinding(source, title, severity, mechanism, hypothesis, raw))
        return results

    def stats(self) -> dict:
        """Return ingestion stats."""
        counts = self._con.execute(
            "SELECT source, COUNT(*) FROM ingested GROUP BY source"
        ).fetchall()
        return {
            "total": sum(c for _, c in counts),
            "by_source": dict(counts),
        }
