"""FindingsDB — SQLite-backed findings registry."""
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

DB_PATH = Path.home() / "AgentAI" / ".claude" / "defi_kg.db"


def _get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    return con


def _init_schema(con: sqlite3.Connection):
    con.executescript("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            contract TEXT,
            hypothesis TEXT,
            gate_status TEXT,
            net_profit REAL,
            submission_platform TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            notes TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
        CREATE INDEX IF NOT EXISTS idx_findings_title ON findings(title);
    """)
    con.commit()


class FindingsDB:
    def __init__(self):
        self._con = _get_conn()
        _init_schema(self._con)

    def add(
        self,
        title: str,
        severity: str,
        contract: str = "",
        hypothesis: str = "",
        gate_status: str = "",
        net_profit: float = 0.0,
        platform: str = "",
        notes: str = "",
    ) -> str:
        fid = str(uuid.uuid4())[:8]
        now = datetime.utcnow().isoformat()
        self._con.execute(
            """INSERT INTO findings
               (id, title, severity, status, contract, hypothesis, gate_status,
                net_profit, submission_platform, created_at, updated_at, notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (fid, title, severity, "pending", contract, hypothesis,
             gate_status, net_profit, platform, now, now, notes),
        )
        self._con.commit()
        return fid

    def update_status(self, fid: str, status: str):
        now = datetime.utcnow().isoformat()
        self._con.execute(
            "UPDATE findings SET status=?, updated_at=? WHERE id=?",
            (status, now, fid),
        )
        self._con.commit()

    def get(self, fid: str) -> Optional[dict]:
        cur = self._con.execute("SELECT * FROM findings WHERE id=?", (fid,))
        row = cur.fetchone()
        return dict(row) if row else None

    def list_findings(self, status: str = None, severity: str = None) -> List[dict]:
        sql = "SELECT * FROM findings WHERE 1=1"
        params = []
        if status:
            sql += " AND status=?"
            params.append(status)
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        sql += " ORDER BY created_at DESC"
        cur = self._con.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def search(self, query: str) -> List[dict]:
        cur = self._con.execute(
            "SELECT * FROM findings WHERE LOWER(title) LIKE ? OR LOWER(hypothesis) LIKE ?",
            (f"%{query.lower()}%", f"%{query.lower()}%"),
        )
        return [dict(r) for r in cur.fetchall()]

    def close(self):
        self._con.close()
