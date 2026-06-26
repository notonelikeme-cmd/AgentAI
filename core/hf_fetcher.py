"""HuggingFaceFetcher — pulls smart contract security datasets from Hugging Face.

Priority datasets:
  1. darkknight25/Smart_Contract_Vulnerability_Dataset   (2K entries, 15 vuln classes)
  2. msc-smart-contract-auditing/vulnerability-severity-classification  (Sherlock/Codehawks)
  3. msc-smart-contract-auditing/audits-with-reasons    (findings + rationale)
  4. GitmateAI/solidity_vulnerability_audit_dataset      (Solidity + audit pairs)
  5. seyyedaliayati/solidity-defi-vulnerabilities        (DeFi-specific)
  6. mwritescode/slither-audited-smart-contracts         (Slither labels)
  7. forta/malicious-smart-contract-dataset              (malicious vs benign)
  8. Coriolan/smart-contract-vulnerabilities             (general vuln DB)
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

_TRAINING_DIR = Path.home() / "AgentAI" / "training_data"
_HF_CACHE = _TRAINING_DIR / "hf"
_SUMMARY_PATH = _TRAINING_DIR / "hf_datasets.json"

# Ordered by priority for our use case
_DATASETS = [
    {
        "id": "darkknight25/Smart_Contract_Vulnerability_Dataset",
        "split": "train",
        "columns": None,  # all
        "max_rows": 2000,
        "description": "2000 entries, 15 vuln categories (reentrancy, flash loan, oracle, access control…)",
        "priority": 1,
    },
    {
        "id": "msc-smart-contract-auditing/vulnerability-severity-classification",
        "split": "train",
        "columns": None,
        "max_rows": 5000,
        "description": "Severity labels from Codehawks/Sherlock/ConsenSys/Cyfrin professional audits",
        "priority": 2,
    },
    {
        "id": "msc-smart-contract-auditing/audits-with-reasons",
        "split": "train",
        "columns": None,
        "max_rows": 5000,
        "description": "Audit findings paired with reasoning — mirrors Gate 1 hypothesis format",
        "priority": 3,
    },
    {
        "id": "GitmateAI/solidity_vulnerability_audit_dataset",
        "split": "train",
        "columns": None,
        "max_rows": 3000,
        "description": "Solidity snippets paired with expert audit findings",
        "priority": 4,
    },
    {
        "id": "seyyedaliayati/solidity-defi-vulnerabilities",
        "split": "train",
        "columns": None,
        "max_rows": 2000,
        "description": "DeFi-specific vulnerability scenarios (flash loans, oracle, price manipulation)",
        "priority": 5,
    },
    {
        "id": "msc-smart-contract-auditing/vulnerable-functions-base",
        "split": "train",
        "columns": None,
        "max_rows": 3000,
        "description": "Vulnerable functions with explanations from multiple audit firms",
        "priority": 6,
    },
    {
        "id": "mwritescode/slither-audited-smart-contracts",
        "split": "train",
        "columns": None,
        "max_rows": 1000,
        "description": "Etherscan-verified contracts labelled with Slither vulnerability classes",
        "priority": 7,
    },
    {
        "id": "forta/malicious-smart-contract-dataset",
        "split": "train",
        "columns": None,
        "max_rows": 2000,
        "description": "Malicious vs. benign Ethereum contracts for threat classification",
        "priority": 8,
    },
]


def _con(db_path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(db_path), check_same_thread=False, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")   # concurrent readers + one writer
    con.execute("PRAGMA synchronous=NORMAL") # fsync only on checkpoint, not every commit
    con.execute("PRAGMA cache_size=-65536")  # 64 MB page cache (M5 Max has 64 GB RAM)
    con.execute("""
        CREATE TABLE IF NOT EXISTS hf_samples (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            dataset_id  TEXT NOT NULL,
            row_index   INTEGER NOT NULL,
            data        TEXT NOT NULL,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_hf_dataset ON hf_samples(dataset_id)")
    con.commit()
    return con


class HuggingFaceFetcher:
    """Downloads and stores HF datasets into local SQLite training DB."""

    def __init__(self, db_path: Optional[str] = None):
        _TRAINING_DIR.mkdir(parents=True, exist_ok=True)
        _HF_CACHE.mkdir(parents=True, exist_ok=True)
        self._db_path = Path(db_path) if db_path else _TRAINING_DIR / "hf_training.db"
        self._con = _con(self._db_path)

    def fetch_all(
        self,
        priorities: Optional[list[int]] = None,
        force_refresh: bool = False,
        workers: int = 0,
    ) -> dict:
        """Fetch all configured datasets in parallel (M5 Max: uses 8 workers by default)."""
        import os
        from concurrent.futures import ThreadPoolExecutor, as_completed

        ds_list = _DATASETS
        if priorities:
            ds_list = [d for d in _DATASETS if d["priority"] in priorities]

        # M5 Max has 18 logical CPUs; HF downloads are I/O bound — 8 threads is sweet spot
        if workers <= 0:
            workers = min(8, os.cpu_count() or 4)

        results: dict = {}

        def _fetch(cfg):
            ds_id = cfg["id"]
            print(f"[HF] Fetching {ds_id} (priority={cfg['priority']})...")
            try:
                # Each thread needs its own connection (SQLite is not thread-safe by default)
                fetcher = HuggingFaceFetcher(db_path=str(self._db_path))
                result = fetcher._fetch_one(cfg, force_refresh)
                fetcher.close()
                print(f"[HF] ✓ {ds_id}: {result['rows_stored']} rows ({result['status']})")
                return ds_id, result
            except Exception as e:
                print(f"[HF] ✗ {ds_id}: {e}")
                return ds_id, {"status": "error", "error": str(e), "rows_stored": 0}

        print(f"[HF] Launching {len(ds_list)} datasets across {workers} parallel workers (M5 Max)")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_fetch, cfg): cfg for cfg in ds_list}
            for fut in as_completed(futures):
                ds_id, result = fut.result()
                results[ds_id] = result

        summary = {
            "datasets": results,
            "total_rows": sum(r.get("rows_stored", 0) for r in results.values()),
            "total_datasets": len(results),
            "workers_used": workers,
            "db_path": str(self._db_path),
        }
        _SUMMARY_PATH.write_text(json.dumps(summary, indent=2))
        return summary

    def _fetch_one(self, cfg: dict, force_refresh: bool) -> dict:
        import warnings
        warnings.filterwarnings("ignore")
        from datasets import load_dataset  # type: ignore

        ds_id = cfg["id"]
        max_rows = cfg["max_rows"]
        split = cfg.get("split", "train")

        # Check existing rows
        existing = self._con.execute(
            "SELECT COUNT(*) FROM hf_samples WHERE dataset_id=?", (ds_id,)
        ).fetchone()[0]

        if existing > 0 and not force_refresh:
            return {"status": "cached", "rows_stored": existing}

        if force_refresh and existing > 0:
            self._con.execute("DELETE FROM hf_samples WHERE dataset_id=?", (ds_id,))
            self._con.commit()

        try:
            ds = load_dataset(ds_id, split=split, trust_remote_code=False)
        except Exception:
            # Try without split specification
            ds = load_dataset(ds_id, trust_remote_code=False)
            if hasattr(ds, "keys"):
                first_split = list(ds.keys())[0]
                ds = ds[first_split]

        # Limit rows
        if len(ds) > max_rows:
            ds = ds.select(range(max_rows))

        # Insert rows
        rows = 0
        batch = []
        for i, row in enumerate(ds):
            batch.append((ds_id, i, json.dumps(row, default=str)))
            if len(batch) >= 200:
                self._con.executemany(
                    "INSERT INTO hf_samples (dataset_id, row_index, data) VALUES (?,?,?)",
                    batch,
                )
                self._con.commit()
                rows += len(batch)
                batch = []

        if batch:
            self._con.executemany(
                "INSERT INTO hf_samples (dataset_id, row_index, data) VALUES (?,?,?)",
                batch,
            )
            self._con.commit()
            rows += len(batch)

        return {"status": "fetched", "rows_stored": rows, "total_available": len(ds)}

    def search(self, query: str, dataset_id: Optional[str] = None, limit: int = 10) -> list[dict]:
        """Full-text search across stored HF samples."""
        q = f"%{query.lower()}%"
        if dataset_id:
            rows = self._con.execute(
                "SELECT dataset_id, row_index, data FROM hf_samples "
                "WHERE dataset_id=? AND lower(data) LIKE ? LIMIT ?",
                (dataset_id, q, limit),
            ).fetchall()
        else:
            rows = self._con.execute(
                "SELECT dataset_id, row_index, data FROM hf_samples "
                "WHERE lower(data) LIKE ? LIMIT ?",
                (q, limit),
            ).fetchall()
        return [
            {"dataset": r[0], "row": r[1], **json.loads(r[2])}
            for r in rows
        ]

    def stats(self) -> dict:
        """Return row counts per dataset."""
        rows = self._con.execute(
            "SELECT dataset_id, COUNT(*) FROM hf_samples GROUP BY dataset_id"
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    def close(self):
        self._con.close()
