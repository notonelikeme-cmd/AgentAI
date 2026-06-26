"""DeFiKnowledgeGraph — SQLite-backed pattern library for known DeFi attack classes.

Pre-seeded with patterns from public postmortems and audit reports.
Agents query this to generate hypotheses and check novelty.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

KG_PATH = Path.home() / "AgentAI" / ".claude" / "defi_kg.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS patterns (
    id          TEXT PRIMARY KEY,
    mechanism   TEXT NOT NULL,
    class       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    description TEXT NOT NULL,
    impact      TEXT NOT NULL,
    example     TEXT,
    protocol    TEXT,
    refs        TEXT
);

CREATE TABLE IF NOT EXISTS relationships (
    from_id TEXT NOT NULL,
    to_id   TEXT NOT NULL,
    rel     TEXT NOT NULL,
    PRIMARY KEY (from_id, to_id, rel)
);

CREATE INDEX IF NOT EXISTS idx_patterns_class     ON patterns(class);
CREATE INDEX IF NOT EXISTS idx_patterns_mechanism ON patterns(mechanism);
CREATE INDEX IF NOT EXISTS idx_patterns_severity  ON patterns(severity);
"""

_SEED_PATTERNS = [
    # ── Flash loan / Price manipulation ───────────────────────────────────
    ("FLA-001", "flash_loan", "price_manipulation", "Critical",
     "Flash loan price manipulation via single-block AMM spot price",
     "Attacker borrows, moves pool price, exploits protocol using inflated/deflated price, repays",
     "Mango Markets 2022 — $114M loss", "Generic", None),
    ("FLA-002", "flash_loan", "liquidity_drain", "Critical",
     "Flash loan used to drain liquidity pool via reentrancy",
     "Protocol state not locked during callback; attacker re-enters withdraw before balance update",
     "Cream Finance 2021 — $130M", "Compound-fork", None),

    # ── Share inflation / First deposit ──────────────────────────────────
    ("INFL-001", "share_inflation", "vault_accounting", "High",
     "First-depositor share inflation via direct token donation",
     "Attacker deposits 1 wei, donates large balance, subsequent depositors get 0 shares",
     "ERC4626 vault pattern; multiple incidents 2022-2023", "ERC4626", None),
    ("INFL-002", "share_inflation", "vault_accounting", "High",
     "Share rounding down to zero allows donation theft from depositors",
     "When totalSupply > 0 and totalAssets inflated, small deposits mint 0 shares",
     "Morpho vaults, Yearn forks", "ERC4626", None),

    # ── Reentrancy ────────────────────────────────────────────────────────
    ("RE-001", "reentrancy", "state_update", "Critical",
     "Classic reentrancy: external call before state update",
     "balance[msg.sender] not zeroed before transfer; attacker recursive-calls withdraw",
     "The DAO 2016", "Generic", None),
    ("RE-002", "reentrancy", "cross_function", "High",
     "Cross-function reentrancy via shared state",
     "Function A and B both read/write same storage; A calls external contract that re-enters B",
     "Uniswap V1 token-to-token swaps", "AMM", None),
    ("RE-003", "reentrancy", "read_only", "Medium",
     "Read-only reentrancy: view function returns stale state during callback",
     "Protocol B reads Protocol A's price/balance view during A's reentrancy window",
     "Curve / WETH reentrancy oracle reads 2022-2023", "Oracle", None),
    ("RE-004", "reentrancy", "transient_storage", "High",
     "EIP-1153 transient storage reentrancy guard can be bypassed cross-call",
     "tstore/tload guard cleared at end of transaction but not sub-call; hook re-enters before tload clears",
     "Uniswap V4 hooks with transient locks", "Uniswap V4", None),

    # ── Oracle manipulation ───────────────────────────────────────────────
    ("ORA-001", "oracle_manipulation", "spot_price", "Critical",
     "Spot price oracle: single-block manipulation via large swap",
     "AMM spot price used as oracle; manipulated in same block by flash loan before liquidation",
     "Harvest Finance 2020 — $34M", "AMM", None),
    ("ORA-002", "oracle_manipulation", "twap_short", "High",
     "TWAP oracle: too-short window allows multi-block manipulation",
     "30-minute TWAP manipulated over several blocks; attacker holds position across blocks",
     "Any protocol with TWAP < 30min on illiquid pools", "AMM", None),
    ("ORA-003", "oracle_manipulation", "stale_cache", "High",
     "Stale cached price: last updated timestamp not validated",
     "Cached oracle price used past freshness threshold; price drift exploited by attacker",
     "Chainlink staleness in illiquid markets", "Lending", None),

    # ── Proxy / Upgrade ───────────────────────────────────────────────────
    ("PRX-001", "storage_collision", "proxy", "Critical",
     "Storage slot collision between proxy admin and implementation",
     "Proxy stores admin at slot 0; implementation also uses slot 0 for owner; admin overwritten",
     "EIP-1967 motivation", "Proxy", None),
    ("PRX-002", "uninitialized_impl", "proxy", "Critical",
     "Uninitialized implementation contract can be self-destructed",
     "Implementation not initialized; attacker calls initialize(), then selfdestruct via delegatecall",
     "Parity multisig 2017", "Proxy", None),

    # ── Access control ────────────────────────────────────────────────────
    ("AC-001", "missing_access_control", "admin", "High",
     "Missing access control on privileged function",
     "Function lacks onlyOwner/onlyRole; anyone can call mint, setOwner, withdraw",
     "Misconfigured contracts, multiple incidents", "Generic", None),
    ("AC-002", "tx_origin", "authentication", "High",
     "tx.origin used for authentication",
     "Phishing contract makes victim call protocol; tx.origin == victim passes check",
     "Classic pattern", "Generic", None),

    # ── ERC20 edge cases ──────────────────────────────────────────────────
    ("ERC-001", "fee_on_transfer", "accounting", "Medium",
     "Fee-on-transfer token: received amount less than transferred amount",
     "Protocol records msg.value not actual received amount; internal accounting inflated",
     "Deflationary tokens in AMMs", "ERC20", None),
    ("ERC-002", "rebasing", "accounting", "Medium",
     "Rebasing token: balance changes without transfer",
     "Cached balance becomes stale after rebase; shares miscalculated",
     "stETH, aTokens in non-rebasing-aware protocols", "ERC20", None),
    ("ERC-003", "approval_front_run", "erc20", "Low",
     "ERC20 approve front-run: allowance race condition",
     "User changes allowance from N to M; attacker frontruns to spend N, then M",
     "Well-known, mostly mitigated by increaseAllowance", "ERC20", None),

    # ── Liquidation / Lending ─────────────────────────────────────────────
    ("LIQ-001", "bad_debt", "lending", "High",
     "Undercollateralized positions accrue bad debt without liquidation",
     "Price moves faster than liquidation; protocol left with bad debt no one will liquidate",
     "AAVE risk parameters, Euler Finance hack", "Lending", None),
    ("LIQ-002", "self_liquidation", "lending", "Medium",
     "Self-liquidation extracts value from protocol's liquidation bonus",
     "Attacker borrows, drops own collateral value, self-liquidates at bonus for profit",
     "Various lending protocols", "Lending", None),

    # ── MEV / Sandwiching ────────────────────────────────────────────────
    ("MEV-001", "sandwich", "mev", "Medium",
     "Sandwich attack: frontrun + backrun around victim swap",
     "Attacker places buy before victim, sell after; profits from victim's price impact",
     "Uniswap V2/V3, any AMM without slippage protection", "AMM", None),

    # ── Frozen funds ──────────────────────────────────────────────────────
    ("FREEZE-001", "admin_key", "frozen_funds", "High",
     "Admin key controls all withdrawals; single point of failure",
     "Admin private key loss or compromise freezes all user funds permanently",
     "Multiple custodial DeFi protocols", "Generic", None),
    ("FREEZE-002", "griefing", "frozen_funds", "Medium",
     "Griefing attack forces withdrawal failure for specific users",
     "Attacker triggers revert in withdraw path; user cannot recover funds",
     "Pull-payment patterns with adversarial callbacks", "Generic", None),
]


def _init_db(con: sqlite3.Connection):
    con.executescript(_SCHEMA)
    existing = {r[0] for r in con.execute("SELECT id FROM patterns").fetchall()}
    for row in _SEED_PATTERNS:
        if row[0] not in existing:
            con.execute(
                "INSERT INTO patterns VALUES (?,?,?,?,?,?,?,?,?)", row
            )
    con.commit()


class DeFiKnowledgeGraph:
    """Query interface for the DeFi attack pattern knowledge graph."""

    def __init__(self, db_path: Optional[str] = None):
        path = Path(db_path) if db_path else KG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(str(path))
        self._con.row_factory = sqlite3.Row
        _init_db(self._con)

    # ── Query API ─────────────────────────────────────────────────────────

    def retrieve(self, query: str) -> List[dict]:
        """Full-text search across description, mechanism, class, impact."""
        q = f"%{query.lower()}%"
        cur = self._con.execute(
            """SELECT * FROM patterns
               WHERE LOWER(description) LIKE ?
                  OR LOWER(mechanism) LIKE ?
                  OR LOWER(class) LIKE ?
                  OR LOWER(impact) LIKE ?
               ORDER BY severity ASC""",
            (q, q, q, q),
        )
        return [dict(r) for r in cur.fetchall()]

    def get_pattern(self, pattern_id: str) -> Optional[dict]:
        cur = self._con.execute("SELECT * FROM patterns WHERE id=?", (pattern_id,))
        r = cur.fetchone()
        return dict(r) if r else None

    def by_class(self, vuln_class: str) -> List[dict]:
        cur = self._con.execute(
            "SELECT * FROM patterns WHERE class=? ORDER BY severity",
            (vuln_class,),
        )
        return [dict(r) for r in cur.fetchall()]

    def by_severity(self, severity: str) -> List[dict]:
        cur = self._con.execute(
            "SELECT * FROM patterns WHERE severity=?", (severity,)
        )
        return [dict(r) for r in cur.fetchall()]

    def by_protocol(self, protocol: str) -> List[dict]:
        cur = self._con.execute(
            "SELECT * FROM patterns WHERE protocol LIKE ?",
            (f"%{protocol}%",),
        )
        return [dict(r) for r in cur.fetchall()]

    def list_patterns(self) -> List[str]:
        cur = self._con.execute("SELECT id, mechanism, class, severity FROM patterns ORDER BY severity")
        return [f"{r['id']}: [{r['severity']}] {r['mechanism']} / {r['class']}" for r in cur.fetchall()]

    def hypotheses_for_pattern(self, pattern_id: str) -> List[str]:
        """Generate Gate 1-formatted hypothesis templates for a pattern."""
        p = self.get_pattern(pattern_id)
        if not p:
            return []
        return [
            f"IF {p['mechanism']} vulnerability exists in <TARGET> "
            f"THEN attacker can {p['impact']} "
            f"BECAUSE {p['description']} — see <CONTRACT>.sol:<LINE>",
        ]

    def add_pattern(
        self, id: str, mechanism: str, vuln_class: str, severity: str,
        description: str, impact: str, example: str = "", protocol: str = "",
        refs: str = "",
    ) -> str:
        self._con.execute(
            "INSERT OR REPLACE INTO patterns VALUES (?,?,?,?,?,?,?,?,?)",
            (id, mechanism, vuln_class, severity, description, impact,
             example, protocol, refs),
        )
        self._con.commit()
        return id

    def close(self):
        self._con.close()
