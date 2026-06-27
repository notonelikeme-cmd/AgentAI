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
    ("MEV-002", "backrunning", "mev", "Medium",
     "Backrun liquidation or large swap for guaranteed profit",
     "Attacker monitors mempool, places trade immediately after large price-moving tx",
     "Lending protocol liquidations, large DEX swaps", "Generic", None),
    ("MEV-003", "jit_liquidity", "mev", "Medium",
     "Just-in-time liquidity provision captures fees then withdraws",
     "Attacker adds concentrated liquidity in same block as large swap, removes immediately after",
     "Uniswap V3 JIT — technically allowed but harmful to passive LPs", "AMM", None),

    # ── Frozen funds ──────────────────────────────────────────────────────
    ("FREEZE-001", "admin_key", "frozen_funds", "High",
     "Admin key controls all withdrawals; single point of failure",
     "Admin private key loss or compromise freezes all user funds permanently",
     "Multiple custodial DeFi protocols", "Generic", None),
    ("FREEZE-002", "griefing", "frozen_funds", "Medium",
     "Griefing attack forces withdrawal failure for specific users",
     "Attacker triggers revert in withdraw path; user cannot recover funds",
     "Pull-payment patterns with adversarial callbacks", "Generic", None),
    ("FREEZE-003", "callback_revert", "frozen_funds", "High",
     "Malicious token or callback always reverts, freezing accumulated rewards",
     "Protocol sends ETH/token to callback contract; attacker deploys contract that always reverts",
     "Push-based reward distribution patterns", "Generic", None),

    # ── EIP-1153 Transient Storage ────────────────────────────────────────
    ("TS-001", "transient_storage_leak", "eip1153", "Critical",
     "EIP-1153 TSTORE value readable by later tx in same block via parent cache delegation",
     "RepositoryImpl.commit() writes tx-scoped transient data to block-level repo; "
     "Tx2 reads Tx1 data via cache miss → parent delegation",
     "TRON DAO EVM — commitTransientStorage bug", "EVM", None),
    ("TS-002", "transient_lock_bypass", "eip1153", "High",
     "Reentrancy guard using TSTORE can be bypassed via delegatecall",
     "Lock written in context A; delegatecall to context B sees different transient slot",
     "Uniswap V4 hooks using transient reentrancy guards", "Uniswap V4", None),
    ("TS-003", "transient_persistence", "eip1153", "High",
     "Protocol assumes transient storage cleared between calls but clear happens at tx end",
     "Sub-call modifies transient slot; caller reads stale value within same tx",
     "Any protocol using TSTORE as temporary flag within single tx", "EVM", None),

    # ── Governance / Voting ───────────────────────────────────────────────
    ("GOV-001", "flash_loan_governance", "governance", "Critical",
     "Flash loan used to temporarily acquire voting power for malicious proposal",
     "Attacker borrows governance tokens, votes on proposal in same block, repays",
     "Build Finance, Beanstalk 2022 — $182M", "Governance", None),
    ("GOV-002", "timelock_bypass", "governance", "High",
     "Timelock delay insufficient or bypassable via parameter manipulation",
     "Proposal encodes multiple actions; one action changes delay to 0 before critical change",
     "Various governance contracts", "Governance", None),
    ("GOV-003", "proposal_frontrun", "governance", "Medium",
     "Attacker frontruns governance execution with state change that invalidates safety assumptions",
     "Governance executes upgrade; attacker frontruns with deposit that exploits new code before team expects",
     "Upgrade proposals with state dependencies", "Governance", None),
    ("GOV-004", "vote_buying", "governance", "Medium",
     "Attacker accumulates tokens cheaply via LP or borrow to pass malicious proposal",
     "Low-liquidity governance token; attacker acquires majority at low cost",
     "Small/illiquid governance tokens", "Governance", None),

    # ── Bridge / Cross-chain ──────────────────────────────────────────────
    ("BRIDGE-001", "signature_forgery", "bridge", "Critical",
     "Bridge validator signatures insufficient — threshold forgeable or colludable",
     "M-of-N multisig bridge; attacker compromises M validators to forge withdrawal",
     "Ronin Bridge 2022 — $625M; Wormhole 2022 — $325M", "Bridge", None),
    ("BRIDGE-002", "replay_cross_chain", "bridge", "Critical",
     "Message without chainId can be replayed on other chain after fork or deployment",
     "Same contract deployed on multiple chains; signed message valid on both",
     "Nomad bridge, various ERC20 permit implementations", "Bridge", None),
    ("BRIDGE-003", "double_spend", "bridge", "Critical",
     "Asset locked on source but mint not properly gated on destination",
     "Attacker submits same lock proof to destination twice before source updates",
     "Early bridge designs without proper nonce/receipt tracking", "Bridge", None),

    # ── Precision / Rounding ──────────────────────────────────────────────
    ("PREC-001", "division_rounding", "precision", "High",
     "Division rounds in attacker's favor, allowing extraction over many iterations",
     "share = assets / pricePerShare rounds down; attacker extracts 1 wei per call repeatedly",
     "Any protocol with division in token-to-share conversion", "ERC4626", None),
    ("PREC-002", "muldiv_overflow", "precision", "High",
     "mulDiv intermediate value overflows uint256 before division",
     "a * b overflows before / c even though a*b/c fits in uint256",
     "Uniswap V3 FullMath, any fixed-point arithmetic", "AMM", None),
    ("PREC-003", "dust_accumulation", "precision", "Medium",
     "Rounding dust accumulates in protocol, eventually becoming extractable",
     "Each operation leaves 1 wei; after N operations attacker can claim accumulated dust",
     "High-frequency protocols with many small operations", "Generic", None),
    ("PREC-004", "precision_loss_fee", "precision", "Medium",
     "Fee calculation precision loss allows fee-free transactions below threshold",
     "fee = amount * feeRate / FEE_DENOMINATOR; for small amounts fee rounds to 0",
     "Any fixed-rate fee on small amounts", "Generic", None),

    # ── Signature / Auth ──────────────────────────────────────────────────
    ("SIG-001", "signature_replay", "signature", "Critical",
     "Signed message replayable: lacks nonce, deadline, or chainId",
     "Attacker captures valid signature, resubmits after original operation completes",
     "ERC20 permit without deadline, off-chain order books", "Generic", None),
    ("SIG-002", "signature_malleability", "signature", "High",
     "ECDSA signature malleable: multiple valid (v,r,s) for same message",
     "ecrecover accepts both (v=27) and (v=28) forms; dedup by sig hash misses duplicates",
     "Pre-EIP-2 transactions, libraries not using OZ ECDSA", "Generic", None),
    ("SIG-003", "eip712_struct_hash", "signature", "High",
     "EIP-712 struct hash missing fields allows partial message forgery",
     "Signed struct omits critical field; attacker constructs different message with same hash",
     "Any EIP-712 implementation with incomplete struct encoding", "Generic", None),
    ("SIG-004", "permit_griefing", "signature", "Medium",
     "ERC20 permit front-run causes target transaction to revert",
     "Attacker frontruns permit call with same sig; nonce consumed; original tx reverts",
     "Any protocol using permit() without try/catch", "ERC20", None),

    # ── Lending / Borrow ──────────────────────────────────────────────────
    ("LEND-001", "interest_rate_manipulation", "lending", "High",
     "Utilization rate manipulation changes interest rate unfavorably for borrowers",
     "Attacker deposits large amount, reduces utilization, borrows at artificially low rate",
     "Compound-style utilization curves", "Lending", None),
    ("LEND-002", "collateral_factor_race", "lending", "High",
     "Governance changes collateral factor; attacker frontruns to borrow at old (higher) factor",
     "Transaction that lowers collateral factor; attacker borrows max before it executes",
     "Any lending protocol with governance-controlled risk parameters", "Lending", None),
    ("LEND-003", "liquidation_bonus_drain", "lending", "Medium",
     "Excessive liquidation bonus drains protocol reserves",
     "Bonus set too high; attacker creates position just below liquidation, self-liquidates repeatedly",
     "Any protocol where liquidation bonus > bad debt cost", "Lending", None),
    ("LEND-004", "borrow_cap_bypass", "lending", "Medium",
     "Borrow cap enforced at borrow time but not at interest accrual",
     "Position under cap when opened; interest accrual pushes it over cap but no revert",
     "Aave V3 borrow caps, similar implementations", "Lending", None),

    # ── Uniswap V4 / Hook-specific ────────────────────────────────────────
    ("HOOK-001", "hook_fee_bypass", "hook", "High",
     "Hook can override pool fee to 0, bypassing protocol fee",
     "beforeSwap hook modifies fee params; attacker-controlled hook drains LP fees",
     "Uniswap V4 dynamic fee hooks", "Uniswap V4", None),
    ("HOOK-002", "hook_reentrancy", "hook", "High",
     "Hook makes external call during PoolManager lock, re-entering pool state",
     "afterSwap hook calls external contract which re-enters pool before lock released",
     "Uniswap V4 hooks with external calls", "Uniswap V4", None),
    ("HOOK-003", "hook_selector_collision", "hook", "Critical",
     "Hook address encodes permissions; malicious hook claims more permissions than intended",
     "Hook address lower bits set to 1 for permissions; attacker deploys to address with extra bits set",
     "Uniswap V4 hook permission model", "Uniswap V4", None),
    ("HOOK-004", "delta_accumulation", "hook", "High",
     "Hook accumulates currency deltas without settling, leaving PoolManager insolvent",
     "Hook takes delta in beforeSwap but fails to settle in afterSwap; pool shortfall",
     "Uniswap V4 currency delta accounting", "Uniswap V4", None),

    # ── Vault / ERC4626 ───────────────────────────────────────────────────
    ("VAULT-001", "totalassets_manipulation", "vault", "High",
     "totalAssets() uses live balanceOf() — manipulable by direct token transfer",
     "Attacker sends tokens directly to vault; totalAssets inflates; share price rises; withdrawers profit",
     "Any vault using balanceOf(address(this)) in totalAssets()", "ERC4626", None),
    ("VAULT-002", "preview_mismatch", "vault", "Medium",
     "previewDeposit/previewWithdraw return values inconsistent with actual mint/withdraw",
     "Preview uses different rounding than actual; integrators receive fewer assets than expected",
     "ERC4626 non-compliant vault implementations", "ERC4626", None),
    ("VAULT-003", "yield_stripping", "vault", "High",
     "Attacker withdraws immediately after yield accrual, before other depositors can react",
     "Yield harvested in single tx; attacker deposits before harvest block, withdraws after",
     "Single-tx yield events in any vault", "ERC4626", None),
    ("VAULT-004", "conversion_rate_drift", "vault", "High",
     "Share/asset conversion rate drifts under extreme conditions causing unfair dilution",
     "Large loss event changes rate; late depositors subsidize early withdrawers",
     "Any vault with socialized losses", "ERC4626", None),

    # ── Integer / Arithmetic ──────────────────────────────────────────────
    ("INT-001", "unchecked_arithmetic", "integer", "High",
     "Unchecked block allows overflow/underflow in Solidity 0.8+",
     "Developer uses unchecked{} for gas savings; input validation missing; overflow exploitable",
     "Any unchecked arithmetic block without bounds validation", "Generic", None),
    ("INT-002", "type_casting_truncation", "integer", "High",
     "Unsafe downcast truncates value silently",
     "uint256 value cast to uint128/uint64 silently truncates high bits; accounting error",
     "Any unsafe type casting without bounds check", "Generic", None),
    ("INT-003", "timestamp_manipulation", "integer", "Medium",
     "Block timestamp manipulable by validator within ~12 second window",
     "Protocol uses block.timestamp for time-sensitive logic; validator shifts timestamp to advantage",
     "RANDAO, auction timing, rate snapshots", "Generic", None),

    # ── AMM-specific ──────────────────────────────────────────────────────
    ("AMM-001", "liquidity_removal_frontrun", "amm", "High",
     "Large liquidity removal frontrun causes swap to fail or execute at bad price",
     "Victim submits swap with slippage tolerance; attacker removes liquidity; swap reverts or loses value",
     "Any AMM where LP removal affects swap price", "AMM", None),
    ("AMM-002", "concentrated_liquidity_drain", "amm", "High",
     "Concentrated liquidity position set to drain fees via tick manipulation",
     "Attacker places liquidity at exact tick boundaries; manipulates price to sweep through range repeatedly",
     "Uniswap V3/V4 concentrated liquidity", "AMM", None),
    ("AMM-003", "invariant_break", "amm", "Critical",
     "AMM invariant (x*y=k or stable curve) violated after fee accounting",
     "Fee deducted before invariant check; post-fee state violates k; reserve drained",
     "Curve stable swap invariant bugs, generic AMM fee paths", "AMM", None),

    # ── Staking / Rewards ────────────────────────────────────────────────
    ("STK-001", "reward_per_token_overflow", "staking", "High",
     "rewardPerToken accumulator overflows after extended operation",
     "uint256 accumulator grows unbounded; overflow wraps around; reward claims miscalculated",
     "Synthetix staking, any per-token accumulator", "Staking", None),
    ("STK-002", "stake_frontrun_reward", "staking", "Medium",
     "Attacker deposits just before reward distribution, withdraws immediately after",
     "Reward snapshot taken at block N; attacker flash-stakes at N-1, claims full period reward at N+1",
     "Any staking protocol with snapshot-based rewards", "Staking", None),
    ("STK-003", "delegation_double_count", "staking", "High",
     "Vote or stake delegation double-counted when delegatee also delegates",
     "A delegates to B, B delegates to C; C's voting power includes A+B+C instead of just C",
     "Governance delegation chains", "Governance", None),
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
