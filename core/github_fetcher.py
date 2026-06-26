"""GitHubFetcher — pulls real DeFi incident data from DeFiHackLabs.

Sources:
  - SunWeb3Sec/DeFiHackLabs  (740+ Foundry PoC files, primary source)
  - Parses @KeyInfo comments for metadata, code for attack class
  - Seeds defi_kg.db incidents table + enriches patterns

Usage:
    from core.github_fetcher import GitHubFetcher
    f = GitHubFetcher()
    f.fetch(max_incidents=200)   # fetches + seeds KG
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

DEFIHACKLABS_TREE = (
    "https://api.github.com/repos/SunWeb3Sec/DeFiHackLabs/git/trees/main?recursive=1"
)
DEFIHACKLABS_RAW = (
    "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/{path}"
)
DEFIHACKLABS_README = (
    "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/README.md"
)

_DEFAULT_CACHE = Path.home() / "AgentAI" / "training_data"

# ── Attack class detection patterns (order matters: most specific first) ──────
_CLASS_SIGNALS: list[tuple[str, str, list[str]]] = [
    # (mechanism, class, keywords_in_source)
    ("storage_collision",  "proxy",            ["delegatecall", "implementation()", "upgradeToAndCall"]),
    ("signature_replay",   "authentication",   ["ecrecover", "ECDSA.recover", "replay", "nonce"]),
    ("price_manipulation", "spot_price",       ["slot0()", "sqrtPriceX96", "getAmountOut", "reserve0", "reserve1"]),
    ("oracle_manipulation","twap_short",       ["observe(", "TWAP", "twap", "timeWeighted"]),
    ("flash_loan",         "liquidity_drain",  ["flashLoan", "executeOperation", "uniswapV3FlashCallback", "pancakeCall"]),
    ("reentrancy",         "state_update",     ["receive()", "fallback()", "call{value", ".call("]),
    ("access_control",     "missing_check",    ["onlyOwner", "tx.origin", "require(msg.sender"]),
    ("share_inflation",    "vault_accounting", ["totalSupply()", "convertToShares", "previewDeposit", "totalAssets()"]),
    ("fee_on_transfer",    "accounting",       ["balanceBefore", "balanceAfter", "fee_on_transfer"]),
    ("integer_overflow",   "arithmetic",       ["unchecked {", "SafeMath", "overflow"]),
    ("business_logic",     "logic_flaw",       ["testExploit", "exploit"]),  # fallback
]

_CHAIN_RE = re.compile(r'vm\.createSelectFork\s*\(\s*["\'](\w+)["\']', re.IGNORECASE)
_BLOCK_RE = re.compile(r'vm\.createSelectFork\s*\([^,]+,\s*(\d[\d_]*)', re.IGNORECASE)
_LOST_RE  = re.compile(r'Total Lost\s*[:\-~]+\s*\$?([\d,.]+\s*[KMB]?)', re.IGNORECASE)
_TX_RE    = re.compile(r'Attack Tx\s*:\s*(https?://\S+)', re.IGNORECASE)
_ATTACKER_RE = re.compile(r'Attacker\s*:\s*(https?://\S+)', re.IGNORECASE)


@dataclass
class Incident:
    id: str             # e.g. "20240115-RadiantCapital"
    protocol: str
    date: str           # YYYYMMDD
    year: str
    mechanism: str
    vuln_class: str
    severity: str       # inferred from loss
    total_lost_usd: float
    chain: str
    block_number: int
    attack_tx: str
    attacker: str
    poc_path: str       # path in DeFiHackLabs repo
    source_snippet: str  # first 500 chars of PoC
    analysis: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "protocol": self.protocol,
            "date": self.date,
            "mechanism": self.mechanism,
            "vuln_class": self.vuln_class,
            "severity": self.severity,
            "total_lost_usd": self.total_lost_usd,
            "chain": self.chain,
            "block_number": self.block_number,
            "attack_tx": self.attack_tx,
            "poc_path": self.poc_path,
        }


def _infer_severity(lost_usd: float) -> str:
    if lost_usd >= 10_000_000:
        return "Critical"
    if lost_usd >= 1_000_000:
        return "High"
    if lost_usd >= 100_000:
        return "Medium"
    return "Low"


def _parse_lost(text: str) -> float:
    m = _LOST_RE.search(text)
    if not m:
        return 0.0
    raw = m.group(1).replace(",", "").replace(" ", "").upper()
    mult = 1.0
    if raw.endswith("K"):
        mult, raw = 1_000, raw[:-1]
    elif raw.endswith("M"):
        mult, raw = 1_000_000, raw[:-1]
    elif raw.endswith("B"):
        mult, raw = 1_000_000_000, raw[:-1]
    try:
        return float(raw) * mult
    except ValueError:
        return 0.0


def _classify_attack(source: str) -> tuple[str, str]:
    src_lower = source.lower()
    for mechanism, vuln_class, keywords in _CLASS_SIGNALS:
        if any(kw.lower() in src_lower for kw in keywords):
            return mechanism, vuln_class
    return "business_logic", "logic_flaw"


def _parse_poc(path: str, source: str) -> dict:
    protocol = re.sub(r"_exp\.sol$", "", Path(path).name, flags=re.IGNORECASE)
    # Extract date from path: src/test/2024-01/Name_exp.sol → 2024-01
    date_match = re.search(r"/(\d{4}-\d{2})/", path)
    date_str = date_match.group(1).replace("-", "") if date_match else "000000"
    year = date_str[:4]

    chain_m = _CHAIN_RE.search(source)
    block_m = _BLOCK_RE.search(source)
    tx_m    = _TX_RE.search(source)
    att_m   = _ATTACKER_RE.search(source)

    chain = chain_m.group(1) if chain_m else "mainnet"
    block = int(block_m.group(1).replace("_", "")) if block_m else 0
    lost  = _parse_lost(source)
    mechanism, vuln_class = _classify_attack(source)

    analysis_urls = re.findall(r"https?://\S+", source[:2000])

    return {
        "id":             f"{date_str}-{protocol}",
        "protocol":       protocol,
        "date":           date_str,
        "year":           year,
        "mechanism":      mechanism,
        "vuln_class":     vuln_class,
        "severity":       _infer_severity(lost),
        "total_lost_usd": lost,
        "chain":          chain,
        "block_number":   block,
        "attack_tx":      tx_m.group(1) if tx_m else "",
        "attacker":       att_m.group(1) if att_m else "",
        "poc_path":       path,
        "source_snippet": source[:500],
        "analysis":       analysis_urls[:5],
    }


def _fetch_url(url: str, retries: int = 3, backoff: float = 2.0) -> Optional[str]:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "trinity-fetcher/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = backoff ** (attempt + 1)
                print(f"    Rate limited, waiting {wait:.0f}s...")
                time.sleep(wait)
            elif e.code == 404:
                return None
            else:
                time.sleep(backoff)
        except Exception:
            time.sleep(backoff)
    return None


class GitHubFetcher:
    """Fetches and parses DeFiHackLabs PoC files, seeds defi_kg.db."""

    def __init__(self, cache_dir: Optional[str] = None, db_path: Optional[str] = None):
        self._cache = Path(cache_dir) if cache_dir else _DEFAULT_CACHE
        self._cache.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._stats = {"fetched": 0, "parsed": 0, "seeded": 0, "errors": 0, "cached": 0}

    # ── Public API ──────────────────────────────────────────────────────────

    def fetch(
        self,
        max_incidents: int = 200,
        years: Optional[list[str]] = None,
        mechanisms: Optional[list[str]] = None,
        force_refresh: bool = False,
        delay: float = 0.3,
    ) -> dict:
        """Main entry point. Downloads PoCs, parses them, seeds the KG.

        Args:
            max_incidents:  Max PoC files to process (GitHub rate limit: 60/hr unauth).
            years:          Filter to specific years e.g. ["2024", "2025", "2026"].
            mechanisms:     Filter by mechanism e.g. ["flash_loan", "reentrancy"].
            force_refresh:  Re-download even if cached locally.
            delay:          Seconds between GitHub requests (stay under rate limit).
        """
        print(f"[Fetcher] Getting PoC file list from DeFiHackLabs...")
        all_paths = self._list_poc_paths()
        if not all_paths:
            return {"error": "Failed to fetch file list from GitHub"}

        # Filter by year
        if years:
            all_paths = [p for p in all_paths if any(f"/test/{y}" in p for y in years)]

        # Prioritise recent years (most relevant for current audits)
        all_paths.sort(reverse=True)
        all_paths = all_paths[:max_incidents]

        print(f"[Fetcher] Processing {len(all_paths)} PoC files...")

        incidents: list[dict] = []
        for i, path in enumerate(all_paths, 1):
            try:
                source = self._get_poc_source(path, force_refresh, delay)
                if not source:
                    self._stats["errors"] += 1
                    continue

                parsed = _parse_poc(path, source)

                # Filter by mechanism after parsing
                if mechanisms and parsed["mechanism"] not in mechanisms:
                    continue

                incidents.append(parsed)
                self._stats["parsed"] += 1

                if i % 25 == 0:
                    print(f"  [{i}/{len(all_paths)}] {parsed['protocol']} — {parsed['mechanism']} (${parsed['total_lost_usd']:,.0f})")

            except Exception as e:
                self._stats["errors"] += 1
                print(f"  [!] Error on {path}: {e}")

        # Save parsed incidents as JSON
        incidents_file = self._cache / "incidents.json"
        with open(incidents_file, "w") as f:
            json.dump(incidents, f, indent=2)
        print(f"\n[Fetcher] Saved {len(incidents)} incidents to {incidents_file}")

        # Seed the KG
        seeded = self._seed_kg(incidents)
        self._stats["seeded"] = seeded

        self._print_summary(incidents)
        return {
            "incidents_fetched": len(incidents),
            "seeded_to_kg": seeded,
            "stats": self._stats,
            "cache": str(incidents_file),
        }

    def load_cached(self) -> list[dict]:
        """Load previously fetched incidents from cache."""
        incidents_file = self._cache / "incidents.json"
        if not incidents_file.exists():
            return []
        with open(incidents_file) as f:
            return json.load(f)

    def fetch_readme_incidents(self) -> list[dict]:
        """Fast parse: extract incident list from README without downloading PoCs."""
        print("[Fetcher] Parsing DeFiHackLabs README...")
        text = _fetch_url(DEFIHACKLABS_README)
        if not text:
            return []

        # Parse lines like: [20260624 DLMC](#... ---attack-type)
        pattern = re.compile(
            r'\[(\d{8})\s+([\w\s]+?)\]\(#[\w-]+-+([^)]+)\)', re.IGNORECASE
        )
        incidents = []
        for m in pattern.finditer(text):
            date_str, protocol, attack_slug = m.group(1), m.group(2).strip(), m.group(3).strip()
            attack_type = attack_slug.replace("-", " ").strip()
            incidents.append({
                "date": date_str,
                "protocol": protocol,
                "attack_type": attack_type,
                "year": date_str[:4],
            })

        print(f"[Fetcher] Parsed {len(incidents)} incidents from README")
        return incidents

    # ── Internal ────────────────────────────────────────────────────────────

    def _list_poc_paths(self) -> list[str]:
        cached_list = self._cache / "poc_paths.json"
        if cached_list.exists():
            age = time.time() - cached_list.stat().st_mtime
            if age < 86400:  # 24h cache
                with open(cached_list) as f:
                    return json.load(f)

        data = _fetch_url(DEFIHACKLABS_TREE)
        if not data:
            return []

        tree = json.loads(data)
        paths = [
            i["path"]
            for i in tree.get("tree", [])
            if i["path"].startswith("src/test/") and i["path"].endswith("_exp.sol")
        ]

        with open(cached_list, "w") as f:
            json.dump(paths, f)

        self._stats["fetched"] = len(paths)
        return paths

    def _get_poc_source(self, path: str, force: bool, delay: float) -> Optional[str]:
        local = self._cache / "pocs" / path.replace("/", "_")
        local.parent.mkdir(parents=True, exist_ok=True)

        if local.exists() and not force:
            self._stats["cached"] += 1
            return local.read_text(errors="replace")

        url = DEFIHACKLABS_RAW.format(path=path)
        time.sleep(delay)  # rate limit courtesy
        source = _fetch_url(url)
        if source:
            local.write_text(source)
            self._stats["fetched"] = self._stats.get("fetched", 0) + 1
        return source

    def _seed_kg(self, incidents: list[dict]) -> int:
        from core.analysis.defi_kg import DeFiKnowledgeGraph
        kg = DeFiKnowledgeGraph(db_path=self._db_path)

        # Ensure incidents table exists
        kg._con.executescript("""
            CREATE TABLE IF NOT EXISTS incidents (
                id              TEXT PRIMARY KEY,
                protocol        TEXT NOT NULL,
                date            TEXT,
                year            TEXT,
                mechanism       TEXT,
                vuln_class      TEXT,
                severity        TEXT,
                total_lost_usd  REAL,
                chain           TEXT,
                block_number    INTEGER,
                attack_tx       TEXT,
                attacker        TEXT,
                poc_path        TEXT,
                source_snippet  TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_mechanism ON incidents(mechanism);
            CREATE INDEX IF NOT EXISTS idx_incidents_year ON incidents(year);
            CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
        """)
        kg._con.commit()

        seeded = 0
        for inc in incidents:
            try:
                kg._con.execute("""
                    INSERT OR REPLACE INTO incidents
                    (id, protocol, date, year, mechanism, vuln_class, severity,
                     total_lost_usd, chain, block_number, attack_tx, attacker,
                     poc_path, source_snippet)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    inc["id"], inc["protocol"], inc["date"], inc["year"],
                    inc["mechanism"], inc["vuln_class"], inc["severity"],
                    inc["total_lost_usd"], inc["chain"], inc["block_number"],
                    inc["attack_tx"], inc["attacker"], inc["poc_path"],
                    inc["source_snippet"],
                ))
                seeded += 1

                # Also upsert matching KG pattern if new mechanism seen
                existing = kg.get_pattern(f"REAL-{inc['mechanism'].upper()[:10]}")
                if not existing and inc["total_lost_usd"] > 0:
                    kg.add_pattern(
                        id=f"REAL-{inc['mechanism'].upper()[:10]}",
                        mechanism=inc["mechanism"],
                        vuln_class=inc["vuln_class"],
                        severity=inc["severity"],
                        description=f"Real-world: {inc['protocol']} — {inc['mechanism']}",
                        impact=f"${inc['total_lost_usd']:,.0f} lost",
                        example=f"{inc['protocol']} {inc['date']}",
                        protocol=inc["chain"],
                        refs=inc["attack_tx"],
                    )

            except Exception:
                pass

        kg._con.commit()
        kg.close()
        return seeded

    def _print_summary(self, incidents: list[dict]):
        by_mech: dict[str, int] = {}
        by_year: dict[str, int] = {}
        total_lost = 0.0
        for inc in incidents:
            by_mech[inc["mechanism"]] = by_mech.get(inc["mechanism"], 0) + 1
            by_year[inc["year"]] = by_year.get(inc["year"], 0) + 1
            total_lost += inc["total_lost_usd"]

        print(f"\n{'='*55}")
        print(f"  Training Data Summary")
        print(f"{'='*55}")
        print(f"  Total incidents:  {len(incidents)}")
        print(f"  Total lost (USD): ${total_lost:,.0f}")
        print(f"\n  By mechanism:")
        for mech, count in sorted(by_mech.items(), key=lambda x: -x[1]):
            print(f"    {mech:<28} {count:>4}")
        print(f"\n  By year:")
        for year, count in sorted(by_year.items()):
            print(f"    {year}  {count:>4}")
        print(f"{'='*55}")
