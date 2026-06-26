"""SkillBuilder — converts verified findings into reusable KG patterns and memory.

Every VERIFIED finding is a training signal. This module:
  1. Extracts the abstract pattern (name, preconditions, code signatures)
  2. Seeds defi_kg.py with the new pattern so future audits detect it automatically
  3. Writes findings_log.md and agent_index hints to ~/AgentAI/memory/
  4. Generates detection regexes calibrated to the specific failure mode
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

_MEMORY_DIR = Path.home() / "AgentAI" / "memory"


def _write_memory(filename: str, content: str):
    _MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    path = _MEMORY_DIR / filename
    with open(path, "a") as f:
        f.write(content)


def _infer_regexes_from_mechanism(mechanism: str, description: str) -> list[str]:
    """Generate Solidity detection regexes from mechanism + description keywords."""
    base: dict[str, list[str]] = {
        "reentrancy":         [r"\.call\{", r"transfer\(", r"send\(", r"withdraw"],
        "flash_loan":         [r"flashLoan", r"executeOperation", r"uniswapV3Flash"],
        "oracle_manipulation":[r"slot0\(", r"getAmountOut", r"sqrtPriceX96"],
        "access_control":     [r"onlyOwner", r"require\(msg\.sender", r"tx\.origin"],
        "storage_collision":  [r"delegatecall", r"_implementation", r"upgradeToAndCall"],
        "price_manipulation": [r"balanceOf\(address\(this\)\)", r"reserve0", r"totalAssets"],
        "inflation":          [r"convertToShares", r"previewDeposit", r"totalSupply\(\)"],
        "signature_replay":   [r"ecrecover", r"ECDSA\.recover", r"permit\("],
        "unchecked_math":     [r"unchecked\s*\{", r"\+\+\s*\w", r"--\s*\w"],
        "frozen_funds":       [r"selfdestruct", r"require\(.*admin", r"onlyEmergency"],
    }
    patterns = list(base.get(mechanism, []))

    # Extract additional patterns from description words
    desc_words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]{4,}\b', description)
    for word in desc_words:
        if any(c.isupper() for c in word[1:]):  # camelCase → likely a Solidity identifier
            patterns.append(re.escape(word))

    return list(dict.fromkeys(patterns))[:6]  # dedupe, max 6


class SkillBuilder:
    """Extracts reusable patterns from verified findings and seeds the knowledge graph."""

    def __init__(self, kg_db_path: Optional[str] = None, router=None):
        from core.analysis.defi_kg import DeFiKnowledgeGraph
        self._kg = DeFiKnowledgeGraph(db_path=kg_db_path)
        self._router = router

    def process_verified_finding(self, finding: dict, gate_data: dict) -> dict:
        """
        Called after all gates pass. Extracts pattern, seeds KG, writes memory.

        Args:
            finding: dict with keys: title, hypothesis, mechanism, severity, contract,
                     net_profit, citations, reproduction_guide
            gate_data: full gate pipeline state dict

        Returns:
            dict with keys: pattern_id, pattern_registered, memory_written, regexes
        """
        hypothesis = finding.get("hypothesis", "")
        mechanism  = finding.get("mechanism", self._infer_mechanism(hypothesis))
        severity   = finding.get("severity", "High")
        protocol   = finding.get("protocol", self._infer_protocol(gate_data))
        title      = finding.get("title", f"{mechanism} in {protocol}")
        net_profit = finding.get("net_profit", 0)

        # Generate pattern ID
        prefix = self._mechanism_prefix(mechanism)
        existing = self._kg._con.execute(
            "SELECT id FROM patterns WHERE id LIKE ? ORDER BY id DESC LIMIT 1",
            (f"{prefix}-%",),
        ).fetchone()
        if existing:
            last_num = int(existing[0].split("-")[-1])
            pattern_id = f"{prefix}-{last_num + 1:03d}"
        else:
            pattern_id = f"{prefix}-901"  # learned patterns start at 901

        # Extract description + impact from hypothesis
        description = self._extract_because(hypothesis) or title
        impact_text = self._extract_then(hypothesis) or finding.get("impact", "funds drained")

        # Generate detection regexes
        regexes = _infer_regexes_from_mechanism(mechanism, description)

        # Use ModelRouter to enrich description if available
        enriched_description = description
        if self._router:
            try:
                prompt = (
                    f"In one sentence, state the abstract vulnerability pattern "
                    f"(not the specific protocol) from this finding:\n{hypothesis}"
                )
                enriched_description = self._router.complete(prompt, gate=1).strip()
            except Exception:
                pass

        # Register pattern in KG
        self._kg.add_pattern(
            id=pattern_id,
            mechanism=mechanism,
            vuln_class=self._mechanism_class(mechanism),
            severity=severity,
            description=enriched_description,
            impact=impact_text,
            protocol=protocol,
            example=f"{protocol} — ${net_profit:,.0f} potential" if net_profit else protocol,
            refs=json.dumps(regexes),
        )
        self._kg._con.execute(
            "INSERT OR IGNORE INTO patterns (id, mechanism, class, severity, description, "
            "impact, protocol, example, refs) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO NOTHING",
            (pattern_id, mechanism, self._mechanism_class(mechanism), severity,
             enriched_description, impact_text, protocol,
             f"{protocol} — ${net_profit:,.0f}" if net_profit else protocol,
             json.dumps(regexes)),
        )

        # Write to memory
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        _write_memory("findings_log.md", f"""
## [{date_str}] {title}
- **Pattern**: {pattern_id} — {mechanism}/{self._mechanism_class(mechanism)}
- **Severity**: {severity}
- **Protocol**: {protocol}
- **Net profit**: ${net_profit:,.0f}
- **KG entry**: added `{pattern_id}` with {len(regexes)} detection regexes
- **Hypothesis**: {hypothesis[:200]}
- **Regexes**: {regexes}

""")

        return {
            "pattern_id": pattern_id,
            "pattern_registered": True,
            "description": enriched_description,
            "regexes": regexes,
            "memory_written": True,
        }

    def log_blocked_pattern(self, hypothesis: str, gate: int, reason: str, mechanism: str = ""):
        """Record a gate block to blocked_patterns.md for negative training data."""
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        _write_memory("blocked_patterns.md", f"""
## [{date_str}] Blocked at Gate {gate}
- **Mechanism**: {mechanism or self._infer_mechanism(hypothesis)}
- **Gate**: {gate} — {reason}
- **Hypothesis**: {hypothesis[:200]}
- **Action**: pattern suppressed from future scoring until root cause resolved

""")

    def log_false_positive(self, hypothesis: str, reason: str, kill_rule: str = ""):
        """Record a rejected finding to false_positive_log.md."""
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        _write_memory("false_positive_log.md", f"""
## [{date_str}] False Positive Caught
- **Kill rule**: {kill_rule or 'peer review'}
- **Reason**: {reason}
- **Hypothesis**: {hypothesis[:200]}

""")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _infer_mechanism(self, hypothesis: str) -> str:
        h = hypothesis.lower()
        for mech in ["reentrancy", "flash_loan", "oracle", "access_control",
                     "storage_collision", "inflation", "signature_replay",
                     "price_manipulation", "frozen_funds", "unchecked_math"]:
            if mech.replace("_", " ") in h or mech in h:
                return mech
        return "unknown"

    def _infer_protocol(self, gate_data: dict) -> str:
        contract = gate_data.get("contract", "")
        if contract:
            return Path(contract).stem
        return "unknown"

    def _extract_because(self, hypothesis: str) -> str:
        m = re.search(r"because\s+(.+?)(?:\s*—|\s*$)", hypothesis, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    def _extract_then(self, hypothesis: str) -> str:
        m = re.search(r"then\s+(.+?)\s+because", hypothesis, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    def _mechanism_prefix(self, mechanism: str) -> str:
        mapping = {
            "reentrancy": "RE", "flash_loan": "FLA", "oracle_manipulation": "ORA",
            "price_manipulation": "ORA", "access_control": "AC",
            "storage_collision": "PRX", "inflation": "ERC", "donation": "ERC",
            "signature_replay": "SIG", "frozen_funds": "FRZ", "unchecked_math": "MATH",
        }
        return mapping.get(mechanism, "GEN")

    def _mechanism_class(self, mechanism: str) -> str:
        mapping = {
            "reentrancy": "state_update", "flash_loan": "price_manipulation",
            "oracle_manipulation": "spot_price", "price_manipulation": "spot_price",
            "access_control": "admin", "storage_collision": "proxy",
            "inflation": "share_accounting", "donation": "conservation",
            "signature_replay": "auth", "frozen_funds": "locked_funds",
            "unchecked_math": "arithmetic",
        }
        return mapping.get(mechanism, "generic")

    def close(self):
        self._kg.close()
