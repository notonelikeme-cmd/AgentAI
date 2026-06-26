"""SolidityAnalyzer — pattern-based vulnerability detection in Solidity source."""
import re
from pathlib import Path
from typing import List, Dict, Any


PATTERNS = [
    # Reentrancy
    {
        "id": "REENTRANT_TRANSFER_BEFORE_UPDATE",
        "type": "reentrancy",
        "severity": "High",
        "regex": r"(transfer|transferFrom|\.call\{[^}]*\})\s*\([^;]+\);\s*\n(?:[^;]*\n){0,5}[^;]*(balance|amount|total)",
        "description": "External call before state update — potential reentrancy",
        "advice": "Apply Checks-Effects-Interactions: update state before external calls",
    },
    # Missing access control
    {
        "id": "MISSING_ACCESS_CONTROL",
        "type": "access_control",
        "severity": "High",
        "regex": r"function\s+\w+\([^)]*\)\s+(?:public|external)\s+(?!view|pure|returns)(?!.*(?:onlyOwner|onlyRole|require\s*\([^)]*msg\.sender))",
        "description": "State-changing public/external function without access control",
        "advice": "Add onlyOwner, onlyRole, or require(msg.sender == ...) check",
    },
    # Unchecked arithmetic
    {
        "id": "UNCHECKED_ARITHMETIC",
        "type": "arithmetic",
        "severity": "Medium",
        "regex": r"unchecked\s*\{[^}]*[+\-\*][^}]*\}",
        "description": "Unchecked arithmetic block — overflow/underflow not protected",
        "advice": "Verify all arithmetic in unchecked blocks cannot overflow",
    },
    # Direct balanceOf (donatable)
    {
        "id": "DIRECT_BALANCE_OF",
        "type": "conservation",
        "severity": "Medium",
        "regex": r"\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
        "description": "Direct balanceOf(address(this)) read — vulnerable to donation attacks",
        "advice": "Cache balance changes via transfer accounting instead of reading balanceOf",
    },
    # No return value check on transfer
    {
        "id": "UNCHECKED_TRANSFER",
        "type": "erc20",
        "severity": "Medium",
        "regex": r"(?<!\.)(?:IERC20|ERC20)\(\w+\)\.transfer(?:From)?\s*\(",
        "description": "ERC20 transfer without SafeERC20 — some tokens don't return bool",
        "advice": "Use SafeERC20.safeTransfer / safeTransferFrom",
    },
    # Selfdestruct
    {
        "id": "SELFDESTRUCT",
        "type": "critical",
        "severity": "Critical",
        "regex": r"\bselfdestruct\b",
        "description": "selfdestruct present — can permanently destroy contract and funds",
        "advice": "Remove selfdestruct or gate behind multisig + timelock",
    },
    # tx.origin auth
    {
        "id": "TX_ORIGIN_AUTH",
        "type": "access_control",
        "severity": "High",
        "regex": r"require\s*\(\s*tx\.origin\s*==",
        "description": "tx.origin used for authentication — bypassed by phishing contracts",
        "advice": "Use msg.sender instead of tx.origin for authentication",
    },
    # Block.timestamp dependence
    {
        "id": "BLOCK_TIMESTAMP",
        "type": "timing",
        "severity": "Low",
        "regex": r"block\.timestamp\s*[<>=!]",
        "description": "block.timestamp comparison — miners can manipulate ±900s",
        "advice": "Don't use block.timestamp for critical comparisons with tight tolerances",
    },
    # Floating pragma
    {
        "id": "FLOATING_PRAGMA",
        "type": "best_practice",
        "severity": "Info",
        "regex": r"pragma\s+solidity\s+\^",
        "description": "Floating pragma — contract compiled with any compatible version",
        "advice": "Pin exact compiler version: pragma solidity 0.8.X;",
    },
]


class SolidityAnalyzer:
    def __init__(self):
        self._compiled = [(p, re.compile(p["regex"], re.MULTILINE | re.DOTALL)) for p in PATTERNS]

    def scan_file(self, path: Path) -> List[Dict[str, Any]]:
        source = path.read_text(errors="replace")
        findings = []
        for pattern, regex in self._compiled:
            for m in regex.finditer(source):
                line = source[:m.start()].count("\n") + 1
                findings.append({
                    "id": pattern["id"],
                    "type": pattern["type"],
                    "severity": pattern["severity"],
                    "location": f"{path}:{line}",
                    "description": pattern["description"],
                    "advice": pattern["advice"],
                    "snippet": source[m.start():m.start() + 100].strip(),
                })
        return findings

    def scan(self, path_str: str) -> List[Dict[str, Any]]:
        path = Path(path_str)
        findings = []
        if path.is_file():
            findings.extend(self.scan_file(path))
        elif path.is_dir():
            for sol_file in path.rglob("*.sol"):
                if any(skip in str(sol_file) for skip in ["node_modules", ".venv", "lib/openzeppelin"]):
                    continue
                findings.extend(self.scan_file(sol_file))
        return sorted(findings, key=lambda f: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(f["severity"], 5))
