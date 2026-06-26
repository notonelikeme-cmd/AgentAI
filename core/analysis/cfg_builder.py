"""CFGBuilder — lightweight Solidity control-flow and call graph extractor.

Operates purely on source text (no compiler required). Extracts:
- Function signatures and visibility
- Internal / external call edges
- State variable reads/writes per function
- Modifiers applied
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


# ── Regex patterns ────────────────────────────────────────────────────────────

_RE_CONTRACT = re.compile(
    r"(?:contract|interface|library|abstract\s+contract)\s+(\w+)"
    r"(?:\s+is\s+([\w\s,]+?))?\s*\{",
    re.MULTILINE,
)

_RE_FUNCTION = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s*((?:public|private|internal|external"
    r"|view|pure|payable|virtual|override|\w+\s*)*)\s*(?:returns\s*\([^)]*\))?\s*[{;]",
    re.MULTILINE,
)

_RE_MODIFIER = re.compile(r"modifier\s+(\w+)\s*\(", re.MULTILINE)

_RE_CALL = re.compile(
    r"(\w+)\.(\w+)\s*\(|(\w+)\s*\(",
    re.MULTILINE,
)

_RE_STATE_VAR = re.compile(
    r"^\s*(uint\d*|int\d*|address|bool|bytes\d*|string|mapping|[A-Z]\w+)\s+"
    r"(?:public\s+|private\s+|internal\s+)?(\w+)\s*[=;]",
    re.MULTILINE,
)

_RE_EMIT = re.compile(r"\bemit\s+(\w+)\s*\(", re.MULTILINE)

_SOLIDITY_KEYWORDS = frozenset({
    "if", "else", "for", "while", "do", "return", "require", "revert",
    "assert", "emit", "delete", "new", "try", "catch", "assembly",
    "uint256", "uint128", "address", "bool", "bytes32", "string",
    "msg", "block", "tx", "abi", "super", "this",
})


@dataclass
class FunctionNode:
    name: str
    visibility: str = "internal"
    mutability: str = ""         # view | pure | payable | ""
    modifiers: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)
    state_reads: List[str] = field(default_factory=list)
    state_writes: List[str] = field(default_factory=list)
    events_emitted: List[str] = field(default_factory=list)
    is_payable: bool = False
    line: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "visibility": self.visibility,
            "mutability": self.mutability,
            "modifiers": self.modifiers,
            "calls": self.calls,
            "state_reads": self.state_reads,
            "state_writes": self.state_writes,
            "events_emitted": self.events_emitted,
            "is_payable": self.is_payable,
            "line": self.line,
        }


@dataclass
class ContractNode:
    name: str
    kind: str = "contract"          # contract | interface | library
    inherits: List[str] = field(default_factory=list)
    state_vars: List[str] = field(default_factory=list)
    functions: Dict[str, FunctionNode] = field(default_factory=dict)
    modifiers: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "inherits": self.inherits,
            "state_vars": self.state_vars,
            "functions": {n: f.to_dict() for n, f in self.functions.items()},
            "modifiers": self.modifiers,
        }


@dataclass
class CFG:
    source_file: str
    contracts: Dict[str, ContractNode] = field(default_factory=dict)
    call_graph: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source_file": self.source_file,
            "contracts": {n: c.to_dict() for n, c in self.contracts.items()},
            "call_graph": self.call_graph,
            "summary": {
                "total_contracts": len(self.contracts),
                "total_functions": sum(len(c.functions) for c in self.contracts.values()),
                "external_entry_points": self._entry_points(),
                "payable_functions": self._payable_functions(),
            },
        }

    def _entry_points(self) -> List[str]:
        out = []
        for cname, contract in self.contracts.items():
            for fname, fn in contract.functions.items():
                if fn.visibility in ("public", "external"):
                    out.append(f"{cname}.{fname}")
        return out

    def _payable_functions(self) -> List[str]:
        out = []
        for cname, contract in self.contracts.items():
            for fname, fn in contract.functions.items():
                if fn.is_payable:
                    out.append(f"{cname}.{fname}")
        return out


def _extract_visibility(attrs: str) -> str:
    for v in ("external", "public", "internal", "private"):
        if v in attrs:
            return v
    return "internal"


def _extract_mutability(attrs: str) -> str:
    for m in ("view", "pure", "payable"):
        if m in attrs:
            return m
    return ""


def _extract_modifiers(attrs: str, known_modifiers: Set[str]) -> List[str]:
    words = set(re.findall(r"\b\w+\b", attrs))
    return sorted(words & known_modifiers)


def _extract_function_body(source: str, fn_start: int) -> str:
    """Extract text of the function body starting from fn_start."""
    depth = 0
    start = source.find("{", fn_start)
    if start == -1:
        return ""
    end = start
    for i, ch in enumerate(source[start:], start=start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    return source[start:end + 1]


def _extract_calls(body: str, state_vars: List[str]) -> tuple[list, list, list]:
    calls: List[str] = []
    reads: List[str] = []
    writes: List[str] = []

    # Calls: obj.method( or method(
    for m in _RE_CALL.finditer(body):
        obj, method, bare = m.group(1), m.group(2), m.group(3)
        if obj and method:
            if obj not in _SOLIDITY_KEYWORDS:
                calls.append(f"{obj}.{method}")
        elif bare and bare not in _SOLIDITY_KEYWORDS:
            calls.append(bare)

    # State var reads/writes (heuristic: var appears in assignment LHS vs elsewhere)
    for var in state_vars:
        pattern = re.compile(r"\b" + re.escape(var) + r"\b")
        if not pattern.search(body):
            continue
        write_pattern = re.compile(r"\b" + re.escape(var) + r"\s*[+\-\*\/]?=")
        if write_pattern.search(body):
            writes.append(var)
        else:
            reads.append(var)

    # Events
    events = [m.group(1) for m in _RE_EMIT.finditer(body)]

    return (
        sorted(set(calls)),
        sorted(set(reads)),
        sorted(set(writes)),
    ), events


class CFGBuilder:
    """Builds a lightweight CFG from Solidity source without requiring the compiler."""

    def build(self, contract_path: str) -> dict:
        path = Path(contract_path)
        if not path.exists():
            return {"error": f"File not found: {contract_path}"}

        source = path.read_text(errors="replace")
        return self._parse(source, str(path)).to_dict()

    def build_from_source(self, source: str, name: str = "<inline>") -> dict:
        return self._parse(source, name).to_dict()

    def _parse(self, source: str, source_file: str) -> CFG:
        cfg = CFG(source_file=source_file)

        # Find all contract definitions
        for cm in _RE_CONTRACT.finditer(source):
            raw_name = cm.group(1)
            kind_match = re.search(r"(interface|library|abstract\s+contract|contract)", source[cm.start():cm.start() + 20])
            kind = "contract"
            if kind_match:
                k = kind_match.group(1)
                if "interface" in k:
                    kind = "interface"
                elif "library" in k:
                    kind = "library"

            inherits_raw = cm.group(2) or ""
            inherits = [i.strip() for i in inherits_raw.split(",") if i.strip()]

            contract = ContractNode(name=raw_name, kind=kind, inherits=inherits)

            # Extract state variables (scan until next contract or EOF)
            next_contract = source.find("\ncontract ", cm.end())
            if next_contract == -1:
                next_contract = len(source)
            contract_source = source[cm.end():next_contract]

            contract.state_vars = [
                m.group(2) for m in _RE_STATE_VAR.finditer(contract_source)
            ]
            contract.modifiers = [
                m.group(1) for m in _RE_MODIFIER.finditer(contract_source)
            ]

            # Extract functions
            known_mods = set(contract.modifiers)
            for fm in _RE_FUNCTION.finditer(contract_source):
                fname = fm.group(1)
                if fname in ("constructor",):
                    continue
                attrs = fm.group(3) or ""
                vis = _extract_visibility(attrs)
                mut = _extract_mutability(attrs)
                mods = _extract_modifiers(attrs, known_mods)
                line = contract_source[:fm.start()].count("\n") + 1

                body = _extract_function_body(contract_source, fm.start())
                (calls, reads, writes), events = _extract_calls(body, contract.state_vars)

                fn = FunctionNode(
                    name=fname,
                    visibility=vis,
                    mutability=mut,
                    modifiers=mods,
                    calls=calls,
                    state_reads=reads,
                    state_writes=writes,
                    events_emitted=events,
                    is_payable="payable" in attrs,
                    line=line,
                )
                contract.functions[fname] = fn

            cfg.contracts[raw_name] = contract

        # Build cross-contract call graph
        all_function_names = {
            fname
            for contract in cfg.contracts.values()
            for fname in contract.functions
        }
        for cname, contract in cfg.contracts.items():
            for fname, fn in contract.functions.items():
                key = f"{cname}.{fname}"
                cfg.call_graph[key] = [
                    c for c in fn.calls
                    if c.split(".")[-1] in all_function_names
                    or c in all_function_names
                ]

        return cfg
