"""EVM Simulator — Gate 3 PoC execution via Foundry fork.

Falls back gracefully when Foundry (forge/anvil) is not installed.
Install: curl -L https://foundry.paradigm.xyz | bash && foundryup
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_FOUNDRY_AVAILABLE: Optional[bool] = None


def _has_foundry() -> bool:
    global _FOUNDRY_AVAILABLE
    if _FOUNDRY_AVAILABLE is None:
        _FOUNDRY_AVAILABLE = shutil.which("forge") is not None
    return _FOUNDRY_AVAILABLE


@dataclass
class SimResult:
    success: bool
    balance_delta: float = 0.0
    gas_used: int = 0
    gas_cost_eth: float = 0.0
    revert_reason: str = ""
    stdout: str = ""
    stderr: str = ""
    harness_path: str = ""
    mode: str = "forge"           # forge | stub | unavailable
    error: str = ""
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "balance_delta": self.balance_delta,
            "gas_used": self.gas_used,
            "gas_cost_eth": self.gas_cost_eth,
            "revert_reason": self.revert_reason,
            "mode": self.mode,
            "error": self.error,
            "harness_path": self.harness_path,
        }


_HARNESS_TEMPLATE = textwrap.dedent("""\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    import "forge-std/Test.sol";
    import "forge-std/console.sol";

    // Auto-generated harness for: {hypothesis}
    contract {name}Test is Test {{
        address constant TARGET = address({target_addr});
        uint256 constant BLOCK = {block};

        function setUp() public {{
            vm.createSelectFork(vm.envString("ETH_RPC_URL"), BLOCK);
        }}

        function test_exploit() public {{
            uint256 balBefore = address(this).balance;
            // TODO: insert exploit calldata here
            uint256 balAfter = address(this).balance;
            int256 delta = int256(balAfter) - int256(balBefore);
            console.log("balance_delta_wei:", delta);
            assertTrue(delta > 0, "exploit not profitable");
        }}
    }}
""")


class SimulationEngine:
    """Runs a PoC against a mainnet fork using Foundry (forge test)."""

    def __init__(self, rpc_url: str = ""):
        self._rpc = rpc_url or os.getenv("ETH_RPC_URL", "")

    def run(
        self,
        contract: str,
        block: Optional[int] = None,
        harness: Optional[str] = None,
        hypothesis: str = "",
        timeout: int = 120,
    ) -> dict:
        if not _has_foundry():
            return self._unavailable(contract)

        if not self._rpc:
            return SimResult(
                success=False,
                mode="forge",
                error="ETH_RPC_URL not set. Export ETH_RPC_URL=https://mainnet.infura.io/v3/<key>",
            ).to_dict()

        block_num = block or 0
        with tempfile.TemporaryDirectory(prefix="trinity_sim_") as tmp:
            tmp_path = Path(tmp)

            # Use provided harness or generate one
            if harness and Path(harness).exists():
                test_file = Path(harness)
            else:
                test_file = self._write_harness(
                    tmp_path, contract, block_num, hypothesis
                )

            result = self._run_forge(test_file, tmp_path, timeout)
            return result.to_dict()

    def _write_harness(
        self, tmp: Path, contract: str, block: int, hypothesis: str
    ) -> Path:
        name = re.sub(r"[^A-Za-z0-9]", "", Path(contract).stem or "Target")
        src_dir = tmp / "src"
        test_dir = tmp / "test"
        src_dir.mkdir()
        test_dir.mkdir()

        harness_code = _HARNESS_TEMPLATE.format(
            hypothesis=hypothesis[:80],
            name=name,
            target_addr=contract if contract.startswith("0x") else "0xdead",
            block=block or 0,
        )
        test_path = test_dir / f"{name}.t.sol"
        test_path.write_text(harness_code)

        # Minimal foundry.toml
        (tmp / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\n'
        )
        return test_path

    def _run_forge(self, test_file: Path, cwd: Path, timeout: int) -> SimResult:
        cmd = [
            "forge", "test",
            "--match-path", str(test_file),
            "--fork-url", self._rpc,
            "-vvv",
            "--json",
        ]
        try:
            proc = subprocess.run(
                cmd, cwd=str(cwd),
                capture_output=True, text=True, timeout=timeout,
                env={**os.environ, "ETH_RPC_URL": self._rpc},
            )
            return self._parse_forge_output(proc, str(test_file))
        except subprocess.TimeoutExpired:
            return SimResult(success=False, mode="forge",
                             error=f"forge timed out after {timeout}s",
                             harness_path=str(test_file))
        except Exception as e:
            return SimResult(success=False, mode="forge", error=str(e),
                             harness_path=str(test_file))

    def _parse_forge_output(self, proc: subprocess.CompletedProcess, harness: str) -> SimResult:
        # Try to parse JSON output
        balance_delta = 0.0
        gas_used = 0
        try:
            data = json.loads(proc.stdout)
            # forge --json returns {suite: {test_name: {status, gas, ...}}}
            for suite_results in data.values():
                if not isinstance(suite_results, dict):
                    continue
                for test_name, test_data in suite_results.items():
                    if not isinstance(test_data, dict):
                        continue
                    gas_used = test_data.get("gasUsed", 0)
                    if test_data.get("status") == "Success":
                        # Try to extract balance_delta from logs
                        for log in test_data.get("logs", []):
                            if "balance_delta_wei" in str(log):
                                m = re.search(r"balance_delta_wei:\s*(-?\d+)", str(log))
                                if m:
                                    balance_delta = int(m.group(1)) / 1e18
        except (json.JSONDecodeError, AttributeError):
            pass

        # Fallback: parse plain stdout
        if balance_delta == 0:
            m = re.search(r"balance_delta_wei:\s*(-?\d+)", proc.stdout)
            if m:
                balance_delta = int(m.group(1)) / 1e18

        revert = ""
        if proc.returncode != 0:
            m = re.search(r"Reason: (.+)", proc.stderr or proc.stdout)
            revert = m.group(1).strip() if m else "test reverted"

        gas_cost_eth = (gas_used * 30e-9)  # assume 30 gwei gas price

        return SimResult(
            success=proc.returncode == 0,
            balance_delta=balance_delta,
            gas_used=gas_used,
            gas_cost_eth=gas_cost_eth,
            revert_reason=revert,
            stdout=proc.stdout[:2000],
            stderr=proc.stderr[:500],
            harness_path=harness,
            mode="forge",
        )

    def _unavailable(self, contract: str) -> dict:
        return SimResult(
            success=False,
            mode="unavailable",
            error=(
                "Foundry not installed. "
                "Install: curl -L https://foundry.paradigm.xyz | bash && foundryup"
            ),
            harness_path=contract,
        ).to_dict()

    def stub_result(self, balance_delta: float, gas_used: int = 500_000) -> dict:
        """Inject a manual simulation result (used when running gates without forge)."""
        gas_cost_eth = gas_used * 30e-9
        return SimResult(
            success=balance_delta > 0,
            balance_delta=balance_delta,
            gas_used=gas_used,
            gas_cost_eth=gas_cost_eth,
            mode="stub",
        ).to_dict()
