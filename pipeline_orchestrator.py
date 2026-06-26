#!/usr/bin/env python3
"""Pipeline Orchestrator — coordinates multi-agent audit workflows."""
import asyncio
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from core.core_registry import CoreRegistry
from core.gates.verification_loop import VerificationLoop


class PipelineOrchestrator:
    """Runs structured multi-gate audit pipelines with agent coordination."""

    def __init__(self):
        self.registry = CoreRegistry()
        self.registry.initialize()
        self._active_pipelines: Dict[str, dict] = {}

    def new_pipeline(self, target: str, protocol: str = "") -> str:
        pid = str(uuid.uuid4())[:8]
        self._active_pipelines[pid] = {
            "id": pid,
            "target": target,
            "protocol": protocol,
            "status": "created",
            "hypotheses": [],
            "findings": [],
        }
        return pid

    async def run_full_audit(self, pipeline_id: str, hypotheses: List[str], block: int = None) -> dict:
        """Run all hypotheses through the 7-gate pipeline."""
        pipeline = self._active_pipelines.get(pipeline_id)
        if not pipeline:
            return {"error": f"Pipeline {pipeline_id} not found"}

        pipeline["status"] = "running"
        loop = VerificationLoop()
        results = []

        for i, hypothesis in enumerate(hypotheses, start=1):
            print(f"\n[Pipeline {pipeline_id}] Hypothesis {i}/{len(hypotheses)}: {hypothesis[:60]}...")
            result = await loop.run(
                hypothesis=hypothesis,
                contract=pipeline["target"],
                block=block,
            )
            results.append(result)
            if result["verdict"] == "VERIFIED":
                pipeline["findings"].append(result)
                print(f"  → VERIFIED (gate {result['final_gate']})")
            else:
                print(f"  → BLOCKED at gate {result['final_gate']}: {result['summary']}")

        pipeline["status"] = "complete"
        pipeline["results"] = results

        verified = [r for r in results if r["verdict"] == "VERIFIED"]
        blocked = [r for r in results if r["verdict"] == "BLOCKED"]

        return {
            "pipeline_id": pipeline_id,
            "target": pipeline["target"],
            "total_hypotheses": len(hypotheses),
            "verified_findings": len(verified),
            "blocked": len(blocked),
            "findings": verified,
            "summary": f"{len(verified)}/{len(hypotheses)} hypotheses verified",
        }

    def run_quick_scan(self, path: str) -> dict:
        """Quick Solidity pattern scan, no gate pipeline."""
        from core.analysis.solidity_analyzer import SolidityAnalyzer
        analyzer = SolidityAnalyzer()
        findings = analyzer.scan(path)
        by_severity = {}
        for f in findings:
            sev = f["severity"]
            by_severity.setdefault(sev, []).append(f)
        return {
            "path": path,
            "total": len(findings),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "findings": findings,
        }

    def status(self) -> dict:
        return {
            "system": self.registry.status(),
            "active_pipelines": len(self._active_pipelines),
            "pipelines": {
                pid: {
                    "target": p["target"],
                    "status": p["status"],
                    "findings": len(p.get("findings", [])),
                }
                for pid, p in self._active_pipelines.items()
            },
        }


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Nexus Trinity Pipeline Orchestrator")
    subs = parser.add_subparsers(dest="cmd", required=True)

    p = subs.add_parser("status")
    p = subs.add_parser("scan")
    p.add_argument("--path", required=True)

    p = subs.add_parser("audit")
    p.add_argument("--contract", required=True)
    p.add_argument("--hypotheses", nargs="+", required=True)
    p.add_argument("--block", type=int)

    args = parser.parse_args()
    orch = PipelineOrchestrator()

    if args.cmd == "status":
        print(json.dumps(orch.status(), indent=2, default=str))
    elif args.cmd == "scan":
        result = orch.run_quick_scan(args.path)
        print(json.dumps(result, indent=2))
    elif args.cmd == "audit":
        pid = orch.new_pipeline(args.contract)
        result = await orch.run_full_audit(pid, args.hypotheses, args.block)
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
