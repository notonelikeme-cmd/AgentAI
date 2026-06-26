"""AuditRunner — single-command full audit from GitHub URL to submission report.

Usage:
    python3 trinity.py audit --repo https://github.com/morpho-org/morpho-blue

Pipeline:
    1. git clone → /tmp/nexus-<repo>/
    2. Gate 0 novelty check (skip known findings)
    3. trinity.py scan (quick pattern scan)
    4. RAO loop → hypothesis generation + scoring
    5. For each candidate: full 8-gate pipeline
    6. For each VERIFIED: ReportWriter → ~/AgentAI/reports/
    7. AgentWriter auto-fires if new mechanism class seen 2x
    8. SkillBuilder seeds KG with verified patterns
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

_TMP = Path("/tmp")
_REPORTS_DIR = Path.home() / "AgentAI" / "reports"


def _slug(url: str) -> str:
    """Turn a GitHub URL into a safe directory name."""
    return re.sub(r"[^\w\-]", "-", url.split("github.com/")[-1].strip("/"))


def _clone(repo_url: str, dest: Path, branch: Optional[str] = None) -> bool:
    """Clone or update a repo. Returns True on success."""
    if dest.exists():
        print(f"[Audit] Updating {dest.name}...")
        result = subprocess.run(
            ["git", "-C", str(dest), "pull", "--ff-only"],
            capture_output=True, text=True
        )
        return result.returncode == 0

    print(f"[Audit] Cloning {repo_url}...")
    cmd = ["git", "clone", "--depth=1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [repo_url, str(dest)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[Audit] Clone failed: {result.stderr}")
        return False
    return True


def _find_sol_dirs(root: Path) -> list[Path]:
    """Find directories containing Solidity files, skip test/lib/node_modules."""
    skip = {"test", "tests", "lib", "node_modules", "out", "cache", "script", "mocks"}
    dirs = set()
    for sol in root.rglob("*.sol"):
        if not any(p.name.lower() in skip for p in sol.parents):
            dirs.add(sol.parent)
    return sorted(dirs)[:10]  # top 10 contract dirs


class AuditRunner:
    """Orchestrates a full audit from repo URL to submission-ready reports."""

    def __init__(
        self,
        model: str = "claude-fable-5",
        max_iterations: int = 10,
        platform: str = "Immunefi",
        branch: Optional[str] = None,
    ):
        self.model = model
        self.max_iterations = max_iterations
        self.platform = platform
        self.branch = branch

    def run(self, repo_url: str) -> dict:
        """Full audit pipeline. Returns summary dict."""
        t0 = time.time()
        slug = _slug(repo_url)
        dest = _TMP / f"nexus-{slug}"

        print(f"\n{'='*60}")
        print(f"  NEXUS TRINITY AUDIT")
        print(f"  Target: {repo_url}")
        print(f"  Model:  {self.model}")
        print(f"{'='*60}\n")

        # Step 1: Clone
        if not _clone(repo_url, dest, self.branch):
            return {"error": f"Failed to clone {repo_url}", "elapsed": 0}

        # Step 2: Find source directories
        sol_dirs = _find_sol_dirs(dest)
        if not sol_dirs:
            return {"error": "No Solidity source files found", "repo": repo_url}
        print(f"[Audit] Found {len(sol_dirs)} source directories")

        # Step 3: Quick pattern scan
        print("\n[Audit] Running pattern scan...")
        scan_results = self._scan(sol_dirs)
        print(f"[Audit] Scan: {len(scan_results)} candidates")

        # Step 4: RAO loop across top source dirs
        all_verified = []
        all_reports = []
        seen_mechanisms = []

        for sol_dir in sol_dirs[:3]:  # top 3 dirs
            print(f"\n[Audit] RAO loop on {sol_dir.relative_to(dest)}...")
            verified = asyncio.run(self._rao_dir(str(sol_dir), seen_mechanisms))
            all_verified.extend(verified)

        # Step 5: Write reports for verified findings
        if all_verified:
            print(f"\n[Audit] Writing {len(all_verified)} reports...")
            for finding in all_verified:
                report_meta = self._write_report(finding)
                if report_meta:
                    all_reports.append(report_meta)
                    print(f"[Audit] Report: {report_meta['path']}")

        elapsed = time.time() - t0
        summary = {
            "repo": repo_url,
            "local_path": str(dest),
            "sol_dirs_scanned": len(sol_dirs),
            "scan_candidates": len(scan_results),
            "verified_findings": len(all_verified),
            "reports_written": len(all_reports),
            "reports": all_reports,
            "elapsed_seconds": round(elapsed, 1),
            "model": self.model,
        }

        # Print summary
        print(f"\n{'='*60}")
        print(f"  AUDIT COMPLETE — {elapsed:.0f}s")
        print(f"  Candidates found:    {len(scan_results)}")
        print(f"  Verified findings:   {len(all_verified)}")
        print(f"  Reports written:     {len(all_reports)}")
        if all_reports:
            for r in all_reports:
                print(f"  [{r['severity']}] {r['title'][:60]}")
                print(f"         → {r['path']}")
        print(f"{'='*60}\n")

        return summary

    def _scan(self, sol_dirs: list[Path]) -> list[dict]:
        """Run SolidityAnalyzer across all dirs."""
        try:
            import sys
            sys.path.insert(0, str(Path.home() / "AgentAI"))
            from core.analysis.solidity_analyzer import SolidityAnalyzer
            analyzer = SolidityAnalyzer()
            results = []
            for d in sol_dirs:
                results.extend(analyzer.scan(str(d)))
            return results
        except Exception as e:
            print(f"[Audit] Scan error: {e}")
            return []

    async def _rao_dir(self, contract_path: str, seen_mechanisms: list) -> list[dict]:
        """Run RAO loop on a directory, return verified findings."""
        try:
            import sys
            sys.path.insert(0, str(Path.home() / "AgentAI"))
            from core.rao_loop import RAOLoop
            from core.agent_writer import AgentWriter

            rao = RAOLoop(
                contract_path=contract_path,
                max_iterations=self.max_iterations,
                model=self.model,
            )
            result = await rao.run()
            findings = result.get("verified_findings", [])

            # Track mechanisms for AgentWriter
            aw = AgentWriter()
            for f in findings:
                mech = f.get("mechanism", "")
                if mech:
                    seen_mechanisms.append(mech)
                    aw.observe(mech, f.get("pattern_id", ""))

            return findings
        except Exception as e:
            print(f"[Audit] RAO error on {contract_path}: {e}")
            return []

    def _write_report(self, finding: dict) -> Optional[dict]:
        """Write a submission report for a verified finding."""
        try:
            import sys
            sys.path.insert(0, str(Path.home() / "AgentAI"))
            from core.report_writer import ReportWriter
            from core.model_router import ModelRouter

            router = ModelRouter()
            writer = ReportWriter(router=router)
            return writer.write(
                hypothesis=finding.get("hypothesis", ""),
                gate_data=finding.get("gate_data", {}),
                pipeline_result=finding,
                platform=self.platform,
            )
        except Exception as e:
            print(f"[Audit] Report write error: {e}")
            return None
