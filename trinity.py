#!/usr/bin/env python3
"""Nexus Trinity — smart contract security research CLI."""
import argparse
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
CORE = ROOT / "core"
sys.path.insert(0, str(ROOT))

from core.core_registry import CoreRegistry
from core.agent_framework import AgentFramework


def cmd_status(args):
    reg = CoreRegistry()
    reg.initialize()
    status = reg.status()
    print(json.dumps(status, indent=2, default=str))


def cmd_gate0(args):
    """Gate 0: novelty check before any research."""
    from core.gates.gate0_novelty import Gate0Novelty
    gate = Gate0Novelty()
    result = gate.check(args.finding)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["novel"] else 1)


def cmd_simulate(args):
    """Gate 3: simulate PoC on mainnet fork."""
    from core.gates.simulation_engine import SimulationEngine
    engine = SimulationEngine()
    result = engine.run(
        contract=args.contract,
        block=args.block,
        harness=getattr(args, "harness", None),
    )
    print(json.dumps(result, indent=2))


def cmd_cfg(args):
    """Extract control flow graph from contract."""
    from core.analysis.cfg_builder import CFGBuilder
    builder = CFGBuilder()
    cfg = builder.build(args.contract)
    print(json.dumps(cfg, indent=2))


def cmd_kg(args):
    """Query the DeFi knowledge graph."""
    from core.analysis.defi_kg import DeFiKnowledgeGraph
    kg = DeFiKnowledgeGraph()
    if args.list:
        patterns = kg.list_patterns()
        for p in patterns:
            print(f"  {p}")
    elif args.query:
        result = kg.retrieve(args.query)
        print(json.dumps(result, indent=2))


def cmd_pipeline(args):
    """Run the full 7-gate pipeline on a hypothesis."""
    from core.gates.verification_loop import VerificationLoop
    from core.models import model_profile, CURATED_MODELS
    model = getattr(args, "model", None) or CURATED_MODELS[0]
    profile = model_profile(model)
    print(f"[Model] {model} — adaptive={profile['adaptive_thinking']} "
          f"max_out={profile['max_output_tokens']:,} xhigh={profile['xhigh_effort']}")
    loop = VerificationLoop()
    result = asyncio.run(loop.run(
        hypothesis=args.hypothesis,
        contract=args.contract,
        block=getattr(args, "block", None),
        model=model,
    ))
    print(json.dumps(result, indent=2, default=str))


def cmd_rao(args):
    """Run RAO (Reason-Act-Observe) autonomous exploit loop."""
    from core.rao_loop import RAOLoop
    from core.models import CURATED_MODELS
    model = getattr(args, "model", None) or CURATED_MODELS[0]
    rao = RAOLoop(
        contract_path=args.contract,
        block_number=getattr(args, "block", None),
        mode=getattr(args, "mode", "default"),
        baseline=getattr(args, "baseline", None),
        max_iterations=getattr(args, "iterations", 5),
        model=model,
    )
    result = asyncio.run(rao.run())
    print(json.dumps(result, indent=2, default=str))


def cmd_scan(args):
    """Quick vulnerability scan using pattern matching."""
    from core.analysis.solidity_analyzer import SolidityAnalyzer
    analyzer = SolidityAnalyzer()
    results = analyzer.scan(args.path)
    for r in results:
        print(f"[{r['severity']}] {r['type']} at {r['location']}: {r['description']}")


def cmd_findings(args):
    """Query the findings database."""
    from core.analysis.findingsdb import FindingsDB
    db = FindingsDB()
    if args.list:
        findings = db.list_findings(status=getattr(args, "status", None))
        for f in findings:
            print(f"[{f['id']}] [{f['severity']}] {f['title']} — {f['status']}")
    elif args.add:
        print("Use: trinity.py findings --add --title '...' --severity High --contract '...'")
    elif args.show:
        f = db.get(args.show)
        print(json.dumps(f, indent=2))


def cmd_models(args):
    """List curated models and their capability profiles."""
    from core.models import CURATED_MODELS, model_profile
    profiles = [model_profile(m) for m in CURATED_MODELS]
    print(json.dumps(profiles, indent=2))


def cmd_fetch_training(args):
    """Fetch real DeFi incident training data from DeFiHackLabs."""
    from core.github_fetcher import GitHubFetcher
    fetcher = GitHubFetcher()
    years = getattr(args, "years", None)
    years = years.split(",") if years else None
    result = fetcher.fetch(
        max_incidents=getattr(args, "max", 200),
        years=years,
        force_refresh=getattr(args, "force", False),
        delay=getattr(args, "delay", 0.3),
    )
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(
        prog="trinity",
        description="Nexus Trinity — Smart Contract Security Research System",
    )
    subs = parser.add_subparsers(dest="cmd", required=True)

    # status
    p = subs.add_parser("status", help="Show system status and agent registry")
    p.set_defaults(func=cmd_status)

    # gate0
    p = subs.add_parser("gate0", help="Gate 0: novelty check (run FIRST)")
    p.add_argument("--finding", required=True, help="Hypothesis text to check for novelty")
    p.set_defaults(func=cmd_gate0)

    # simulate
    p = subs.add_parser("simulate", help="Gate 3: simulate PoC on fork")
    p.add_argument("--contract", required=True, help="Path to contract source")
    p.add_argument("--block", type=int, help="Fork block number")
    p.add_argument("--harness", help="Path to existing .t.sol harness")
    p.set_defaults(func=cmd_simulate)

    # cfg
    p = subs.add_parser("cfg", help="Extract control flow graph")
    p.add_argument("--contract", required=True, help="Path to contract")
    p.set_defaults(func=cmd_cfg)

    # kg
    p = subs.add_parser("kg", help="Query DeFi knowledge graph")
    p.add_argument("--list", action="store_true", help="List all patterns")
    p.add_argument("--query", help="Mechanism to query")
    p.set_defaults(func=cmd_kg)

    # models
    p = subs.add_parser("models", help="List available models and their capabilities")
    p.set_defaults(func=cmd_models)

    # fetch-training
    p = subs.add_parser("fetch-training", help="Fetch real DeFi incident training data from GitHub")
    p.add_argument("--max", type=int, default=200, help="Max PoC files to fetch (default: 200)")
    p.add_argument("--years", default="2024,2025,2026", help="Comma-separated years (default: 2024,2025,2026)")
    p.add_argument("--force", action="store_true", help="Re-download even if cached")
    p.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds")
    p.set_defaults(func=cmd_fetch_training)

    # pipeline
    p = subs.add_parser("pipeline", help="Run full 7-gate verification pipeline")
    p.add_argument("--hypothesis", required=True, help="Falsifiable hypothesis string")
    p.add_argument("--contract", required=True, help="Path to target contract")
    p.add_argument("--block", type=int, help="Fork block number")
    p.add_argument("--model", help="Claude model to use (default: claude-fable-5)")
    p.set_defaults(func=cmd_pipeline)

    # rao
    p = subs.add_parser("rao", help="Run RAO autonomous exploit loop")
    p.add_argument("--contract", required=True, help="Path to target contract")
    p.add_argument("--block", type=int, help="Fork block number")
    p.add_argument("--mode", choices=["default", "differential"], default="default")
    p.add_argument("--baseline", help="Baseline protocol for differential mode")
    p.add_argument("--iterations", type=int, default=5, help="Max RAO iterations")
    p.add_argument("--model", help="Claude model to use (default: claude-fable-5)")
    p.set_defaults(func=cmd_rao)

    # scan
    p = subs.add_parser("scan", help="Quick automated vulnerability scan")
    p.add_argument("--path", required=True, help="Path to scan (file or directory)")
    p.set_defaults(func=cmd_scan)

    # findings
    p = subs.add_parser("findings", help="Query findings database")
    p.add_argument("--list", action="store_true")
    p.add_argument("--status", choices=["verified", "pending", "rejected", "submitted"])
    p.add_argument("--show", metavar="ID", help="Show finding by ID")
    p.add_argument("--add", action="store_true")
    p.set_defaults(func=cmd_findings)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
