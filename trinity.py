#!/usr/bin/env python3
"""Nexus Trinity — smart contract security research CLI."""
import argparse
import asyncio
import json
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


def cmd_audit(args):
    """Full audit: clone repo → scan → RAO → 8 gates → reports."""
    from core.gates.gate0_novelty import Gate0Novelty
    from core.audit_runner import AuditRunner
    model = getattr(args, "model", None) or "claude-fable-5"
    gate0 = Gate0Novelty()
    g0 = gate0.check(f"full audit of {args.repo}")
    if not g0.get("novel", True):
        print(json.dumps({"gate0": "DUPLICATE", "reason": g0}, indent=2))
        sys.exit(1)
    runner = AuditRunner(
        model=model,
        max_iterations=getattr(args, "iterations", 10),
        platform=getattr(args, "platform", "Immunefi"),
        branch=getattr(args, "branch", None),
    )
    result = runner.run(args.repo)
    print(json.dumps(result, indent=2, default=str))


def cmd_report(args):
    """Write a submission report from a verified finding JSON."""
    from core.report_writer import ReportWriter
    from core.model_router import ModelRouter
    router = ModelRouter()
    writer = ReportWriter(router=router)

    gate_data = {}
    if getattr(args, "gate_data", None):
        with open(args.gate_data) as f:
            gate_data = json.load(f)

    meta = writer.write(
        hypothesis=args.hypothesis,
        gate_data=gate_data,
        pipeline_result={},
        platform=getattr(args, "platform", "Immunefi"),
    )
    print(json.dumps(meta, indent=2, default=str))


def cmd_router_status(args):
    """Show LLM routing status: Anthropic + Ollama fallback."""
    from core.model_router import ModelRouter
    router = ModelRouter()
    status = router.status()
    print(json.dumps(status, indent=2))


def cmd_rpc_status(args):
    """Show on-chain RPC connection status and latest block."""
    from core.onchain_client import OnChainClient
    client = OnChainClient(rpc_url=getattr(args, "rpc", "") or "")
    status = client.status()
    print(json.dumps(status, indent=2))


def cmd_rpc_read(args):
    """Read on-chain state from a live contract."""
    from core.onchain_client import OnChainClient
    client = OnChainClient(rpc_url=getattr(args, "rpc", "") or "")
    if not client.available:
        print('{"error": "ETH_RPC_URL not set — export ETH_RPC_URL=https://..."}')
        sys.exit(1)
    result = client.validate_hypothesis_state(
        contract=args.address,
        hypothesis=getattr(args, "hypothesis", ""),
    )
    print(json.dumps(result, indent=2, default=str))


def cmd_h1_default(args):
    print("Usage: trinity h1 <subcommand>  (programs | scope | scan | reports | profile | check)")


def cmd_h1_profile(args):
    from core.h1_client import get_profile
    profile = get_profile()
    attrs = profile.get("data", {}).get("attributes", {})
    print(f"Handle:     {attrs.get('username', '')}")
    print(f"Signal:     {attrs.get('signal') or 0:.1f}")
    print(f"Reputation: {attrs.get('reputation', 0)}")
    print(f"Impact:     {attrs.get('impact') or 0:.1f}")


def cmd_h1_programs(args):
    from core.h1_scanner import find_best_programs
    programs = find_best_programs(n=args.n, min_bounty=args.min_bounty)
    print(f"\n{'Handle':<30} {'Max Bounty':>12} {'Avg Bounty':>12} {'Response %':>10}")
    print("-" * 68)
    for p in programs:
        print(
            f"{p['handle']:<30} ${p['max_bounty']:>10,.0f} ${p['avg_bounty']:>10,.0f} "
            f"{p.get('response_efficiency', 0):>9.0f}%"
        )
    print(f"\nTotal eligible: {len(programs)}")


def cmd_h1_scope(args):
    from core.h1_scanner import analyze_scope, learn_scope_and_strategize
    if args.deep:
        result = learn_scope_and_strategize(args.handle)
        print(result)
    else:
        result = analyze_scope(args.handle)
        print(f"\n--- SCOPE ---\n{result['scope_text']}")
        print(f"\n--- AI ANALYSIS ---\n{result['ai_analysis']}")


def cmd_h1_scan(args):
    from core.h1_scanner import run_full_scan
    results = run_full_scan(
        n_programs=args.n,
        min_bounty=args.min_bounty,
        output_file=getattr(args, "output", None),
    )
    for r in results:
        print(f"\n{'='*60}")
        print(f"Program: {r['handle']} | Max bounty: ${r.get('max_bounty', 0):,.0f}")
        print(f"URL: {r.get('url', '')}")
        analysis = r.get('ai_analysis') or ""
        print(f"\n{analysis[:1000]}{'...' if len(analysis) > 1000 else ''}")


def cmd_h1_reports(args):
    from core.h1_scanner import monitor_reports
    monitor_reports(verbose=True)


def cmd_h1_check(args):
    from core.h1_client import check_eligibility
    result = check_eligibility(args.handle)
    print(f"\nProgram: {result['handle']}")
    print(f"Eligible: {'YES' if result['eligible'] else 'NO'}")
    print(f"Submission state: {result['submission_state']}")
    print(f"Bounties offered: {result['offers_bounties']}")
    print(f"Signal required: {result['signal_required']} | Your signal: {result['my_signal'] or 0:.1f}")
    if result.get("blocker"):
        print(f"Blocker: {result['blocker']}")


def cmd_ask(args):
    """Send a prompt through the ModelRouter (uses Ollama if Anthropic unavailable)."""
    from core.model_router import ModelRouter
    router = ModelRouter(prefer_local=getattr(args, "local", False))
    response = router.complete(
        prompt=args.prompt,
        gate=getattr(args, "gate", None),
        think=getattr(args, "think", False),
        code=getattr(args, "code", False),
    )
    print(f"[via {router.last_route}]\n")
    print(response)


def cmd_fetch_hf(args):
    """Fetch smart contract security datasets from Hugging Face."""
    from core.hf_fetcher import HuggingFaceFetcher
    fetcher = HuggingFaceFetcher()
    priorities = None
    if getattr(args, "priority", None):
        priorities = [int(p) for p in args.priority.split(",")]
    result = fetcher.fetch_all(
        priorities=priorities,
        force_refresh=getattr(args, "force", False),
    )
    print(json.dumps(result, indent=2, default=str))
    fetcher.close()


def cmd_analyze(args):
    """LLM-powered contract analysis — reads real source, generates hypotheses."""
    from core.llm_auditor import LLMAuditor
    focus = args.focus.split(",") if getattr(args, "focus", None) else None
    auditor = LLMAuditor(max_functions=getattr(args, "max_functions", 15))
    hypotheses = auditor.analyze(
        args.contract,
        focus_functions=focus,
        verbose=True,
    )
    import sys as _sys
    _out = _sys.stderr if getattr(args, "json", False) else _sys.stdout
    print(f"\n{'='*60}", file=_out)
    print(f"  {len(hypotheses)} hypothesis(es) from LLM source analysis", file=_out)
    print(f"{'='*60}\n", file=_out)
    for i, h in enumerate(hypotheses, 1):
        print(f"[{i}] [{h.source_function}()] {h.text}\n", file=_out)
    if getattr(args, "json", False):
        print(json.dumps([{
            "text": h.text,
            "function": h.source_function,
            "file": h.source_file,
            "citations": h.citations,
        } for h in hypotheses], indent=2))


def cmd_hf_search(args):
    """Search HuggingFace training data for vulnerability patterns."""
    from core.hf_fetcher import HuggingFaceFetcher
    fetcher = HuggingFaceFetcher()
    results = fetcher.search(
        args.query,
        dataset_id=getattr(args, "dataset", None),
        limit=getattr(args, "limit", 10),
    )
    print(json.dumps(results, indent=2, default=str))
    fetcher.close()


def cmd_ingest(args):
    """Ingest threat intelligence from all sources into RAOBrain-ready Hypothesis objects."""
    from core.data_ingestor import DataIngestor
    ingestor = DataIngestor()
    max_per = getattr(args, "max", 200)

    if getattr(args, "stats", False):
        print(json.dumps(ingestor.stats(), indent=2))
        ingestor.close()
        return

    if getattr(args, "feed", None):
        findings = ingestor.load_feed(args.feed)
        print(f"[ingest] Loaded {len(findings)} findings from {args.feed}", file=sys.stderr)
    else:
        findings = ingestor.ingest_all(max_per_source=max_per)

    hypotheses = ingestor.to_hypotheses(findings)
    ingestor.close()

    _out = sys.stderr if getattr(args, "json", False) else sys.stdout
    print(f"\n{'='*60}", file=_out)
    print(f"  {len(hypotheses)} hypotheses ingested from threat intelligence", file=_out)
    print(f"{'='*60}\n", file=_out)

    for i, h in enumerate(hypotheses[:20], 1):
        print(f"[{i:02d}] [{h.score:.2f}] [{h.pattern_id}] {h.text[:100]}", file=_out)

    if len(hypotheses) > 20:
        print(f"  ... and {len(hypotheses)-20} more", file=_out)

    if getattr(args, "json", False):
        print(json.dumps([h.to_dict() for h in hypotheses], indent=2))

    if getattr(args, "seed_rao", False) and hypotheses:
        from core.rao_brain import RAOBrain
        brain = RAOBrain()
        for h in hypotheses:
            brain._observation_log.append({
                "pattern_id": h.pattern_id,
                "verdict": "INGESTED",
                "gate": 0,
                "details": h.rationale,
            })
        print(f"\n[ingest] Seeded RAOBrain with {len(hypotheses)} historical findings")


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
    p.add_argument("--model", default="claude-fable-5", help="Claude model to use")
    p.set_defaults(func=cmd_pipeline)

    # rao
    p = subs.add_parser("rao", help="Run RAO autonomous exploit loop")
    p.add_argument("--contract", required=True, help="Path to target contract")
    p.add_argument("--block", type=int, help="Fork block number")
    p.add_argument("--mode", choices=["default", "differential"], default="default")
    p.add_argument("--baseline", help="Baseline protocol for differential mode")
    p.add_argument("--iterations", type=int, default=5, help="Max RAO iterations")
    p.add_argument("--model", default="claude-fable-5", help="Claude model to use")
    p.set_defaults(func=cmd_rao)

    # scan
    p = subs.add_parser("scan", help="Quick automated vulnerability scan")
    p.add_argument("--path", required=True, help="Path to scan (file or directory)")
    p.set_defaults(func=cmd_scan)

    # audit
    p = subs.add_parser("audit", help="Full audit: clone repo → scan → RAO → 8 gates → reports")
    p.add_argument("--repo", required=True, help="GitHub URL to audit (e.g. https://github.com/morpho-org/morpho-blue)")
    p.add_argument("--model", default="claude-fable-5", help="LLM model")
    p.add_argument("--iterations", type=int, default=10, help="Max RAO iterations per dir")
    p.add_argument("--platform", default="Immunefi", choices=["Immunefi", "Cantina", "Sherlock"])
    p.add_argument("--branch", help="Git branch to audit (default: main)")
    p.set_defaults(func=cmd_audit)

    # report
    p = subs.add_parser("report", help="Write submission report from verified finding")
    p.add_argument("--hypothesis", required=True, help="IF/THEN/BECAUSE hypothesis")
    p.add_argument("--gate-data", help="Path to gate_data JSON file")
    p.add_argument("--platform", default="Immunefi", choices=["Immunefi", "Cantina", "Sherlock"])
    p.set_defaults(func=cmd_report)

    # router-status
    p = subs.add_parser("router-status", help="Show LLM routing: Anthropic primary + Ollama fallback")
    p.set_defaults(func=cmd_router_status)

    # rpc-status
    p = subs.add_parser("rpc-status", help="Show on-chain RPC connection status and latest block")
    p.add_argument("--rpc", help="Override ETH_RPC_URL for this call")
    p.set_defaults(func=cmd_rpc_status)

    # rpc-read
    p = subs.add_parser("rpc-read", help="Read live on-chain state from a contract address")
    p.add_argument("--address", required=True, help="Contract address (0x...)")
    p.add_argument("--hypothesis", default="", help="Hypothesis text (helps focus state reads)")
    p.add_argument("--rpc", help="Override ETH_RPC_URL for this call")
    p.set_defaults(func=cmd_rpc_read)

    # ask
    p = subs.add_parser("ask", help="Send a prompt through the ModelRouter")
    p.add_argument("--prompt", required=True, help="Prompt text")
    p.add_argument("--gate", type=int, help="Gate number (1-2 auto-routes to local Ollama)")
    p.add_argument("--local", action="store_true", help="Force Ollama (skip Anthropic)")
    p.add_argument("--think", action="store_true", help="Enable Gemma 4 thinking mode")
    p.add_argument("--code", action="store_true", help="Route to Qwen2.5-Coder (Solidity/code tasks)")
    p.set_defaults(func=cmd_ask)

    # analyze
    p = subs.add_parser("analyze", help="LLM reads real Solidity source → contract-specific hypotheses")
    p.add_argument("--contract", required=True, help="Path to .sol file or directory")
    p.add_argument("--focus", help="Comma-separated function names to prioritize (e.g. liquidate,supply)")
    p.add_argument("--max-functions", type=int, default=15, help="Max functions to audit (default: 15)")
    p.add_argument("--json", action="store_true", help="Also output JSON")
    p.set_defaults(func=cmd_analyze)

    # fetch-hf
    p = subs.add_parser("fetch-hf", help="Fetch HuggingFace smart contract security datasets")
    p.add_argument("--priority", help="Comma-separated priorities to fetch (e.g. 1,2,3 — default: all)")
    p.add_argument("--force", action="store_true", help="Re-download even if cached")
    p.set_defaults(func=cmd_fetch_hf)

    # hf-search
    p = subs.add_parser("hf-search", help="Search HuggingFace training data")
    p.add_argument("--query", required=True, help="Term to search for")
    p.add_argument("--dataset", help="Filter by dataset ID")
    p.add_argument("--limit", type=int, default=10)
    p.set_defaults(func=cmd_hf_search)

    # ingest
    p = subs.add_parser("ingest", help="Pull threat intel from DeFiHackLabs + HuggingFace → Hypothesis objects")
    p.add_argument("--max", type=int, default=200, help="Max findings per source (default: 200)")
    p.add_argument("--feed", help="Load custom JSON feed file instead of live sources")
    p.add_argument("--stats", action="store_true", help="Show cache stats only")
    p.add_argument("--seed-rao", action="store_true", help="Seed RAOBrain observation log with findings")
    p.add_argument("--json", action="store_true", help="Output full JSON")
    p.set_defaults(func=cmd_ingest)

    # findings
    p = subs.add_parser("findings", help="Query findings database")
    p.add_argument("--list", action="store_true")
    p.add_argument("--status", choices=["verified", "pending", "rejected", "submitted"])
    p.add_argument("--show", metavar="ID", help="Show finding by ID")
    p.add_argument("--add", action="store_true")
    p.set_defaults(func=cmd_findings)

    # h1 — HackerOne intelligence
    h1 = subs.add_parser("h1", help="HackerOne intelligence: programs, scope, reports")
    h1_subs = h1.add_subparsers(dest="h1_cmd")

    p = h1_subs.add_parser("programs", help="List eligible high-bounty programs")
    p.add_argument("--min-bounty", type=float, default=10_000, help="Min max_bounty filter (default: $10K)")
    p.add_argument("--n", type=int, default=20, help="Number of programs to fetch (default: 20)")
    p.set_defaults(func=cmd_h1_programs)

    p = h1_subs.add_parser("scope", help="Pull and AI-analyze scope for a program")
    p.add_argument("--handle", required=True, help="Program handle (e.g. polygon)")
    p.add_argument("--deep", action="store_true", help="Run deep strategic analysis (slower)")
    p.set_defaults(func=cmd_h1_scope)

    p = h1_subs.add_parser("scan", help="Full scan: find eligible programs + analyze scope with AI")
    p.add_argument("--n", type=int, default=5, help="Number of programs to deep-scan (default: 5)")
    p.add_argument("--min-bounty", type=float, default=25_000, help="Min bounty to consider (default: $25K)")
    p.add_argument("--output", help="Save results to JSON file")
    p.set_defaults(func=cmd_h1_scan)

    p = h1_subs.add_parser("reports", help="Check status of your submitted reports")
    p.set_defaults(func=cmd_h1_reports)

    p = h1_subs.add_parser("profile", help="Show your H1 profile and signal score")
    p.set_defaults(func=cmd_h1_profile)

    p = h1_subs.add_parser("check", help="Check eligibility for a specific program")
    p.add_argument("--handle", required=True, help="Program handle to check")
    p.set_defaults(func=cmd_h1_check)

    h1.set_defaults(func=cmd_h1_default)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
