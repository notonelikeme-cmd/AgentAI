"""
HackerOne program scanner — uses local AI to analyze scope and find targets.

Workflow:
1. Pull top programs from H1 API
2. Filter by eligibility (signal score, submission state, bounty minimum)
3. For each eligible program: pull scope, feed to local AI for attack surface analysis
4. Output ranked target list with vulnerability candidates
"""

import json
import subprocess
import sys
from typing import Optional
from core.h1_client import (
    get_top_programs,
    check_eligibility,
    scope_for_ai,
    get_signal,
    summarize_reports,
    get_report,
)


# ─── Local AI ────────────────────────────────────────────────────────────────

def _ask_local(prompt: str, code: bool = False, think: bool = False) -> str:
    """Call trinity.py ask with local model routing."""
    cmd = [sys.executable, "trinity.py", "ask", "--local", "--prompt", prompt]
    if code:
        cmd.append("--code")
    if think:
        cmd.append("--think")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=120,
            cwd="/Users/nova/AgentAI"
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[timeout — try a shorter prompt]"


# ─── Program Intelligence ─────────────────────────────────────────────────────

def find_best_programs(
    n: int = 20,
    min_bounty: float = 10_000,
    verbose: bool = True,
) -> list:
    """
    Pull top H1 programs, filter by eligibility and bounty, return ranked list.
    """
    if verbose:
        print("[h1_scanner] Fetching top programs from HackerOne...")

    signal = get_signal()
    if verbose:
        print(f"[h1_scanner] Your signal score: {signal:.1f}")

    programs = get_top_programs(n=n, min_bounty=min_bounty)
    eligible = []

    for p in programs:
        handle = p["handle"]
        elig = check_eligibility(handle, my_signal=signal)
        p["eligible"] = elig["eligible"]
        p["blocker"] = elig.get("blocker")
        if elig["eligible"]:
            eligible.append(p)
        elif verbose:
            print(f"  [skip] {handle} — {elig['blocker']}")

    if verbose:
        print(f"[h1_scanner] Eligible programs: {len(eligible)} / {len(programs)}")

    return eligible


def analyze_scope(handle: str, verbose: bool = True) -> dict:
    """
    Pull program scope and use local AI to identify high-value attack surfaces.
    Returns: {handle, scope_text, ai_analysis, vuln_candidates}
    """
    if verbose:
        print(f"[h1_scanner] Analyzing scope for: {handle}")

    scope_text = scope_for_ai(handle)

    prompt = (
        f"You are a DeFi / Web3 security researcher analyzing a bug bounty program scope.\n\n"
        f"Scope:\n{scope_text}\n\n"
        f"Task:\n"
        f"1. Identify the highest-value targets in this scope (smart contracts, APIs, bridges, oracles)\n"
        f"2. For each target, list the most likely vulnerability classes based on the asset type\n"
        f"3. Estimate attack complexity: LOW / MEDIUM / HIGH\n"
        f"4. Recommend which Nexus Trinity agents to run (flash-loan-detector, conservation-breaker, etc.)\n"
        f"5. Flag anything explicitly OUT of scope to avoid wasted effort\n\n"
        f"Output a ranked target list with vulnerability candidates."
    )

    analysis = _ask_local(prompt, think=True)

    return {
        "handle": handle,
        "scope_text": scope_text,
        "ai_analysis": analysis,
    }


# ─── Full Scan Pipeline ───────────────────────────────────────────────────────

def run_full_scan(
    n_programs: int = 10,
    min_bounty: float = 25_000,
    output_file: Optional[str] = None,
) -> list:
    """
    Full pipeline:
    1. Find eligible programs
    2. Analyze scope with AI for each
    3. Rank by bounty × AI-assessed opportunity
    4. Save results

    Returns list of {handle, max_bounty, scope_text, ai_analysis}
    """
    eligible = find_best_programs(n=n_programs * 3, min_bounty=min_bounty)

    results = []
    for prog in eligible[:n_programs]:
        handle = prog["handle"]
        scan = analyze_scope(handle)
        scan["max_bounty"] = prog["max_bounty"]
        scan["avg_bounty"] = prog["avg_bounty"]
        scan["url"] = prog["url"]
        results.append(scan)

    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[h1_scanner] Results saved to {output_file}")

    return results


# ─── Report Monitor ───────────────────────────────────────────────────────────

def monitor_reports(verbose: bool = True) -> dict:
    """
    Pull all your reports and categorize by status.
    Returns summary dict with open/pending mediation/resolved/rejected.
    """
    reports = summarize_reports()

    buckets = {
        "open_active": [],       # new or triaged — waiting on triage
        "needs_action": [],      # needs-more-info — you need to respond
        "in_mediation": [],      # you've filed mediation
        "resolved_paid": [],     # resolved with bounty
        "rejected": [],          # not-applicable, duplicate, spam, informative
    }

    for r in reports:
        state = r["state"]
        if state in ("new", "triaged"):
            buckets["open_active"].append(r)
        elif state == "needs-more-info":
            buckets["needs_action"].append(r)
        elif state == "pending-program-review":
            buckets["in_mediation"].append(r)
        elif state == "resolved":
            if r.get("bounty", 0):
                buckets["resolved_paid"].append(r)
            else:
                buckets["rejected"].append(r)
        else:
            buckets["rejected"].append(r)

    if verbose:
        print("\n=== YOUR H1 REPORT STATUS ===")
        for bucket, items in buckets.items():
            if items:
                print(f"\n[{bucket.upper()}] ({len(items)} reports)")
                for r in items:
                    bounty = f"  ${r['bounty']}" if r.get("bounty") else ""
                    print(f"  #{r['id']} — {r['title'][:60]} [{r['severity']}]{bounty}")

    return buckets


# ─── AI Scope Learner ─────────────────────────────────────────────────────────

def learn_scope_and_strategize(handle: str) -> str:
    """
    Deep scope analysis: pull scope, learn it with AI, output a full attack strategy.
    Uses DeepSeek-R1:14b for strategic reasoning.
    Best for programs you're committing to seriously.
    """
    scope_text = scope_for_ai(handle)

    prompt = (
        f"You are an elite DeFi security researcher preparing for a serious bug bounty engagement on '{handle}'.\n\n"
        f"Full scope:\n{scope_text}\n\n"
        f"Produce a complete attack strategy:\n"
        f"1. PRIORITY TARGETS — ranked by expected value (bounty × exploitability)\n"
        f"2. FOR EACH TARGET:\n"
        f"   a. Vulnerability classes most likely to exist (with reasoning)\n"
        f"   b. Specific functions/contracts to focus on first\n"
        f"   c. Required setup (mainnet fork, specific tokens, flash loan source)\n"
        f"   d. Nexus Trinity agent sequence to run\n"
        f"3. SCOPE LANDMINES — things that look in scope but are explicitly excluded\n"
        f"4. QUICK WINS — patterns likely to have obvious bugs (high signal, low effort)\n"
        f"5. TIME ESTIMATE — realistic hours for initial pass\n\n"
        f"Be specific. Cite asset names from the scope. This is your research plan."
    )

    print(f"[h1_scanner] Running deep scope analysis for {handle} (may take 60–90s)...")
    return _ask_local(prompt, think=True)
