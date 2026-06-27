"""
HackerOne API client — program intelligence, report monitoring, scope analysis.

Auth: H1_USERNAME + H1_API_TOKEN environment variables (Basic Auth).
Set once in ~/.zshrc:
    export H1_USERNAME="your-handle"
    export H1_API_TOKEN="your-token"
"""

import os
import json
import time
import requests
from typing import Optional
from requests.auth import HTTPBasicAuth

_BASE = "https://api.hackerone.com/v1"

_USERNAME = os.environ.get("H1_USERNAME", "")
_API_TOKEN = os.environ.get("H1_API_TOKEN", "")


def _auth() -> HTTPBasicAuth:
    if not _USERNAME or not _API_TOKEN:
        raise RuntimeError(
            "Set H1_USERNAME and H1_API_TOKEN environment variables. "
            "Run: export H1_USERNAME='your-handle' && export H1_API_TOKEN='your-token'"
        )
    return HTTPBasicAuth(_USERNAME, _API_TOKEN)


def _get(path: str, params: dict = None) -> dict:
    r = requests.get(
        f"{_BASE}{path}",
        auth=_auth(),
        params=params or {},
        headers={"Accept": "application/json"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


# ─── Profile ──────────────────────────────────────────────────────────────────

def get_profile() -> dict:
    """Return your H1 hacker profile (signal, reputation, report counts)."""
    return _get("/hackers/me")


def get_signal() -> float:
    """Return your current signal score (0.0–7.0)."""
    data = get_profile()
    return data.get("data", {}).get("attributes", {}).get("signal", 0.0)


# ─── Reports ──────────────────────────────────────────────────────────────────

def get_my_reports(state: str = None) -> list:
    """
    Return your submitted reports.
    state: new | triaged | needs-more-info | resolved | not-applicable |
           informative | duplicate | spam | retesting
    """
    params = {"page[size]": 100}
    if state:
        params["filter[state][]"] = state
    data = _get("/me/reports", params=params)
    return data.get("data", [])


def get_report(report_id: int) -> dict:
    """Return full detail on a single report."""
    return _get(f"/reports/{report_id}")


def summarize_reports() -> list:
    """Return a clean summary list of all your reports."""
    reports = get_my_reports()
    out = []
    for r in reports:
        attrs = r.get("attributes", {})
        out.append({
            "id": r["id"],
            "title": attrs.get("title", ""),
            "state": attrs.get("state", ""),
            "severity": attrs.get("severity_rating", "unknown"),
            "bounty": attrs.get("bounty_amount", 0),
            "program": r.get("relationships", {}).get("program", {}).get("data", {}).get("id", ""),
            "created_at": attrs.get("created_at", ""),
            "disclosed_at": attrs.get("disclosed_at", ""),
        })
    return out


# ─── Programs ─────────────────────────────────────────────────────────────────

def get_program(handle: str) -> dict:
    """Return program metadata for a given handle."""
    return _get(f"/programs/{handle}")


def get_structured_scopes(handle: str) -> list:
    """Return the structured in-scope assets for a program."""
    data = _get(f"/programs/{handle}/structured_scopes", {"page[size]": 100})
    return data.get("data", [])


def search_programs(page_size: int = 100, min_bounty: float = 0) -> list:
    """
    Return programs from the H1 directory.
    min_bounty: filter to programs whose max_bounty >= this value (USD).
    """
    params = {
        "page[size]": page_size,
        "sort": "-maximum_bounty",
    }
    data = _get("/programs", params=params)
    programs = data.get("data", [])

    if min_bounty > 0:
        programs = [
            p for p in programs
            if (p.get("attributes", {}).get("maximum_bounty") or 0) >= min_bounty
        ]
    return programs


def get_top_programs(n: int = 20, min_bounty: float = 10_000) -> list:
    """
    Return top N programs sorted by max bounty, filtered by minimum bounty.
    Returns clean dicts ready for local AI analysis.
    """
    raw = search_programs(page_size=100, min_bounty=min_bounty)
    out = []
    for p in raw[:n]:
        attrs = p.get("attributes", {})
        out.append({
            "handle": attrs.get("handle", ""),
            "name": attrs.get("name", ""),
            "max_bounty": attrs.get("maximum_bounty", 0),
            "avg_bounty": attrs.get("average_bounty", 0),
            "submission_state": attrs.get("submission_state", ""),
            "signal_requirement": attrs.get("signal_requirement", 0),
            "response_efficiency": attrs.get("response_efficiency_percentage", 0),
            "offers_bounties": attrs.get("offers_bounties", False),
            "url": f"https://hackerone.com/{attrs.get('handle', '')}",
        })
    return out


def check_eligibility(handle: str, my_signal: float = None) -> dict:
    """
    Check if you're eligible to submit to a program based on signal score.
    Returns eligibility status and what's blocking submission if any.
    """
    if my_signal is None:
        my_signal = get_signal()

    prog = get_program(handle)
    attrs = prog.get("data", {}).get("attributes", {})
    required = attrs.get("signal_requirement") or 0
    state = attrs.get("submission_state", "closed")

    eligible = (
        state == "open"
        and attrs.get("offers_bounties", False)
        and my_signal >= required
    )

    return {
        "handle": handle,
        "eligible": eligible,
        "submission_state": state,
        "signal_required": required,
        "my_signal": my_signal,
        "offers_bounties": attrs.get("offers_bounties", False),
        "blocker": None if eligible else (
            "submissions_closed" if state != "open" else
            f"signal_too_low (have {my_signal:.1f}, need {required:.1f})" if my_signal < required else
            "no_bounties"
        ),
    }


# ─── Scope Intelligence ───────────────────────────────────────────────────────

def get_scope_summary(handle: str) -> dict:
    """
    Return a structured scope summary ready for local AI analysis.
    Includes in-scope assets, URL patterns, eligible targets.
    """
    scopes = get_structured_scopes(handle)
    assets = []
    for s in scopes:
        attrs = s.get("attributes", {})
        if attrs.get("eligible_for_bounty", False):
            assets.append({
                "type": attrs.get("asset_type", ""),
                "identifier": attrs.get("asset_identifier", ""),
                "instruction": attrs.get("instruction", ""),
                "max_severity": attrs.get("max_severity", ""),
                "eligible": True,
            })
    return {
        "handle": handle,
        "total_eligible_assets": len(assets),
        "assets": assets,
    }


def scope_for_ai(handle: str) -> str:
    """
    Return scope as a plain-text block suitable for pasting into trinity.py ask.
    Feed to DeepSeek-R1:14b to identify vulnerability candidates.
    """
    summary = get_scope_summary(handle)
    lines = [f"Program: {handle}", f"Eligible assets: {summary['total_eligible_assets']}\n"]
    for a in summary["assets"]:
        lines.append(f"[{a['type']}] {a['identifier']}")
        if a["instruction"]:
            lines.append(f"  Notes: {a['instruction'][:200]}")
        if a["max_severity"]:
            lines.append(f"  Max severity: {a['max_severity']}")
    return "\n".join(lines)
