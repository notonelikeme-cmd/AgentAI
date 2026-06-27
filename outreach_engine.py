#!/usr/bin/env python3
"""
Autonomous Company Discovery and Outreach Engine
Uses local Ollama models to identify companies, score them, and generate outreach packages.
"""

import os
import json
import csv
import subprocess
from datetime import datetime
from pathlib import Path

# Configuration
MODELS = {
    'discovery': 'qwen2.5-coder:14b',
    'scoring': 'deepseek-r1:14b',
    'outreach': 'gemma4:latest',
}

REPO_ROOT = Path('/Users/nova/AgentAI')
MEMORY_DIR = REPO_ROOT / 'memory'
TARGETS_DIR = REPO_ROOT / 'targets'

# Ensure directories exist
MEMORY_DIR.mkdir(parents=True, exist_ok=True)
TARGETS_DIR.mkdir(parents=True, exist_ok=True)

def call_ollama(model, prompt, system_prompt=None):
    """Call a local Ollama model and return the response."""
    try:
        cmd = ['ollama', 'run', model]
        if system_prompt:
            full_prompt = f"System: {system_prompt}\n\nUser: {prompt}"
        else:
            full_prompt = prompt
        
        result = subprocess.run(
            cmd,
            input=full_prompt,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return f"[Timeout calling {model}]"
    except Exception as e:
        return f"[Error calling {model}: {e}]"

def discover_companies(search_terms=None):
    """Use the discovery model to find potential target companies."""
    if not search_terms:
        search_terms = "SaaS, fintech, e-commerce, web services not on major bug bounty platforms"
    
    prompt = f"""
    Identify 10 companies that would be good targets for a web application security assessment service.
    Focus on: {search_terms}
    
    For each company, provide:
    - Company name
    - Primary domain
    - Industry
    - Estimated size (startup, small, mid-market, enterprise)
    - Why they might need security assessment
    
    Format as JSON array with objects containing: name, domain, industry, size, reason
    Return ONLY the JSON, no other text.
    """
    
    system_prompt = "You are a security researcher identifying companies that would benefit from web application security assessments."
    response = call_ollama(MODELS['discovery'], prompt, system_prompt)
    
    try:
        companies = json.loads(response)
        return companies
    except json.JSONDecodeError:
        print(f"Failed to parse discovery response: {response[:200]}")
        return []

def score_companies(companies):
    """Use the scoring model to evaluate companies using the rubric."""
    scored = []
    
    for company in companies:
        prompt = f"""
        Score this company for a web security assessment outreach using the rubric below.
        
        Company: {company.get('name')}
        Domain: {company.get('domain')}
        Industry: {company.get('industry')}
        Size: {company.get('size')}
        Context: {company.get('reason')}
        
        Scoring Rubric (0-100 total):
        - Security Posture Weakness (0-30): likely gaps, headers, endpoints, HTTPS
        - Business Impact/Risk (0-20): data handling, compliance needs, brand impact
        - Company Size & Budget (0-15): employees, revenue, security budget
        - Visibility & Reputation (0-15): brand recognition, reputation damage if breached
        - Bug Bounty History (0-10): not on platforms (8-10), minimal (6-7), active (0-3)
        - Industry/Sector (0-10): finance/healthcare/SaaS (9-10), e-commerce (7-8), other lower
        
        Provide:
        1. Score breakdown (each category)
        2. Total score (0-100)
        3. Outreach confidence (low/medium/high)
        4. Key vulnerabilities likely to be found
        5. Estimated budget capability
        
        Format as JSON with keys: security_posture, business_impact, company_size, visibility, bug_bounty, industry, total_score, confidence, likely_vulns, estimated_budget
        Return ONLY JSON, no other text.
        """
        
        system_prompt = "You are a security assessment expert scoring companies for outreach potential."
        response = call_ollama(MODELS['scoring'], prompt, system_prompt)
        
        try:
            scoring = json.loads(response)
            scored.append({
                **company,
                **scoring,
                'scored_at': datetime.now().isoformat()
            })
        except json.JSONDecodeError:
            print(f"Failed to score {company.get('name')}: {response[:200]}")
            scored.append({
                **company,
                'total_score': 0,
                'error': 'Scoring failed'
            })
    
    return scored

def generate_outreach(company):
    """Use the outreach model to generate a complete outreach package."""
    prompt = f"""
    Generate a complete security assessment outreach package for this company.
    
    Company: {company.get('name')}
    Domain: {company.get('domain')}
    Industry: {company.get('industry')}
    Score: {company.get('total_score')}/100
    Likely vulnerabilities: {company.get('likely_vulns')}
    Estimated budget: {company.get('estimated_budget')}
    
    Generate in this format (use ### for section headers):
    
    ### Assessment Summary
    [Brief summary of findings likely to be discovered]
    
    ### Key Findings Overview
    [3-5 likely security weaknesses with impact descriptions]
    
    ### Business Impact
    [Specific business impact of these findings]
    
    ### Outreach Email
    [Professional email ready to send]
    
    ### Proposal Summary
    [Brief proposal/SOW for engagement]
    
    ### Pricing
    [Suggested pricing based on company size and budget]
    """
    
    system_prompt = "You are a security consultant preparing professional outreach materials for a web application security assessment engagement."
    response = call_ollama(MODELS['outreach'], prompt, system_prompt)
    
    return response

def save_company_data(companies, scores, outreach_packages):
    """Save all company data to files for tracking and reference."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Save scored companies to CSV
    csv_path = TARGETS_DIR / f'scored_companies_{timestamp}.csv'
    if scores:
        keys = scores[0].keys()
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(scores)
        print(f"Saved scored companies to {csv_path}")
    
    # Save outreach packages to JSON
    outreach_path = TARGETS_DIR / f'outreach_packages_{timestamp}.json'
    with open(outreach_path, 'w') as f:
        json.dump(outreach_packages, f, indent=2)
    print(f"Saved outreach packages to {outreach_path}")
    
    return csv_path, outreach_path

def main():
    """Main orchestration: discover, score, and generate outreach for companies."""
    print("=" * 80)
    print("AUTONOMOUS COMPANY DISCOVERY AND OUTREACH ENGINE")
    print("=" * 80)
    print()
    
    # Step 1: Discover companies
    print("[1] Discovering companies...")
    companies = discover_companies()
    if not companies:
        print("No companies discovered. Exiting.")
        return
    print(f"Discovered {len(companies)} companies")
    for c in companies:
        print(f"  - {c.get('name')} ({c.get('domain')})")
    print()
    
    # Step 2: Score companies
    print("[2] Scoring companies...")
    scores = score_companies(companies)
    scores_sorted = sorted(scores, key=lambda x: x.get('total_score', 0), reverse=True)
    print("Top candidates:")
    for s in scores_sorted[:5]:
        score = s.get('total_score', 'N/A')
        confidence = s.get('confidence', 'N/A')
        print(f"  - {s.get('name')}: {score}/100 ({confidence})")
    print()
    
    # Step 3: Filter high-score companies (70+)
    high_score_companies = [s for s in scores_sorted if s.get('total_score', 0) >= 70]
    print(f"[3] Found {len(high_score_companies)} high-value targets (score >= 70)")
    for c in high_score_companies:
        print(f"  - {c.get('name')}: {c.get('total_score')}")
    print()
    
    # Step 4: Generate outreach for high-score companies
    print("[4] Generating outreach packages...")
    outreach_packages = {}
    for company in high_score_companies[:3]:  # Limit to top 3 for now
        print(f"  Generating outreach for {company.get('name')}...")
        outreach = generate_outreach(company)
        outreach_packages[company.get('name')] = {
            'company': company,
            'outreach': outreach
        }
    print()
    
    # Step 5: Save all data
    print("[5] Saving data...")
    csv_path, json_path = save_company_data(companies, scores, outreach_packages)
    print()
    
    # Step 6: Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Companies discovered: {len(companies)}")
    print(f"Companies scored: {len(scores)}")
    print(f"High-value targets (70+): {len(high_score_companies)}")
    print(f"Outreach packages generated: {len(outreach_packages)}")
    print(f"Data saved to: {TARGETS_DIR}")
    print()
    print(f"Next steps:")
    print(f"  1. Review scored companies in: {csv_path}")
    print(f"  2. Review outreach packages in: {json_path}")
    print(f"  3. Customize outreach emails as needed")
    print(f"  4. Send outreach to high-priority targets")
    print()

if __name__ == '__main__':
    main()
