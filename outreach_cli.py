#!/usr/bin/env python3
"""
Outreach Engine CLI
Command-line interface for the autonomous company discovery and outreach system.
"""

import argparse
import sys
from pathlib import Path

# Add repo to path
sys.path.insert(0, str(Path(__file__).parent))

from outreach_engine import main as run_discovery
from outreach_agent import run_outreach_agent_for_company

def main():
    parser = argparse.ArgumentParser(
        description='Autonomous Company Discovery and Outreach Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full discovery and scoring
  python3 outreach_cli.py discover
  
  # Generate outreach for a specific company
  python3 outreach_cli.py outreach "Example Corp" "example.com"
  
  # Run full pipeline
  python3 outreach_cli.py run-all
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Discover command
    discover_parser = subparsers.add_parser('discover', help='Discover and score companies')
    discover_parser.add_argument(
        '--search',
        type=str,
        default='SaaS, fintech, e-commerce, web services',
        help='Search terms for company discovery'
    )
    
    # Outreach command
    outreach_parser = subparsers.add_parser('outreach', help='Generate outreach for a specific company')
    outreach_parser.add_argument('company', help='Company name')
    outreach_parser.add_argument('domain', help='Company domain')
    
    # Run all
    run_all_parser = subparsers.add_parser('run-all', help='Run full pipeline (discover, score, generate outreach)')
    
    args = parser.parse_args()
    
    if args.command == 'discover':
        print(f"Running company discovery with search terms: {args.search}")
        run_discovery()
    
    elif args.command == 'outreach':
        print(f"Generating outreach for {args.company} ({args.domain})")
        result = run_outreach_agent_for_company(args.company, args.domain)
        
        # Save and display results
        if result['status'] == 'success':
            print("\n" + "="*80)
            print("OUTREACH PACKAGE GENERATED")
            print("="*80)
            print("\n[EMAIL]\n")
            print(result['state'].get('email', 'No email generated'))
            print("\n[PROPOSAL]\n")
            print(result['state'].get('proposal', 'No proposal generated'))
            print("\n" + "="*80)
    
    elif args.command == 'run-all':
        print("Running full pipeline: discover → score → outreach")
        # This would run the full pipeline
        # For now, just run discovery
        run_discovery()
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
