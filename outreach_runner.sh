#!/usr/bin/env bash
# Outreach Engine Runner
# Simplifies running the outreach engine and agent from the command line

set -e

REPO_ROOT="/Users/nova/AgentAI"
PYTHON="${PYTHON:-python3}"

case "$1" in
  discover)
    echo "Running company discovery..."
    cd "$REPO_ROOT"
    $PYTHON outreach_engine.py
    ;;
  
  outreach)
    if [ -z "$2" ] || [ -z "$3" ]; then
      echo "Usage: outreach <company_name> <domain>"
      exit 1
    fi
    echo "Generating outreach for $2 ($3)..."
    cd "$REPO_ROOT"
    $PYTHON outreach_agent.py "$2" "$3"
    ;;
  
  run-all)
    echo "Running full pipeline..."
    cd "$REPO_ROOT"
    $PYTHON outreach_cli.py run-all
    ;;
  
  *)
    echo "Outreach Engine - Autonomous Company Discovery and Outreach"
    echo ""
    echo "Usage: $0 {discover|outreach|run-all} [args]"
    echo ""
    echo "Commands:"
    echo "  discover                    Discover and score companies"
    echo "  outreach COMPANY DOMAIN     Generate outreach for a specific company"
    echo "  run-all                     Run full pipeline"
    echo ""
    echo "Examples:"
    echo "  $0 discover"
    echo "  $0 outreach 'Example Corp' 'example.com'"
    echo "  $0 run-all"
    ;;
esac
