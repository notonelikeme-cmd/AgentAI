# Autonomous Outreach Engine

Autonomous company discovery, vulnerability assessment, and outreach system powered by local Ollama models.

## Overview

The Outreach Engine is a production-ready system for identifying companies that need web application security assessments, automatically analyzing their security posture, and generating professional outreach materials including reports, proposals, and emails.

**Key Features:**
- Autonomous company discovery using AI
- Intelligent company scoring (0-100 scale)
- Automated vulnerability assessment
- Professional outreach email generation
- Statement of work and proposal generation
- Agent-based architecture with pluggable tools
- Powered by local Ollama models (no API keys required)

## System Architecture

### Three Core Models

- **qwen2.5-coder:14b** — Company discovery, research, technical analysis
- **deepseek-r1:14b** — Vulnerability assessment, threat analysis, reasoning
- **gemma4:latest** — Outreach copy, proposals, client-facing writing

### Components

1. **outreach_engine.py** — Main orchestrator for company discovery and scoring
2. **outreach_agent.py** — Agent framework with pluggable tools for outreach generation
3. **outreach_cli.py** — Command-line interface
4. **outreach_runner.sh** — Shell wrapper for easy terminal use

### Tool Types

The agent framework includes:

- `CompanyResearchTool` — Research companies and gather public information
- `VulnerabilityAssessmentTool` — Identify likely vulnerabilities
- `OutreachEmailTool` — Generate personalized outreach emails
- `ProposalGeneratorTool` — Create professional proposals/SOWs

## Quick Start

### 1. Discover and Score Companies

```bash
python3 /Users/nova/AgentAI/outreach_engine.py
```

This will:
- Discover 10 companies fitting your search criteria
- Score each company (0-100 scale)
- Filter high-value targets (70+ score)
- Generate outreach packages for top 3 targets
- Save results to `targets/` directory

### 2. Generate Outreach for a Specific Company

```bash
python3 /Users/nova/AgentAI/outreach_agent.py "Company Name" "domain.com"
```

This will:
- Research the company
- Assess likely vulnerabilities
- Generate a personalized outreach email
- Create a professional proposal
- Display results in terminal

### 3. Using the CLI

```bash
python3 /Users/nova/AgentAI/outreach_cli.py discover
python3 /Users/nova/AgentAI/outreach_cli.py outreach "Example Corp" "example.com"
python3 /Users/nova/AgentAI/outreach_cli.py run-all
```

### 4. Using the Shell Wrapper

```bash
/Users/nova/AgentAI/outreach_runner.sh discover
/Users/nova/AgentAI/outreach_runner.sh outreach "Example Corp" "example.com"
/Users/nova/AgentAI/outreach_runner.sh run-all
```

## Scoring Rubric

Companies are scored on:

| Category | Points | Criteria |
|----------|--------|----------|
| Security Posture Weakness | 0-30 | How likely we are to find real vulnerabilities |
| Business Impact / Risk Exposure | 0-20 | Data handling, compliance, brand impact |
| Company Size & Budget | 0-15 | Ability to pay for security assessment |
| Visibility & Reputation | 0-15 | Brand recognition, breach impact |
| Bug Bounty History | 0-10 | Not on major platforms = better outreach candidate |
| Industry / Sector | 0-10 | Finance, healthcare, SaaS = higher priority |

**Score Interpretation:**
- 85-100: Excellent outreach candidate
- 70-84: Good candidate, worth prioritizing
- 55-69: Moderate candidate, worth exploring
- <55: Lower priority

## Workflow

### Full Pipeline

```
1. DISCOVER
   ↓
2. SCORE
   ↓
3. FILTER (70+ scores only)
   ↓
4. RESEARCH
   ↓
5. ASSESS VULNERABILITIES
   ↓
6. GENERATE EMAIL
   ↓
7. GENERATE PROPOSAL
   ↓
8. SAVE OUTREACH PACKAGES
```

### Output Files

Discovery and scoring results are saved to:
- `targets/scored_companies_YYYYMMDD_HHMMSS.csv` — Full scoring data
- `targets/outreach_packages_YYYYMMDD_HHMMSS.json` — Complete outreach packages

Agent results are displayed in terminal and can be exported manually.

## Terminal Commands

### Quick Setup

```bash
# Add shortcuts to ~/.zshrc
alias outreach-discover='python3 /Users/nova/AgentAI/outreach_engine.py'
alias outreach-agent='python3 /Users/nova/AgentAI/outreach_agent.py'
alias ollama-coder='ollama run qwen2.5-coder:14b'
alias ollama-reason='ollama run deepseek-r1:14b'
alias ollama-general='ollama run gemma4:latest'
```

Then use:
```bash
outreach-discover
outreach-agent "Company Name" "domain.com"
```

## Guardrails & Ethics

✓ **Only passive, non-invasive assessment** — No destructive testing, brute-force, or unauthorized access
✓ **Consent-based scope** — All assessments are offered as professional services with authorization
✓ **Responsible disclosure** — Findings are reported confidentially with safe-harbor language
✓ **Business-focused** — Outreach is professional and emphasizes security improvement, not fear
✓ **Legal compliance** — Legal language is provided as draft for counsel review

## Customization

### Change Search Terms for Discovery

Edit the search terms in `outreach_engine.py`:
```python
companies = discover_companies("fintech, crypto, blockchain")
```

Or pass as argument (future version):
```bash
python3 outreach_engine.py --search "fintech, crypto, blockchain"
```

### Adjust Scoring Weights

Modify the rubric in `memory/target_scoring_rubric.md` or adjust scoring in `outreach_agent.py`.

### Customize Outreach Templates

Modify prompts in:
- `outreach_agent.py` — Email and proposal generation
- `memory/outreach_package_template.md` — Reference templates

## Integration

### With Local Ollama Models

The system automatically uses your local Ollama models. Ensure you have the three models loaded:

```bash
ollama pull qwen2.5-coder:14b
ollama pull deepseek-r1:14b
ollama pull gemma4:latest
```

Verify with:
```bash
ollama list
```

### Expand with Additional Tools

Create new tools by extending `OutreachTool`:

```python
class MyCustomTool(OutreachTool):
    def __init__(self):
        super().__init__('tool_name', 'Tool description')
    
    def execute(self, **kwargs):
        # Your tool logic here
        return {'status': 'success', 'data': result}
```

Then add to agent:
```python
self.tools['my_tool'] = MyCustomTool()
```

## Production Use

For production deployment:

1. **Verify Authorization** — Always ensure companies are authorized for assessment
2. **Track Outreach** — Use the CSV target list to track outreach attempts and responses
3. **Save Conversations** — Archive generated emails and proposals for records
4. **Follow Up** — Use the follow-up checklist in `memory/outreach_package_template.md`
5. **Monitor Responses** — Track which companies engage and their feedback

## Next Steps

- [ ] Test with local Ollama models
- [ ] Run discovery on your target industries
- [ ] Review scored companies and adjust search criteria
- [ ] Customize outreach emails for your pitch
- [ ] Begin outreach to top candidates
- [ ] Track responses and engagement
- [ ] Scale to full outreach campaign

## Repository Structure

```
AgentAI/
├── outreach_engine.py          # Main discovery and scoring orchestrator
├── outreach_agent.py           # Agent framework with tools
├── outreach_cli.py             # Command-line interface
├── outreach_runner.sh          # Shell wrapper
├── memory/
│   ├── security_outreach_prompt.md     # Master workflow prompt
│   ├── target_scoring_rubric.md        # Scoring methodology
│   ├── target_list_template.csv        # Target tracking template
│   └── outreach_package_template.md    # Outreach material templates
└── targets/
    ├── scored_companies_*.csv          # Generated scoring results
    └── outreach_packages_*.json        # Generated outreach materials
```

## Support

For issues or questions:
1. Check local Ollama models are running: `ollama list`
2. Verify model calls: Run individual prompts manually
3. Review generated output for accuracy
4. Adjust prompts and scoring criteria as needed

---

**Built with:** Python 3, Ollama (local), and agent-based automation
