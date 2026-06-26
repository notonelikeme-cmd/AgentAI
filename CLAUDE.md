# Nexus Trinity — Smart Contract Security Research System
## M5 Mac Setup (rebuilt 2026-06-25)

## System Overview
7-gate autonomous vulnerability verification pipeline for DeFi smart contract auditing.

## Default Model: claude-fable-5
All pipelines default to `claude-fable-5` (Mythos-class). Key properties:
- 1M context window, 128K max output tokens
- Adaptive thinking (mandatory — reasoning cannot be disabled)
- xhigh effort level supported
- Use `--model claude-opus-4-8` to override if Fable unavailable

```bash
python3 trinity.py models               # list all curated models + profiles
python3 trinity.py pipeline --hypothesis "..." --contract src/Vault.sol
python3 trinity.py pipeline --hypothesis "..." --contract src/Vault.sol --model claude-opus-4-8
```

## Quick Start
```bash
cd ~/AgentAI
python3 trinity.py status           # verify system OK
python3 trinity.py gate0 --finding "IF X THEN Y BECAUSE Z"  # ALWAYS FIRST
python3 trinity.py scan --path src/ # quick pattern scan
python3 trinity.py pipeline --hypothesis "..." --contract src/Vault.sol
```

## MANDATORY: Gate 0 First
Run `trinity.py gate0` before ANY research. No exceptions.
Uniswap V4 got 3 findings rejected because Gate 0 was skipped.

## Targets (active)
- Uniswap V4: hooks, PoolManager, transient storage (EIP-1153)
- Lido: withdrawal queue, oracle, stETH shares math
- Seaport: order validation, consideration amounts
- Morpho: vault accounting, share rounding, interest accrual

## Agents (in ~/.claude/agents/ — 40 total)

### DeFi Security
- `defi-security-auditor` — full 7-gate audit, use for any DeFi protocol
- `web3-defi-analyst` — protocol mechanics deep dive (use first)
- `defi-vuln-scout` — fast pattern scan, get candidates quickly
- `conservation-breaker` — balance invariant violations (Critical class)
- `freeze-hunter` — frozen funds bugs (Critical class)
- `upgrade-storage-collision` — proxy storage collision
- `cross-contract-invariant` — oracle manipulation, composability bugs
- `cache-tier-reviewer` — stale cache/TWAP exploitation
- `token-optimizer` — fee-on-transfer, rebasing token edge cases
- `onchain-surveillance-sentinel` — live on-chain state verification

### Recon
- `recon-surface-mapper` — initial attack surface mapping
- `attack-vector-mapper` — enumerate all vectors for a bug class
- `code-risk-analyzer` — score contracts by risk, prioritize audit time
- `source-verified-auditor` — verify bytecode matches source before audit

### Verification Pipeline
- `vuln-finding-verifier` — runs all 7 gates on a candidate
- `verification-adversary` — Gate 6: tries to refute the finding
- `gatekeeper-hallucination-enforcer` — verifies all claims against code
- `research-engine-reviewer` — quality check before entering pipeline
- `issue-duplicate-role-validator` — duplicate check before submission
- `Veritas-security-auditor` — pre-submission quality review

### Workflow
- `agent-router-reviewer` — which agents to use, in what order

### Security/Pentest (from workspace)
- `web-security-triage`, `ai-red-teamer`, `burp-suite-tester`, and 16 more...

## Python Code Structure
```
~/AgentAI/
├── trinity.py                    # Main CLI entry point
├── agentai_mcp_server.py         # MCP server for IDE/Claude integration
├── pipeline_orchestrator.py      # Multi-hypothesis batch pipeline
└── core/
    ├── core_registry.py          # Agent registry, system status
    ├── agent_framework.py        # Agent base class, task routing
    ├── gates/
    │   ├── gate0_novelty.py      # Gate 0: novelty check (SQLite + patterns)
    │   └── verification_loop.py  # 7-gate orchestrator
    └── analysis/
        ├── solidity_analyzer.py  # Pattern-based Solidity scanner
        └── findingsdb.py         # SQLite findings registry
```

## 7-Gate Pipeline
| Gate | Engine | Purpose |
|------|--------|---------|
| 0 | gate0_novelty | Novelty check — FIRST, ALWAYS |
| 1 | hypothesis | Falsifiable claim |
| 2 | evidence | Code citations (file:line) |
| 3 | simulation | PoC on mainnet fork |
| 4 | replay | Determinism across 2+ runs |
| 5 | economics | profit > 0 after all costs |
| 6 | adversarial | Cannot be refuted |
| 7 | reproducibility | Third-party can reproduce |

## Previous Work
- Morpho Midnight audit (Cantina): 3 findings (2 Low, 1 Info)
- Uniswap V4 H3a (MulDiv precision): REJECTED at Gate 5 (net profit -$2,048)
- System rebuild: 2026-06-09, Phase 1-2 complete and verified
