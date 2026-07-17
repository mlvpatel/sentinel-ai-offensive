# Sentinel AI Offensive — Plugin Guide

This repo is a Claude Code plugin for professional offensive security — bug bounty hunting, VAPT, SAST analysis, and network penetration testing across HackerOne, Bugcrowd, Intigriti, and Immunefi.

A deterministic **trust layer** backs the plugin: a scope-attested audit chain (`tools/attest.py`), a K-repro oracle (`tools/oracle.py`), and an expected-value prior over your own hit/miss history (`memory/prior.py`).

## What's Here

### Skills (11 domains)

| Skill | Domain |
|---|---|
| `skills/sentinel-core/` | Master workflow — recon to report, all vuln classes, LLM testing, chains |
| `skills/hunt-mindset/` | **Hunting mindset + 5-phase non-linear workflow + tool routing + session discipline** |
| `skills/apex-pipeline/` | **Unified AppSec pipeline — intake → recon → SAST → DAST → hunt → chain → validate → report** |
| `skills/code-reaper/` | **Deep SAST — 12 languages, Semgrep, secret scanning, taint analysis, auth architecture audit** |
| `skills/netbreach/` | **Network pentesting — nmap/masscan, service exploitation, AD attacks, privesc, pivoting, wireless** |
| `skills/ghost-recon/` | Subdomain enum, live host discovery, URL crawling, nuclei |
| `skills/vuln-matrix/` | 20 bug classes with bypass tables (SSRF, open redirect, file upload, Agentic AI) |
| `skills/payload-forge/` | Payloads, bypass tables, gf patterns, always-rejected list |
| `skills/chain-guard/` | 10 smart contract bug classes, Foundry PoC template, pre-dive kill signals |
| `skills/strike-report/` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1, human tone |
| `skills/verdict-gate/` | 7-Question Gate, 4 gates, never-submit list, conditionally valid table |

### Commands (13 slash commands)

| Command | Usage |
|---|---|
| `/recon` | `/recon target.com` — full recon pipeline |
| `/hunt` | `/hunt target.com` — start hunting |
| `/validate` | `/validate` — run 7-Question Gate on current finding |
| `/report` | `/report` — write submission-ready report |
| `/chain` | `/chain` — build A→B→C exploit chain |
| `/scope` | `/scope <asset>` — verify asset is in scope |
| `/triage` | `/triage` — quick 7-Question Gate |
| `/web3-audit` | `/web3-audit <contract.sol>` — smart contract audit |
| `/autopilot` | `/autopilot target.com --normal` — autonomous hunt loop |
| `/surface` | `/surface target.com` — ranked attack surface |
| `/resume` | `/resume target.com` — pick up previous hunt |
| `/remember` | `/remember` — log finding to hunt memory |
| `/intel` | `/intel target.com` — fetch CVE + disclosure intel |

### Agents (7 specialized agents)

- `recon-agent` — subdomain enum + live host discovery
- `report-writer` — generates H1/Bugcrowd/Immunefi reports
- `validator` — 4-gate checklist on a finding
- `web3-auditor` — smart contract bug class analysis
- `chain-builder` — builds A→B→C exploit chains
- `autopilot` — autonomous hunt loop (scope→recon→rank→hunt→validate→report)
- `recon-ranker` — attack surface ranking from recon output + memory

### Rules (always active)

- `rules/hunting.md` — 20 critical hunting rules
- `rules/reporting.md` — report quality rules

### Tools (Python/shell — in `tools/`)

- `tools/hunt.py` — master orchestrator
- `tools/recon_engine.sh` — subdomain + URL discovery
- `tools/validate.py` — 4-gate finding validator
- `tools/report_generator.py` — report writer
- `tools/learn.py` — CVE + disclosure intel
- `tools/intel_engine.py` — on-demand intel with memory context
- `tools/scope_checker.py` — deterministic scope safety checker
- `tools/cicd_scanner.sh` — GitHub Actions workflow scanner (sisakulint wrapper, remote scan)
- `tools/attest.py` — verifies the audit log's tamper-evident hash chain and proves scope-clean (exits 1 if any request went out of scope): `python3 tools/attest.py <audit.jsonl>`
- `tools/oracle.py` — `repro_gate`: a finding is REAL only if a deterministic predicate fires K/K, else it routes to a needs-manual lane (the model never mints a finding)

### MCP Integrations (in `mcp/`)

- `mcp/burp-mcp-client/` — Burp Suite proxy integration
- `mcp/hackerone-mcp/` — HackerOne public API (Hacktivity, program stats, policy)

### Hunt Memory (in `memory/`)

- `memory/hunt_journal.py` — append-only hunt log (JSONL)
- `memory/pattern_db.py` — cross-target pattern learning
- `memory/prior.py` — expected-value Beta prior over your own confirm/reject history plus dead-end negative memory, wired into `pattern_db.match()`
- `memory/audit_log.py` — hash-chained request audit log (`prev_hash`/`entry_hash`, `verify_chain()`), rate limiter, circuit breaker
- `memory/schemas.py` — schema validation for all data

## Start Here

```bash
claude
# /recon target.com
# /hunt target.com
# /validate   (after finding something)
# /report     (after validation passes)
```

## Install Skills

```bash
chmod +x install.sh && ./install.sh
```

## Critical Rules (Always Active)

1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — "Can attacker do this RIGHT NOW?"
3. Run 7-Question Gate BEFORE writing any report
4. KILL weak findings fast — N/A hurts your validity ratio
5. 5-minute rule — nothing after 5 min = move on
