# Changelog

## 2026-07-17 — Trust Layer, Valid Plugin Manifest & Green CI

### Added — Trust Layer
- `tools/attest.py`: verifies the audit log's tamper-evident hash chain and proves scope-clean, exiting `1` if any request went out of scope (`python3 tools/attest.py <audit.jsonl>`)
- `tools/oracle.py`: `repro_gate` — a finding is REAL only if a deterministic predicate fires K/K, otherwise it routes to a needs-manual lane (the model never mints a finding)
- `memory/prior.py`: expected-value Beta prior over your own confirm/reject history plus dead-end negative memory, wired into `pattern_db.match()`
- `memory/audit_log.py`: hash-chains every entry (`prev_hash`/`entry_hash`) with a `verify_chain()` method; `schemas.py` now registers the `prev_hash`/`entry_hash` audit fields

### Added — Valid Plugin & CI/CD
- **Valid, installable Claude Code plugin**: `.claude-plugin/plugin.json` + `marketplace.json`; `hooks/hooks.json` valid schema (SessionStart / Stop / SessionEnd); `requirements.txt` (requests, certifi)
  - Install: `/plugin marketplace add mlvpatel/sentinel-ai-offensive` then `/plugin install sentinel-ai-offensive@sentinel-ai-offensive`
- **Green CI** — `ci.yml` (lint / test / security / structure) + CodeQL, with all GitHub Actions SHA-pinned; Dependabot configured (pip + github-actions)
- Agents now pin model **aliases** (`sonnet` / `opus` / `haiku`) instead of dated model IDs

### Fixed
- TLS-verification fix on the HackerOne path

### Changed — Docs
- Honest README rewrite — dropped "platform", "orchestrates 25+ tools in 60s", and NIST/GDPR/ISO **certification** claims (the project is a control-mapping/reference aid, not certified)
- Added `assets/logo.svg`

### Removed
- Stray `SKILL.md.zip`
- 1.4 MB `logo.png` (replaced by `assets/logo.svg`)

## v1.0.0 — Sentinel AI Offensive (Apr 2026)

### Added — Enterprise Documentation
- **`SECURITY.md`**: Security policy — responsible disclosure, threat model, trust boundaries, attack vector matrix, secure development lifecycle, runtime security controls, secrets management, incident response, supply chain security, SBOM
- **`COMPLIANCE.md`**: Compliance control mapping — NIST Cyber AI Profile, SOC 2 Type II, GDPR/EU AI Act, ISO 27001, ISO 42001, Zero-Trust architecture, evidence verification scripts
- **`ARCHITECTURE.md`**: Technical architecture — 6-layer decomposition, data flow diagrams, agent architecture, memory system design, defense-in-depth model, decision architecture, scalability & extension guides
- **`CONTRIBUTING.md`**: Contribution guidelines — fork/branch workflow, code style, testing requirements, PR process, security review checklist
- **`CODE_OF_CONDUCT.md`**: Contributor Covenant v2.1 with ethical use addendum for offensive security

### Added — Platform Features
- **11 skill domains**: `sentinel-core`, `hunt-mindset`, `apex-pipeline`, `code-reaper`, `netbreach`, `ghost-recon`, `vuln-matrix`, `payload-forge`, `chain-guard`, `strike-report`, `verdict-gate`
- **13 slash commands**: `/recon`, `/hunt`, `/validate`, `/report`, `/chain`, `/scope`, `/triage`, `/web3-audit`, `/autopilot`, `/surface`, `/resume`, `/remember`, `/intel`
- **7 specialized agents**: `recon-agent`, `report-writer`, `validator`, `web3-auditor`, `chain-builder`, `autopilot`, `recon-ranker`
- **MCP integrations**: Burp Suite proxy + HackerOne public API

### Added — Compliance Framework
- NIST, GDPR, ISO 27001 badge links to `COMPLIANCE.md`
- SOC 2 trust service criteria mapping
- ISO 42001 (AI Management) controls
- Compliance audit checklist with executable verification commands

### Added — CI/CD GitHub Actions Security
- `SKILL.md` CI/CD Pipeline section: **6 categories, 30+ checks, PoC templates, hunting workflow, and GHSA reference table**
  - **Category 1: Code Injection & Expression Safety** — expression injection, envvar/envpath/output clobbering, argument injection, SSRF via workflow, taint source catalog, fix patterns
  - **Category 2: Pipeline Poisoning & Untrusted Checkout** — untrusted checkout on `pull_request_target`/`workflow_run`, TOCTOU, cache/artifact poisoning
  - **Category 3: Supply Chain & Dependency Security** — unpinned actions (tag → SHA), impostor commits, ref confusion, vulnerable/archived actions
  - **Category 4: Credential & Secret Protection** — secret exfiltration, unmasked `fromJson()` bypass, excessive `secrets: inherit`
  - **Category 5: Triggers & Access Control** — dangerous triggers, label-based approval bypass, bot condition spoofing, OIDC token theft
  - **Category 6: AI Agent Security** — unrestricted AI triggers, excessive tool grants, prompt injection via workflow context
  - **Tooling**: integrated [sisakulint](https://sisaku-security.github.io/lint/) — 52 rules, taint propagation, 81.6% GHSA coverage
  - **10 real-world GHSAs** — proven Critical/High advisories with affected actions
- `tools/cicd_scanner.sh`: standalone sisakulint wrapper — org/repo scanning, recursive reusable workflow analysis
- `install_tools.sh`: sisakulint binary auto-download with OS/arch detection

### Added — Hunting Methodology Skill
- `skills/hunt-mindset/SKILL.md`: **Hunting mindset + 5-phase non-linear workflow**
  - **Part 1: Mindset** — Define/Select/Execute discipline, 4 thinking domains, developer psychology, Feature-based vs Vuln-based route selection
  - **Part 2: Workflow** — 5-phase non-linear flow (Recon → Map → Find → Prove → Report) with decision trees, vuln-class routing
  - **Part 3: Navigation & Timing** — "I'm stuck because..." reference table, 20-minute rotation clock, session discipline

### Added — 20 Vulnerability Classes
- **20 Web2 bug classes** with bypass tables: IDOR, Auth Bypass, XSS, SSRF, Business Logic, Race Conditions, SQLi, OAuth/OIDC, File Upload, GraphQL, LLM/AI, API Misconfig, ATO, SSTI, Subdomain Takeover, Cloud/Infra, HTTP Smuggling, Cache Poisoning, MFA Bypass, SAML/SSO
- **10 Web3 bug classes**: Accounting Desync, Access Control, Incomplete Code Path, Off-By-One, Oracle Manipulation, ERC4626, Reentrancy, Flash Loan, Signature Replay, Proxy/Upgrade
- **Full network pentesting**: nmap, masscan, AD attacks, privesc, pivoting, wireless

### Added — Payload Arsenal
- NoSQL injection, command injection, SSTI detection, HTTP smuggling, WebSocket, MFA bypass, SAML attack payloads
- SSRF IP bypass table (11 techniques), open redirect bypass table (11 techniques), file upload bypass table (10 techniques)
- Agentic AI ASI01-ASI10 framework (OWASP 2026)

### Added — Security Controls
- `memory/audit_log.py`: Immutable JSONL audit log + per-host rate limiter + circuit breaker + safe method policy + autopilot guard
- `tools/scope_checker.py`: Deterministic scope safety with anchored suffix matching
- `tools/credential_store.py`: Secure credential handling with masked output
- `tools/validate.py`: 4-gate finding validation with 7-Question Gate
- `memory/schemas.py`: Schema validation for all entry types (versioned)
- `memory/hunt_journal.py`: Append-only JSONL hunt log (concurrent-safe via `fcntl.flock`)
- `memory/pattern_db.py`: Cross-target pattern learning database
- `tools/recon_adapter.py`: Canonical recon output format with legacy adapter

### Added — Tools
- `tools/hunt.py` — Master orchestrator
- `tools/recon_engine.sh` — Subdomain + URL discovery (8-phase pipeline)
- `tools/intel_engine.py` — Memory-aware CVE + disclosure intel
- `tools/report_generator.py` — H1/Bugcrowd/Intigriti report output
- `tools/cicd_scanner.sh` — GitHub Actions workflow scanner
- Vulnerability scanners: `h1_idor_scanner.py`, `h1_mutation_idor.py`, `h1_oauth_tester.py`, `h1_race.py`, `zero_day_fuzzer.py`, `cve_hunter.py`
- AI/LLM testing: `hai_probe.py`, `hai_payload_builder.py`, `hai_browser_recon.js`

### Added — Rules (Always Active)
- `rules/hunting.md` — 20 critical hunting rules
- `rules/reporting.md` — 12 report quality rules

### Infrastructure
- `hooks/hooks.json` — Session start/stop hooks
- `install.sh` — One-command skill installation
- `install_tools.sh` — Go binaries + sisakulint auto-download
- 5 vendored wordlists
- 238 tests across 15 test files
