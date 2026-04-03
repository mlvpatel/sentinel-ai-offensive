---
name: apex-pipeline
description: Unified application security testing workflow — combines recon, SAST, DAST, manual hunting, validation, and reporting into a single orchestrated pipeline. Runs as an "app" with automated phase transitions. Supports web apps (React, Next.js, Django, Flask, Laravel, Spring, Rails, Express), mobile APIs, GraphQL, REST, gRPC, and microservices. Phases — Phase 0 (target intake + scope lock), Phase 1 (passive recon + tech fingerprint), Phase 2 (SAST deep scan via semgrep/grep/trufflehog), Phase 3 (DAST active probing — nuclei/ffuf/dalfox), Phase 4 (manual hunt — IDOR/SSRF/XSS/SQLi/auth-bypass/race/business-logic/LLM), Phase 5 (chain building + impact escalation), Phase 6 (7-Question Gate validation), Phase 7 (report generation). Use when starting a full security assessment on any application, when asked to "test this app", "audit this codebase", "find bugs in this project", or when you need an end-to-end security workflow that combines static and dynamic analysis with manual expertise.
---

# AppSec Workflow — Full Pipeline in One Skill

End-to-end application security testing: Intake → Recon → SAST → DAST → Hunt → Chain → Validate → Report.

---

## THE GOLDEN RULE

> **Every finding must answer: "What can an attacker steal, break, or take over RIGHT NOW — with proof?"**
>
> If you can't show a working exploit → it's not a finding. Move on.

---

## PHASE 0: TARGET INTAKE & SCOPE LOCK

### Step 1: Define the Target

```
TARGET_NAME: _______________
TARGET_TYPE: [ ] Web App  [ ] API  [ ] Mobile Backend  [ ] Microservices  [ ] Monolith
SOURCE_CODE: [ ] Available  [ ] Partial (JS bundles)  [ ] None (black-box)
AUTH_MODEL:  [ ] Session Cookie  [ ] JWT  [ ] OAuth/OIDC  [ ] API Key  [ ] SAML  [ ] None
```

### Step 2: Lock Scope

```
IN SCOPE:
  - Domain(s): _______________
  - API(s):    _______________
  - Source:    _______________

OUT OF SCOPE:
  - _______________

RULES:
  [ ] No DoS / load testing
  [ ] No social engineering
  [ ] Rate limit: ___ req/sec
  [ ] Test accounts only (no real user data)
```

### Step 3: Crown Jewel Identification

Before touching any tool, determine the highest-value targets:

| App Type | Crown Jewel | Worst Case |
|----------|-------------|------------|
| E-commerce | Payment/billing | Drain funds, steal PII |
| SaaS | Multi-tenancy | Cross-tenant data access |
| Healthcare | Patient data | HIPAA violation, PII leak |
| Auth provider | SSO/tokens | Full SSO chain compromise |
| FinTech | Transactions | Unauthorized transfers |
| Social | User content | Mass data exfil, ATO |

```
MY CROWN JEWELS:
  1. _______________
  2. _______________
  3. _______________
```

### Step 4: Environment Setup

```bash
# Create assessment directory
TARGET="target-name"
mkdir -p assessments/$TARGET/{recon,sast,dast,findings,reports}

# Set test accounts
ATTACKER_EMAIL="attacker@test.com"
VICTIM_EMAIL="victim@test.com"

# Verify tools
which semgrep httpx nuclei ffuf dalfox trufflehog gitleaks 2>/dev/null
```

---

## PHASE 1: PASSIVE RECON & TECH FINGERPRINT

### 1A: Technology Stack Detection (2 min)

```bash
# Response headers
curl -sI https://$TARGET | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator|set-cookie"

# Cookie fingerprinting
# XSRF-TOKEN + *_session → Laravel
# PHPSESSID → PHP
# JSESSIONID → Java (Spring/Tomcat)
# connect.sid → Express/Node.js
# _rails_session → Ruby on Rails

# JS bundle analysis
curl -s https://$TARGET | grep -oE 'src="[^"]*\.js"' | head -20
# /_next/static/ → Next.js
# /static/js/main.chunk.js → Create React App
# /__nuxt/ → Nuxt.js
# /assets/*.js → ViteJS

# API convention detection
curl -s https://$TARGET/api/ 2>/dev/null | head -5
curl -s https://$TARGET/graphql 2>/dev/null -d '{"query":"{ __typename }"}' | head -5
```

### 1B: Attack Surface Mapping

```bash
# If source code available
find . -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.go" \
  -o -name "*.rb" -o -name "*.php" -o -name "*.java" -o -name "*.rs" \
  | grep -v node_modules | grep -v vendor | grep -v test | wc -l

# Count route definitions (framework-specific)
grep -rn "app\.\(get\|post\|put\|delete\|patch\)" --include="*.js" --include="*.ts" | grep -v node_modules | wc -l
grep -rn "@app\.route\|@router\." --include="*.py" | wc -l
grep -rn "Route::" --include="*.php" | wc -l
```

### 1C: Subdomain + Asset Discovery (if applicable)

```bash
# Passive subdomain enum
subfinder -d $TARGET -silent | anew assessments/$TARGET/recon/subs.txt
assetfinder --subs-only $TARGET | anew assessments/$TARGET/recon/subs.txt

# Resolve + probe
cat assessments/$TARGET/recon/subs.txt | dnsx -silent | \
  httpx -silent -status-code -title -tech-detect | \
  tee assessments/$TARGET/recon/live.txt

# URL collection
cat assessments/$TARGET/recon/live.txt | awk '{print $1}' | \
  katana -d 3 -jc -kf all -silent | \
  anew assessments/$TARGET/recon/urls.txt
```

### Phase 1 Decision Gate

| What You Found | Next Phase |
|----------------|------------|
| Source code available | Phase 2 (SAST) |
| No source, live endpoints found | Phase 3 (DAST) |
| Nothing after 5 min | KILL — move to next target |

---

## PHASE 2: STATIC APPLICATION SECURITY TESTING (SAST)

> **Delegate here**: For deep SAST, use `skills/code-reaper/SKILL.md`.

### 2A: Quick Wins — Dangerous Function Grep (5 min)

```bash
# Universal dangerous patterns
grep -rn "eval(\|exec(\|system(\|popen(\|passthru(" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.php" \
  --include="*.rb" --include="*.go" --include="*.java" \
  | grep -v node_modules | grep -v test | grep -v vendor \
  | tee assessments/$TARGET/sast/dangerous-functions.txt

# TODO/FIXME/HACK markers near security code
grep -rn "TODO\|FIXME\|HACK\|UNSAFE\|INSECURE\|WORKAROUND" \
  --include="*.py" --include="*.js" --include="*.ts" \
  | grep -iv "test\|spec\|node_modules" \
  | grep -i "auth\|token\|password\|session\|crypto\|encrypt\|sign\|verify\|permission\|role" \
  | tee assessments/$TARGET/sast/security-todos.txt
```

### 2B: Semgrep Scan (10 min)

```bash
# Install if needed
pip3 install semgrep 2>/dev/null

# Broad security audit
semgrep --config=p/security-audit ./ --json -o assessments/$TARGET/sast/semgrep-security.json 2>/dev/null
semgrep --config=p/owasp-top-ten ./ --json -o assessments/$TARGET/sast/semgrep-owasp.json 2>/dev/null

# Extract critical + high findings
cat assessments/$TARGET/sast/semgrep-security.json | \
  jq '.results[] | select(.extra.severity == "ERROR" or .extra.severity == "WARNING") | 
  {severity:.extra.severity, path:.path, line:.start.line, rule:.check_id, msg:.extra.message}'
```

### 2C: Secret Scanning (5 min)

```bash
# Trufflehog — verified secrets only
trufflehog filesystem --only-verified ./ 2>/dev/null | tee assessments/$TARGET/sast/secrets.txt

# Gitleaks — git history scan
gitleaks detect --source . --report-path assessments/$TARGET/sast/gitleaks.json 2>/dev/null

# Manual grep for high-value patterns
grep -rn "AKIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA" . --include="*.js" --include="*.ts" --include="*.py" --include="*.env" | grep -v node_modules
grep -rn "sk-[a-zA-Z0-9]\{20,\}\|ghp_[a-zA-Z0-9]\{36\}\|gho_[a-zA-Z0-9]\{36\}" . | grep -v node_modules
```

### 2D: Auth Pattern Analysis

```bash
# Find all auth middleware / decorators
grep -rn "authenticate\|authorize\|requireAuth\|isAuthenticated\|login_required\|@auth" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.go" \
  | grep -v node_modules | grep -v test \
  | tee assessments/$TARGET/sast/auth-checks.txt

# Find routes WITHOUT auth (The Sibling Rule)
# Compare route definitions against auth middleware applications
# Any route WITHOUT auth middleware = POTENTIAL IDOR / AUTH BYPASS
```

### Phase 2 Decision Gate

| SAST Finding | Next Action |
|-------------|-------------|
| Critical: hardcoded secrets | Verify they're active → Report immediately |
| High: SQLi/XSS/RCE pattern | Phase 4 — confirm with manual testing |
| Medium: auth inconsistency | Phase 4 — test the unprotected endpoints |
| No findings in 15 min | Phase 3 (DAST) |

---

## PHASE 3: DYNAMIC APPLICATION SECURITY TESTING (DAST)

### 3A: Nuclei Scan (template-based)

```bash
# Full nuclei scan against live hosts
nuclei -l assessments/$TARGET/recon/live.txt \
  -severity critical,high,medium \
  -t ~/nuclei-templates/ \
  -o assessments/$TARGET/dast/nuclei.txt

# Targeted scans
nuclei -u https://$TARGET -t ~/nuclei-templates/cves/ -severity critical,high
nuclei -u https://$TARGET -t ~/nuclei-templates/exposures/ -severity medium,high,critical
nuclei -u https://$TARGET -t ~/nuclei-templates/misconfiguration/
```

### 3B: Directory & API Fuzzing

```bash
# Directory discovery
ffuf -u "https://$TARGET/FUZZ" \
  -w ~/wordlists/common.txt \
  -mc 200,201,204,301,302,307,401,403 \
  -ac -t 40 \
  -o assessments/$TARGET/dast/dirs.json

# API endpoint discovery
ffuf -u "https://$TARGET/api/FUZZ" \
  -w ~/wordlists/api-endpoints.txt \
  -mc 200,201,204,301,302 \
  -ac -t 20

# Parameter discovery
ffuf -w ~/wordlists/params.txt \
  -u "https://$TARGET/api/endpoint?FUZZ=test" \
  -ac -mc 200
```

### 3C: XSS Scanning

```bash
# Identify reflective parameters
cat assessments/$TARGET/recon/urls.txt | \
  grep -E "[?&](q|search|query|name|redirect|url|next|callback|ref)=" | \
  dalfox pipe -o assessments/$TARGET/dast/xss.txt
```

### 3D: Quick Wins Checklist

```
[ ] /.env → exposed environment variables
[ ] /.git/config → exposed git repository
[ ] /graphql → introspection enabled
[ ] /swagger-ui.html or /api-docs → exposed API docs
[ ] /actuator/env → Spring Boot actuator
[ ] /debug or /_debug → debug endpoints
[ ] /phpinfo.php → PHP info exposed
[ ] /server-status → Apache status
[ ] /wp-json/wp/v2/users → WordPress user enum
[ ] Firebase: https://APP.firebaseio.com/.json
```

### Phase 3 Decision Gate

| DAST Finding | Next Action |
|-------------|-------------|
| Nuclei critical/high hit | Phase 4 — manual confirm + escalate |
| Interesting 403/401 endpoints | Phase 4 — auth bypass testing |
| XSS confirmed | Phase 5 — chain to ATO if possible |
| Nothing in 20 min | Phase 4 — manual hunting on high-value endpoints |

---

## PHASE 4: MANUAL VULNERABILITY HUNTING

### Hunt Priority by Stack

| Stack | Hunt First | Hunt Second |
|-------|-----------|-------------|
| React + Express | Prototype pollution, DOM XSS | IDOR (API routes) |
| Next.js | SSRF via Server Actions | Open redirect via redirect() |
| Django | IDOR (ModelViewSet, no object_permission) | SSTI (mark_safe) |
| Flask | SSTI (render_template_string) | SSRF (requests lib) |
| Laravel | Mass assignment ($fillable) | IDOR (Eloquent, no ownership) |
| Spring Boot | Actuator endpoints | SSTI (Thymeleaf) |
| Ruby on Rails | Mass assignment | IDOR (:id routes) |
| GraphQL | Introspection → auth bypass on mutations | IDOR via node(id:) |

### Testing Decision Flow

```
What input are you testing?
├── ID parameter (user_id, order_id)
│   → IDOR checklist (10 variants)
├── Search/filter/sort field
│   → SQLi, NoSQLi probing
├── URL input / webhook / PDF gen
│   → SSRF checklist (11 IP bypasses)
├── Text field reflected in page
│   → XSS (DOM or reflected)
├── File upload
│   → SVG XSS, web shell, path traversal
├── Price/quantity/coupon
│   → Business logic, race conditions
├── Login / 2FA / password reset
│   → Auth bypass (9 ATO paths)
├── Profile update API
│   → Mass Assignment
├── Template / wiki editor
│   → SSTI
└── Nothing obvious
    → Fuzz with ffuf, try error-based probing
```

### IDOR Quick Test (2 accounts required)

```bash
# Step 1: Login as Attacker (Account A)
# Step 2: Note all IDs in requests
# Step 3: Login as Victim (Account B)
# Step 4: Replay Attacker's requests with Victim's IDs but Attacker's auth token

# Test every HTTP method
for M in GET POST PUT PATCH DELETE; do
  echo "=== $M ==="
  curl -s -X $M "https://$TARGET/api/resource/VICTIM_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -H "Content-Type: application/json"
done
```

### Auth Bypass Checklist

```
[ ] Missing auth on sibling endpoints (Sibling Rule)
[ ] API version rollback (/v1 vs /v2)
[ ] HTTP method swap (GET blocked → try PUT/DELETE)
[ ] JWT none algorithm attack
[ ] JWT RS256→HS256 confusion
[ ] Role parameter injection (role=admin in body)
[ ] Header injection (X-User-ID, X-Org-ID)
[ ] GraphQL node() bypassing per-object auth
[ ] WebSocket messages without auth verification
```

### 20-Minute Rotation Clock

Every 20 min ask: **"Am I making progress?"**
- Yes → Continue
- No → Rotate: endpoint → subdomain → vuln class → target
- 45+ min on one parameter → STOP. Rabbit hole.

---

## PHASE 5: CHAIN BUILDING & IMPACT ESCALATION

### A→B→C Chain Table

| Bug A (Found) | Hunt for Bug B | Escalate to C |
|---------------|---------------|---------------|
| IDOR (read) | PUT/DELETE on same endpoint | Full data manipulation |
| SSRF (any) | Cloud metadata 169.254.169.254 | IAM cred exfil → RCE |
| XSS (stored) | HttpOnly cookie check | Session hijack → ATO |
| Open redirect | OAuth redirect_uri | Auth code theft → ATO |
| S3 bucket listing | JS bundles in bucket | OAuth secrets → chain |
| Rate limit bypass | OTP brute force | Account takeover |
| GraphQL introspection | Missing field auth | Mass PII exfil |
| Prompt injection | IDOR via chatbot | Data exfil via AI |

### Cluster Hunt Protocol

```
1. CONFIRM A     — Verify with real HTTP request
2. MAP SIBLINGS  — Find all endpoints in same controller/module
3. TEST SIBLINGS — Apply same bug pattern to every sibling
4. CHAIN         — If sibling has different bug class, combine A + B
5. QUANTIFY      — "Affects N users" / "exposes $X" / "N records"
6. REPORT        — One report per chain (chains pay 3-10x more)
```

---

## PHASE 6: VALIDATION (7-Question Gate)

All 7 must be YES. One NO → KILL the finding.

### Q1: Can I exploit this RIGHT NOW with a working PoC?
Write the exact HTTP request. If you can't → KILL IT.

### Q2: Does it affect a REAL user who took NO unusual actions?
No "the user would need to..." with 5 preconditions.

### Q3: Is the impact concrete (money, PII, ATO, RCE)?
"Technically possible" is NOT impact.

### Q4: Is this in scope per the program policy?
Check exact domain/endpoint against scope page.

### Q5: Did I check for duplicates?
Search Hacktivity, changelog, GitHub issues.

### Q6: Is this NOT on the "always rejected" list?
See Never Submit list. If it's there without a chain → KILL IT.

### Q7: Would a triager say "yes, that's a real bug"?
Read your report as a tired triager at 5pm Friday.

---

## PHASE 7: REPORT GENERATION

### Title Formula

```
[Bug Class] in [Exact Endpoint] allows [attacker role] to [impact] [victim scope]
```

### Report Structure (Platform-Agnostic)

```markdown
## Summary
[2-3 sentences: what, where, what attacker can do]

## Steps To Reproduce
1. Setup: [accounts needed]
2. Request: [exact HTTP request — copy-paste ready]
3. Observe: [exact response showing the bug]
4. Confirm: [what the attacker gained]

## Impact
An attacker can [specific action] resulting in [specific harm].
[Quantify: "Affects N users" / "Exposes $X"]

## CVSS 3.1
Score: X.X ([Severity]) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

## Recommended Fix
[1-2 sentences of concrete fix with code snippet]

## Supporting Material
[Screenshot / video / Burp request-response]
```

### Pre-Submit Checklist (60 seconds)

```
[ ] Title follows formula
[ ] First sentence = exact impact in plain English
[ ] Steps have exact HTTP request (copy-paste ready)
[ ] Response showing bug is included
[ ] Two test accounts used
[ ] CVSS score calculated
[ ] Fix is 1 sentence (not a lecture)
[ ] No typos in endpoint paths
[ ] Report < 600 words
[ ] Severity matches impact described
[ ] Never used "could potentially" or "may allow"
```

---

## ASSESSMENT OUTPUT STRUCTURE

```
assessments/TARGET/
├── recon/
│   ├── subs.txt         # Subdomains
│   ├── live.txt         # Live hosts with tech stack
│   └── urls.txt         # All URLs
├── sast/
│   ├── semgrep-security.json
│   ├── semgrep-owasp.json
│   ├── secrets.txt      # Verified secrets
│   ├── gitleaks.json
│   ├── dangerous-functions.txt
│   ├── security-todos.txt
│   └── auth-checks.txt
├── dast/
│   ├── nuclei.txt       # Template scan results
│   ├── dirs.json        # Directory fuzzing
│   └── xss.txt          # XSS scan results
├── findings/
│   ├── finding-001.md   # Each confirmed finding
│   └── chains.md        # Chain documentation
└── reports/
    └── final-report.md  # Submission-ready report
```

---

## ANTI-PATTERNS — STOP DOING THESE

```
Scanning without understanding the app (tool spray)
Spending 2 hours on a single 403 endpoint
Reporting DNS-only SSRF
Reporting alert(1) XSS without cookie theft
Reporting introspection alone
Reporting "missing headers" — always rejected
Writing report before confirming exploit works
Saying "could potentially" in any report
Ignoring business logic because there's no scanner for it
```

---

## RESOURCES

| Resource | Use |
|----------|-----|
| [PortSwigger Academy](https://portswigger.net/web-security) | Free vuln labs |
| [HackTricks](https://book.hacktricks.xyz) | Attack technique reference |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Payload database |
| [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) | Methodology reference |
| [SecLists](https://github.com/danielmiessler/SecLists) | Wordlists |

---

## INSTALLATION

```bash
# Add to Claude Code skills
mkdir -p ~/.claude/skills/apex-pipeline
cp SKILL.md ~/.claude/skills/apex-pipeline/SKILL.md

# Or link from repo
ln -s $(pwd)/skills/apex-pipeline/SKILL.md ~/.claude/skills/apex-pipeline/SKILL.md
```

Then use in Claude Code: ask about "app security testing", "full security assessment", "test this app", or "audit this application".
