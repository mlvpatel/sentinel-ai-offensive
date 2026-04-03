---
name: code-reaper
description: Static Application Security Testing (SAST) — deep source code analysis for vulnerability detection. Covers 12 languages (JavaScript/TypeScript, Python, PHP, Go, Ruby, Rust, Java, C#, Solidity, Kotlin, Swift, Dart). Automated scanning (Semgrep rulesets, Gitleaks, Trufflehog), manual pattern hunting (dangerous sinks, auth inconsistency, injection vectors), taint analysis (source→sink tracing), auth architecture audit (middleware gaps, IDOR patterns, privilege escalation), secret detection (API keys, tokens, credentials), dependency analysis (known CVEs in packages), and framework-specific vulnerability patterns. Generates prioritized findings with exploitability assessment. Use when asked to "review this code", "audit source code", "find vulnerabilities in code", "static analysis", "code security review", "SAST scan", or when source code is available for a target.
---

# SAST — Static Application Security Testing

Deep source code analysis. Find bugs that scanners miss by understanding code flow, auth patterns, and developer psychology.

---

## THE SAST MINDSET

> **SAST is not "run a tool and read output." It's understanding HOW the code works, WHERE trust boundaries exist, and WHAT happens when assumptions break.**

### Three Questions Before Every SAST Engagement

1. **"Where does user input enter the system?"** → Sources (HTTP params, headers, files, WebSocket, env vars)
2. **"Where does dangerous processing happen?"** → Sinks (SQL queries, exec(), template rendering, file I/O)
3. **"What stands between source and sink?"** → Sanitizers (validation, encoding, parameterization)

If source reaches sink without adequate sanitizer → **VULNERABILITY**.

---

## PHASE 1: CODEBASE RECONNAISSANCE (5 min)

### 1A: Technology Stack & Architecture

```bash
# Detect languages & frameworks
find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.go" \
  -o -name "*.rb" -o -name "*.php" -o -name "*.java" -o -name "*.rs" \
  -o -name "*.cs" -o -name "*.kt" -o -name "*.sol" -o -name "*.swift" \) \
  | grep -v node_modules | grep -v vendor | grep -v __pycache__ | grep -v .git \
  | sed 's/.*\.//' | sort | uniq -c | sort -rn

# Count lines of code per language
find . -type f -name "*.py" | grep -v node_modules | xargs wc -l 2>/dev/null | tail -1
find . -type f -name "*.js" -o -name "*.ts" | grep -v node_modules | xargs wc -l 2>/dev/null | tail -1

# Detect package manager & dependencies
ls package.json requirements.txt Pipfile Gemfile go.mod Cargo.toml composer.json pom.xml build.gradle 2>/dev/null

# Detect framework
grep -l "express\|koa\|fastify\|hapi" package.json 2>/dev/null && echo "Node.js framework detected"
grep -l "django\|flask\|fastapi\|tornado" requirements.txt Pipfile 2>/dev/null && echo "Python framework detected"
grep -l "laravel\|symfony\|slim" composer.json 2>/dev/null && echo "PHP framework detected"
grep -l "gin\|echo\|fiber\|chi" go.mod 2>/dev/null && echo "Go framework detected"
grep -l "rails\|sinatra" Gemfile 2>/dev/null && echo "Ruby framework detected"
grep -l "spring" pom.xml build.gradle 2>/dev/null && echo "Java/Spring detected"
```

### 1B: Security-Relevant File Discovery

```bash
# Configuration files (often contain secrets or misconfigs)
find . -name ".env*" -o -name "config*.json" -o -name "config*.yml" \
  -o -name "secrets*" -o -name "credentials*" -o -name "*.pem" -o -name "*.key" \
  2>/dev/null | grep -v node_modules

# Auth-related files
find . -type f | grep -viE "node_modules|vendor|test|spec|__pycache__|\.git" \
  | xargs grep -liE "authenticate|authorize|login|session|jwt|oauth|token|permission|role|acl" 2>/dev/null \
  | head -30

# Route definitions
find . -type f | grep -viE "node_modules|vendor|test|spec|__pycache__|\.git" \
  | xargs grep -liE "router\.|app\.(get|post|put|delete)|@app\.route|Route::|@GetMapping|@PostMapping" 2>/dev/null \
  | head -30

# Database interaction files
find . -type f | grep -viE "node_modules|vendor|test|spec|__pycache__|\.git" \
  | xargs grep -liE "query|execute|find|select|insert|update|delete|\.where|\.raw" 2>/dev/null \
  | head -30
```

### 1C: Git History Security Audit

```bash
# Security-related commits
git log --oneline --all -30 | grep -iE "security|fix|CVE|vuln|patch|auth|xss|sqli|ssrf|csrf|inject"

# Recently changed auth/security files
git log --name-only --since="30 days ago" --pretty=format:"" \
  | sort -u | grep -iE "auth|security|middleware|permission|token|session" | head -20

# Developer breadcrumbs in commit messages
git log --oneline -50 | grep -iE "TODO|FIXME|HACK|temp|workaround|disable|skip"

# Secrets that were committed then removed
git log --all --diff-filter=D -- "*.env" "*.pem" "*.key" "credentials*" "secrets*" 2>/dev/null | head -10
```

---

## PHASE 2: AUTOMATED SCANNING (15 min)

### 2A: Semgrep — Rule-Based Static Analysis

```bash
# Install
pip3 install semgrep 2>/dev/null

# ═══════════════════════════════════════════
# TIER 1: Broad Security Audit (run first)
# ═══════════════════════════════════════════
semgrep --config=p/security-audit ./ --json -o /tmp/sast-security-audit.json 2>/dev/null
semgrep --config=p/owasp-top-ten ./ --json -o /tmp/sast-owasp.json 2>/dev/null

# ═══════════════════════════════════════════
# TIER 2: Language-Specific (run for detected languages)
# ═══════════════════════════════════════════

# JavaScript / TypeScript
semgrep --config=p/javascript ./ --json -o /tmp/sast-js.json 2>/dev/null
semgrep --config=p/typescript ./ --json -o /tmp/sast-ts.json 2>/dev/null
semgrep --config=p/nodejs ./ --json -o /tmp/sast-node.json 2>/dev/null
semgrep --config=p/react ./ --json -o /tmp/sast-react.json 2>/dev/null
semgrep --config=p/nextjs ./ --json -o /tmp/sast-nextjs.json 2>/dev/null

# Python
semgrep --config=p/python ./ --json -o /tmp/sast-python.json 2>/dev/null
semgrep --config=p/django ./ --json -o /tmp/sast-django.json 2>/dev/null
semgrep --config=p/flask ./ --json -o /tmp/sast-flask.json 2>/dev/null

# PHP
semgrep --config=p/php ./ --json -o /tmp/sast-php.json 2>/dev/null
semgrep --config=p/laravel ./ --json -o /tmp/sast-laravel.json 2>/dev/null

# Go
semgrep --config=p/golang ./ --json -o /tmp/sast-go.json 2>/dev/null

# Java
semgrep --config=p/java ./ --json -o /tmp/sast-java.json 2>/dev/null
semgrep --config=p/spring ./ --json -o /tmp/sast-spring.json 2>/dev/null

# Ruby
semgrep --config=p/ruby ./ --json -o /tmp/sast-ruby.json 2>/dev/null
semgrep --config=p/rails ./ --json -o /tmp/sast-rails.json 2>/dev/null

# Rust
semgrep --config=p/rust ./ --json -o /tmp/sast-rust.json 2>/dev/null

# Solidity (Web3)
semgrep --config=p/solidity ./ --json -o /tmp/sast-sol.json 2>/dev/null

# ═══════════════════════════════════════════
# TIER 3: Targeted Vulnerability Rules
# ═══════════════════════════════════════════
semgrep --config=p/sql-injection ./ --json -o /tmp/sast-sqli.json 2>/dev/null
semgrep --config=p/xss ./ --json -o /tmp/sast-xss.json 2>/dev/null
semgrep --config=p/jwt ./ --json -o /tmp/sast-jwt.json 2>/dev/null
semgrep --config=p/command-injection ./ --json -o /tmp/sast-cmdi.json 2>/dev/null
semgrep --config=p/insecure-transport ./ --json -o /tmp/sast-transport.json 2>/dev/null
semgrep --config=p/secrets ./ --json -o /tmp/sast-secrets.json 2>/dev/null

# ═══════════════════════════════════════════
# PARSE RESULTS — Extract critical findings
# ═══════════════════════════════════════════
for f in /tmp/sast-*.json; do
  COUNT=$(cat "$f" 2>/dev/null | jq '.results | length' 2>/dev/null)
  [ "$COUNT" -gt 0 ] 2>/dev/null && echo "$(basename $f .json): $COUNT findings"
done

# Show critical + high severity findings
for f in /tmp/sast-*.json; do
  cat "$f" 2>/dev/null | jq -r '.results[] | select(.extra.severity == "ERROR") |
    "\(.extra.severity) | \(.path):\(.start.line) | \(.check_id) | \(.extra.message)"' 2>/dev/null
done | sort -u | head -50
```

### 2B: Custom Semgrep Patterns (High-Signal)

```bash
# SQL string concatenation in Python
semgrep --pattern 'cursor.execute("..." + $X)' --lang python . 2>/dev/null
semgrep --pattern 'cursor.execute(f"...$X...")' --lang python . 2>/dev/null

# Unsanitized template rendering
semgrep --pattern 'render_template_string($X)' --lang python . 2>/dev/null
semgrep --pattern 'res.render($TEMPLATE, {..., $KEY: req.$SOURCE})' --lang javascript . 2>/dev/null

# Dangerous deserialization
semgrep --pattern 'pickle.loads($X)' --lang python . 2>/dev/null
semgrep --pattern 'yaml.load($X)' --lang python . 2>/dev/null
semgrep --pattern 'JSON.parse(req.$X)' --lang javascript . 2>/dev/null

# Missing auth check pattern (Express)
semgrep --pattern 'router.$METHOD($PATH, $HANDLER)' --lang javascript . 2>/dev/null \
  | grep -v "auth\|middleware\|protect\|verify"

# eval() with user input
semgrep --pattern 'eval($X)' --lang javascript . 2>/dev/null
semgrep --pattern 'eval($X)' --lang python . 2>/dev/null
```

### 2C: Secret Scanning (Automated)

```bash
# Trufflehog — ONLY verified secrets (no false positives)
trufflehog filesystem --only-verified ./ 2>/dev/null | tee /tmp/sast-verified-secrets.txt

# Trufflehog — Git history (finds deleted secrets)
trufflehog git file://. --only-verified 2>/dev/null | tee /tmp/sast-git-secrets.txt

# Gitleaks — comprehensive pattern matching
gitleaks detect --source . --report-path /tmp/sast-gitleaks.json --report-format json 2>/dev/null

# Manual high-value secret patterns
echo "=== AWS Keys ==="
grep -rn "AKIA[0-9A-Z]\{16\}" . --include="*.js" --include="*.ts" --include="*.py" --include="*.env" --include="*.json" | grep -v node_modules | grep -v ".git"

echo "=== Private Keys ==="
grep -rn "BEGIN.*PRIVATE KEY" . | grep -v node_modules | grep -v ".git" | grep -v test

echo "=== API Keys / Tokens ==="
grep -rn "sk-[a-zA-Z0-9]\{20,\}" . | grep -v node_modules | grep -v ".git"  # OpenAI
grep -rn "ghp_[a-zA-Z0-9]\{36\}" . | grep -v node_modules | grep -v ".git"  # GitHub PAT
grep -rn "xox[bps]-[a-zA-Z0-9-]\{10,\}" . | grep -v node_modules | grep -v ".git"  # Slack

echo "=== Hardcoded Passwords ==="
grep -rn "password\s*[:=]\s*['\"][^'\"]\{4,\}['\"]" . \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.rb" --include="*.php" \
  | grep -viE "test|example|placeholder|PASSWORD_HERE|changeme|node_modules|\.git" | head -20

echo "=== Database Connection Strings ==="
grep -rn "mongodb://\|postgres://\|mysql://\|redis://\|amqp://" . \
  | grep -v node_modules | grep -v ".git" | grep -v test | head -10
```

### 2D: Dependency Vulnerability Scan

```bash
# npm / Node.js
npm audit --json 2>/dev/null | jq '.vulnerabilities | to_entries[] | select(.value.severity == "critical" or .value.severity == "high") | {name:.key, severity:.value.severity, via:.value.via[0]}' 2>/dev/null

# Python (pip-audit)
pip-audit --format json 2>/dev/null | jq '.[] | select(.fix_versions != []) | {name:.name, version:.version, vuln:.id}' 2>/dev/null

# Go
govulncheck ./... 2>/dev/null

# Ruby
bundle audit check 2>/dev/null

# PHP
composer audit --format=json 2>/dev/null
```

---

## PHASE 3: MANUAL PATTERN HUNTING (20 min)

> **This is where human skill beats automation.** Scanners find syntax patterns. Humans find logic bugs, auth gaps, and developer shortcuts.

### 3A: Injection Sinks — Language by Language

#### JavaScript / TypeScript

```bash
# XSS sinks
grep -rn "innerHTML\|outerHTML\|document\.write\|dangerouslySetInnerHTML" \
  --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" \
  | grep -v node_modules | grep -v test

# DOM XSS — user-controlled data flowing to dangerous APIs
grep -rn "location\.hash\|location\.search\|document\.referrer\|window\.name" \
  --include="*.js" --include="*.ts" | grep -v node_modules

# Command injection
grep -rn "child_process\|execSync\|exec(\|spawn(\|execFile(" \
  --include="*.js" --include="*.ts" | grep -v node_modules | grep -v test

# Prototype pollution
grep -rn "__proto__\|constructor\[" --include="*.js" --include="*.ts" | grep -v node_modules
grep -rn "Object\.assign\|\.extend(\|merge(\|deepMerge\|lodash\.merge\|_.merge" \
  --include="*.js" --include="*.ts" | grep -v node_modules

# SQL injection (string concatenation in queries)
grep -rn "\.query(\|\.execute(\|\.raw(" --include="*.js" --include="*.ts" \
  | grep -v node_modules | grep -E "\+|template|concat|\$\{"

# SSRF — fetching user-supplied URLs
grep -rn "fetch(\|axios\.\(get\|post\)\|request(\|got(\|urllib" \
  --include="*.js" --include="*.ts" | grep -v node_modules \
  | grep "req\.\|params\.\|query\.\|body\.\|args\.\|input"

# PostMessage (DOM-based attacks)
grep -rn "postMessage\|addEventListener.*message" --include="*.js" --include="*.ts" \
  | grep -v node_modules

# Insecure randomness
grep -rn "Math\.random\(\)" --include="*.js" --include="*.ts" \
  | grep -vi "test\|node_modules" \
  | grep -i "token\|key\|secret\|password\|nonce\|salt\|id\|session"
```

#### Python

```bash
# SQL injection
grep -rn "execute(\|executemany(\|raw(" --include="*.py" \
  | grep -v test | grep -v __pycache__ \
  | grep -E "\+|format\(|f\"|%s|%d|\.format"

# Command injection
grep -rn "subprocess\|os\.system\|os\.popen\|commands\.getoutput" --include="*.py" \
  | grep -v test | grep -v __pycache__

# Dangerous deserialization
grep -rn "pickle\.loads\|pickle\.load\|yaml\.load[^_]\|yaml\.unsafe_load" --include="*.py" \
  | grep -v test
grep -rn "marshal\.loads\|shelve\.open" --include="*.py" | grep -v test

# SSTI
grep -rn "render_template_string\|Template(\|Markup(\|mark_safe\|safe" --include="*.py" \
  | grep -v test

# Path traversal
grep -rn "open(\|os\.path\.join\|send_file\|send_from_directory" --include="*.py" \
  | grep -v test | grep "request\.\|params\.\|args\.\|input"

# eval/exec
grep -rn "eval(\|exec(\|compile(\|__import__(" --include="*.py" | grep -v test

# Weak crypto
grep -rn "md5\|sha1\|DES\|RC4\|ECB" --include="*.py" \
  | grep -vi "test\|checksum\|etag\|hash_name\|spec"
```

#### PHP

```bash
# SQL injection
grep -rn "mysql_query\|mysqli_query\|->query(" --include="*.php" \
  | grep "\$_\|\..*\$\|concat\|\".*\.\""

# Type juggling (== instead of ===)
grep -rn "\s==\s" --include="*.php" | grep -i "password\|token\|hash\|secret\|key\|admin"

# Deserialization
grep -rn "unserialize(\|json_decode(" --include="*.php" | grep "\$_"

# LFI / Path traversal
grep -rn "include(\|require(\|include_once(\|require_once(\|file_get_contents(" \
  --include="*.php" | grep "\$_GET\|\$_POST\|\$_REQUEST"

# Command injection
grep -rn "system(\|exec(\|shell_exec(\|passthru(\|popen(\|proc_open(" \
  --include="*.php" | grep "\$_"

# eval
grep -rn "eval(\|assert(\|preg_replace.*e'" --include="*.php" | grep "\$_"
```

#### Go

```bash
# Template injection (unescaped output)
grep -rn "template\.HTML\|template\.JS\|template\.URL\|template\.CSS" --include="*.go"

# SQL injection
grep -rn "fmt\.Sprintf.*SELECT\|fmt\.Sprintf.*INSERT\|fmt\.Sprintf.*UPDATE\|fmt\.Sprintf.*DELETE" \
  --include="*.go"
grep -rn "db\.Query(\|db\.Exec(\|db\.QueryRow(" --include="*.go" | grep "fmt\.\|Sprintf\|\+"

# Command injection
grep -rn "exec\.Command(\|os\.StartProcess" --include="*.go" | grep -v test

# Race conditions
grep -rn "go func\|sync\.Mutex\|sync\.RWMutex\|atomic\." --include="*.go" | head -20

# Path traversal
grep -rn "filepath\.Join\|os\.Open\|os\.ReadFile\|ioutil\.ReadFile" --include="*.go" \
  | grep "r\.URL\|r\.Form\|mux\.Vars\|c\.Param\|c\.Query"
```

#### Ruby

```bash
# Mass assignment
grep -rn "attr_accessible\|permit(\|params\[" --include="*.rb" | grep -v test

# Deserialization
grep -rn "YAML\.load[^_]\|Marshal\.load\|JSON\.parse" --include="*.rb" | grep -v test

# Command injection
grep -rn "system(\|exec(\|`.*#\{" --include="*.rb" | grep -v test

# SQL injection
grep -rn "\.where(\|\.find_by_sql(\|\.execute(" --include="*.rb" | grep -E "#\{|concat|\+"

# Unsafe redirect
grep -rn "redirect_to.*params\[" --include="*.rb"
```

#### Rust

```bash
# Panic on network input (DoS)
grep -rn "\.unwrap()\|\.expect(" --include="*.rs" \
  | grep -v "test\|encode\|to_bytes\|serialize\|Display\|format"

# Unsafe blocks near network handling
grep -rn "unsafe {" --include="*.rs" -A10 | grep "read\|recv\|parse\|decode\|deserialize"

# Integer overflow (unchecked casts)
grep -rn "as u8\|as u16\|as u32\|as u64\|as usize\|as i8\|as i16\|as i32" --include="*.rs" \
  | grep -v "checked\|saturating\|wrapping\|test"

# Skipped verification
grep -rn "if let Ok\|let _ =" --include="*.rs" \
  | grep -i "verify\|sign\|cert\|auth\|validate\|check"

# TODO/FIXME near security code
grep -rn "TODO\|FIXME\|not signed\|not verified\|for now\|temporary" --include="*.rs" \
  | grep -i "sign\|verify\|cert\|auth\|encrypt\|token"
```

#### Java / Kotlin

```bash
# SQL injection
grep -rn "Statement\|createStatement\|executeQuery\|executeUpdate" --include="*.java" --include="*.kt" \
  | grep -E "\+|concat|String\.format|\".*\+.*\"" | grep -v test

# Deserialization
grep -rn "ObjectInputStream\|readObject\|XMLDecoder\|XStream\|SnakeYAML\|Gson\.fromJson" \
  --include="*.java" --include="*.kt" | grep -v test

# Command injection
grep -rn "Runtime\.getRuntime\|ProcessBuilder\|exec(" \
  --include="*.java" --include="*.kt" | grep -v test

# SSTI / Expression Language
grep -rn "SpEL\|ExpressionParser\|parseExpression\|StandardEvaluationContext" \
  --include="*.java" --include="*.kt"

# XXE
grep -rn "XMLInputFactory\|DocumentBuilder\|SAXParser\|TransformerFactory" \
  --include="*.java" --include="*.kt" | grep -v "setFeature.*disallow\|setFeature.*false"

# Weak crypto
grep -rn "MD5\|SHA-1\|DESede\|\"DES\"\|\"RC4\"\|ECB" --include="*.java" --include="*.kt" \
  | grep -v test | grep -v "MessageDigest.*SHA-256\|SHA-384\|SHA-512"
```

#### Solidity (Smart Contracts)

```bash
# Reentrancy
grep -rn "\.call\{value\|\.call\.value\|\.transfer(\|\.send(" --include="*.sol"

# tx.origin (auth bypass)
grep -rn "tx\.origin" --include="*.sol"

# Delegatecall to untrusted contract
grep -rn "delegatecall\|staticcall" --include="*.sol"

# Unchecked math (pre-0.8.0)
grep -rn "pragma solidity" --include="*.sol" | grep -v "0\.8\.\|>=.*0\.8\."

# Selfdestruct
grep -rn "selfdestruct\|suicide" --include="*.sol"

# Block timestamp dependency
grep -rn "block\.timestamp\|block\.number\|block\.difficulty\|block\.prevrandao" --include="*.sol"
```

---

### 3B: Auth Architecture Audit (The Sibling Rule)

```bash
# THE SIBLING RULE: If 9 endpoints have auth middleware and the 10th doesn't, that's your bug.

# Step 1: Find all route definitions
grep -rn "app\.\(get\|post\|put\|delete\|patch\)\|router\.\(get\|post\|put\|delete\|patch\)" \
  --include="*.js" --include="*.ts" | grep -v node_modules | grep -v test \
  > /tmp/sast-all-routes.txt

# Step 2: Find authenticated routes
grep "auth\|middleware\|protect\|verify\|requireAuth\|isAuthenticated\|isAdmin\|checkRole" \
  /tmp/sast-all-routes.txt > /tmp/sast-auth-routes.txt

# Step 3: Find UNAUTHENTICATED routes (the gap)
grep -v "auth\|middleware\|protect\|verify\|requireAuth\|isAuthenticated\|isAdmin\|checkRole" \
  /tmp/sast-all-routes.txt > /tmp/sast-unauth-routes.txt

echo "=== ROUTES WITHOUT AUTH MIDDLEWARE ==="
cat /tmp/sast-unauth-routes.txt

echo ""
echo "=== COMPARE: Auth routes vs Unauth routes ==="
echo "Authenticated: $(wc -l < /tmp/sast-auth-routes.txt)"
echo "Unauthenticated: $(wc -l < /tmp/sast-unauth-routes.txt)"
```

### 3C: Timing Side-Channel Detection

```bash
# Timing-unsafe comparison (=== or == for secrets instead of timingSafeEqual)
grep -rn "===.*token\|===.*secret\|===.*hash\|===.*password\|===.*key\|===.*api_key" \
  --include="*.js" --include="*.ts" | grep -v node_modules | grep -v test

# Python: timing-unsafe comparison
grep -rn "==.*token\|==.*secret\|==.*hash\|==.*password" \
  --include="*.py" | grep -v test | grep -v "timingSafeEqual\|hmac\.compare_digest\|secrets\.compare_digest"

# Developer inconsistency: timingSafeEqual in ONE place, === elsewhere
echo "=== timingSafeEqual usage ==="
grep -rnl "timingSafeEqual\|hmac\.compare_digest\|constantTimeCompare\|MessageDigest\.isEqual" \
  . --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" \
  | grep -v node_modules 2>/dev/null

echo "=== Plain comparison near security code ==="
grep -rn "===\|==" --include="*.js" --include="*.ts" | grep -v node_modules \
  | grep -i "token\|secret\|hash\|hmac\|signature\|apikey\|api_key" | head -20
```

### 3D: Data Flow Tracing (Source → Sink Analysis)

```
SOURCES (where user input enters):
├── HTTP Request
│   ├── req.params / req.query / req.body
│   ├── req.headers (Host, X-Forwarded-For, Referer)
│   ├── req.cookies
│   └── req.files (uploaded files)
├── WebSocket messages
├── Environment variables (process.env)
├── Database reads (if data was tainted at write)
├── File reads (if user controls path)
└── External API responses (if attacker controls upstream)

SINKS (where dangerous processing happens):
├── DATABASE: cursor.execute(), db.query(), Model.where()
├── COMMAND: exec(), system(), spawn(), popen()
├── TEMPLATE: render_template_string(), innerHTML, dangerouslySetInnerHTML
├── FILE: open(), readFile(), writeFile(), sendFile()
├── NETWORK: fetch(), axios(), request(), http.get()
├── EVAL: eval(), Function(), setTimeout(string)
├── DESERIALIZE: pickle.loads(), yaml.load(), unserialize()
├── REDIRECT: res.redirect(), header("Location:")
└── CRYPTO: md5(), sha1(), Math.random() for secrets

SANITIZERS (what should stand between source and sink):
├── PARAMETERIZATION: prepared statements, ? placeholders
├── ENCODING: htmlEncode(), encodeURI(), escapeshellarg()
├── VALIDATION: joi.validate(), zod.parse(), regex whitelist
├── TYPE CHECKING: parseInt(), Boolean(), Number()
└── FRAMEWORK: ORM (prevents raw SQL), CSRF tokens, CSP headers
```

### Tracing Protocol

```
1. Find a SINK (dangerous function call)
2. Trace the variable BACKWARD to its SOURCE
3. Check every function in the path for SANITIZATION
4. If no sanitizer between source and sink → FINDING
5. Verify: can the attacker control the source value?
6. Rate: What's the worst outcome? (RCE > SQLi > XSS > Info Disclosure)
```

---

## PHASE 4: FRAMEWORK-SPECIFIC VULNERABILITY PATTERNS

### Express / Node.js

| Pattern | Risk | Grep |
|---------|------|------|
| Missing auth middleware on route | Auth bypass | Routes without `authenticate` middleware |
| `body-parser` without size limit | DoS | `app.use(bodyParser.json())` without `{limit: '1mb'}` |
| `res.redirect(req.query.url)` | Open redirect | `redirect.*req\.\(query\|params\|body\)` |
| Template rendering with user input | SSTI | `render.*req\.` |
| Missing CSRF on state-changing routes | CSRF | POST/PUT/DELETE routes without CSRF token check |

### Django / Flask

| Pattern | Risk | Grep |
|---------|------|------|
| `mark_safe()` with user data | XSS | `mark_safe.*request\.\|mark_safe.*user` |
| Missing `@login_required` | Auth bypass | View functions without decorator |
| `render_template_string()` | SSTI | `render_template_string` |
| Raw SQL queries | SQLi | `.raw(\|.extra(\|cursor\.execute.*%s` + no parameterization |
| `DEBUG = True` in production | Info leak | `DEBUG\s*=\s*True` |

### Laravel / PHP

| Pattern | Risk | Grep |
|---------|------|------|
| Missing `$fillable` or `$guarded` | Mass assignment | Models without `$fillable` or `$guarded` |
| `DB::raw()` with concatenation | SQLi | `DB::raw.*\$\|DB::raw.*concat` |
| Missing middleware on routes | Auth bypass | Routes without middleware in `routes/web.php` |
| `unserialize()` with user input | RCE | `unserialize.*\$_` |
| Loose comparison `==` for auth | Auth bypass | `==.*password\|==.*token` |

### Spring Boot / Java

| Pattern | Risk | Grep |
|---------|------|------|
| Exposed actuator endpoints | Info leak/RCE | `management.endpoints.web.exposure.include=*` |
| Missing `@PreAuthorize` | Auth bypass | Controller methods without auth annotation |
| SpEL injection | RCE | `parseExpression.*request\|StandardEvaluationContext` |
| XXE in XML processing | File read/SSRF | `DocumentBuilder` without DTD disabled |
| Thymeleaf SSTI | RCE | `__${...}__::` patterns |

### Ruby on Rails

| Pattern | Risk | Grep |
|---------|------|------|
| Open `permit!` or over-permissive params | Mass assign | `params\.permit!\|permit(.*:role\|:admin)` |
| Missing `before_action :authenticate` | Auth bypass | Controller actions without auth |
| `YAML.load()` (not `safe_load`) | RCE | `YAML\.load[^_]` |
| Unsafe redirect | Open redirect | `redirect_to.*params\[` |
| `render inline:` with user data | SSTI | `render.*inline.*params` |

---

## PHASE 5: FINDING PRIORITIZATION

### Severity Classification

| Severity | Criteria | Examples |
|----------|----------|---------|
| **Critical** | RCE, full DB access, admin bypass, mass ATO | eval() with user input, hardcoded admin creds, SQLi with no WAF |
| **High** | PII exfil, privilege escalation, partial RCE | IDOR on all users, SSTI in non-sandboxed template, verified leaked secrets |
| **Medium** | Auth gap on specific endpoint, limited data leak | Missing auth on one route, XSS in low-traffic page, weak crypto for tokens |
| **Low** | Info disclosure, best practice violation | Debug mode in non-prod config, verbose error messages, GET request with sensitive data |
| **Info** | No exploitable impact, defense-in-depth | Missing security headers, TODO comments, hardcoded test credentials |

### Exploitability Assessment

For each finding, answer:

```
1. Can an external attacker reach this code? [ ] Yes [ ] No (internal only) [ ] Maybe
2. Is user input the source?               [ ] Yes [ ] No (hardcoded/env) [ ] Indirect
3. Is there a sanitizer in the path?        [ ] None [ ] Weak [ ] Strong (bypass needed)
4. Is this the only control?               [ ] Yes [ ] No (defense in depth)
5. What's the worst outcome?               [ ] RCE [ ] Data leak [ ] Auth bypass [ ] DoS [ ] Info
```

### Output Template — SAST Finding

```markdown
## SAST-001: [Finding Title]

**Severity:** Critical / High / Medium / Low
**Category:** SQLi / XSS / RCE / Auth Bypass / IDOR / SSRF / Secrets / Crypto
**File:** path/to/file.py
**Line:** 42-48
**CWE:** CWE-XXX

### Description
[One paragraph: what the code does wrong, why it's vulnerable]

### Vulnerable Code
```language
// Line 42-48
vulnerable_code_here
```

### Data Flow
```
SOURCE: req.params.userId (line 38)
  → passes through function validateInput() (line 40) — NO SANITIZATION
  → reaches SINK: db.query("SELECT * FROM users WHERE id = " + userId) (line 45)
```

### Impact
[What can an attacker do? Be specific.]

### Proof of Concept
[Exact request or input that triggers the vulnerability]

### Recommended Fix
```language
// SECURE version
fixed_code_here
```
```

---

## SAST REPORT TEMPLATE

```markdown
# Static Application Security Testing Report

**Target:** [Application Name]
**Date:** [YYYY-MM-DD]
**Analyst:** [Name]
**Scope:** [Source code directories analyzed]

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |
| Info | X |

## Key Findings

### Finding 1: [Title]
[Use SAST Finding Template above]

### Finding 2: [Title]
[Use SAST Finding Template above]

## Methodology
- Automated scanning: Semgrep (security-audit, owasp-top-ten, language-specific)
- Secret scanning: Trufflehog (verified), Gitleaks
- Manual review: Injection sinks, auth architecture, data flow tracing
- Dependency audit: npm audit / pip-audit / govulncheck

## Recommendations
1. [Priority 1 fix]
2. [Priority 2 fix]
3. [Priority 3 fix]
```

---

## ANTI-PATTERNS — DON'T DO THESE

```
Running semgrep and reporting raw output without analysis
Flagging "missing security header" as a real finding
Reporting TODO comments as vulnerabilities
Ignoring context (eval() in test files is not exploitable)
Marking everything as "Critical" (lose credibility)
Skipping manual review because scanner found nothing
Ignoring the auth architecture (biggest source of real bugs)
Not tracing data flow from source to sink
Reporting hardcoded test credentials as real secrets
```

---

## INSTALLATION

```bash
# Prerequisites
pip3 install semgrep 2>/dev/null
brew install trufflehog gitleaks 2>/dev/null

# Add to Claude Code skills
mkdir -p ~/.claude/skills/code-reaper
cp SKILL.md ~/.claude/skills/code-reaper/SKILL.md
```

Then use in Claude Code: ask about "SAST", "static analysis", "code review", "audit this source code", or "find vulnerabilities in code".
