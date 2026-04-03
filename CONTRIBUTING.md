# Contributing to Sentinel AI Offensive

Thank you for your interest in contributing! This guide covers our workflow, standards, and requirements.

---

## Getting Started

```bash
# 1. Fork the repository
# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/sentinel-ai-offensive.git
cd sentinel-ai-offensive

# 3. Create a feature branch
git checkout -b feature/your-contribution

# 4. Install dependencies
chmod +x install.sh && ./install.sh
bash install_tools.sh

# 5. Set up local security controls (Commit Signing Hooks)
chmod +x setup_security.sh && ./setup_security.sh

# 6. Run tests to verify setup
python3 -m pytest tests/ -v
```

---

## What We're Looking For

### High-Impact Contributions

| Type | Examples |
|:---|:---|
| **New vulnerability scanners** | Detection modules for emerging vuln classes |
| **Payload additions** | New bypass techniques, WAF evasion payloads |
| **Agent definitions** | Platform-specific agents (YesWeHack, Synack, HackenProof) |
| **Methodology improvements** | Real-world techniques backed by paid reports |
| **Skill domain expansion** | New SKILL.md files for uncovered areas |
| **Test coverage** | Unit tests, integration tests, edge case tests |
| **Documentation** | Technique guides, tool comparisons, workflow improvements |

### Before You Start

- Check [Issues](https://github.com/mlvpatel/sentinel-ai-offensive/issues) for existing discussions
- For major changes, open an issue first to discuss the approach
- Read `ARCHITECTURE.md` to understand the system design
- Review `SECURITY.md` for security requirements

---

## Development Standards

### Code Style

**Python:**
- Follow PEP 8
- Type hints for function signatures
- Docstrings for all public functions
- No `eval()`, `exec()`, or dynamic code execution on untrusted input

**Shell:**
- Use `set -e` at the top of scripts
- Quote all variable expansions
- Use `shellcheck` for linting

**Markdown (Skills/Commands/Agents):**
- YAML frontmatter required for SKILL.md files
- Use tables for structured data
- Include code examples for all techniques

### Security Requirements

Every contribution must pass the security checklist:

```
[ ] No hardcoded API keys, tokens, or credentials
[ ] Commits are digitally signed (GPG or SSH)
[ ] All outbound requests use scope_checker.py
[ ] All outbound requests logged via audit_log.py
[ ] All data entries validated via schemas.py
[ ] Error messages do not leak internal paths
[ ] Tests cover both happy path and adversarial input
```

### Testing

```bash
# Run full test suite
python3 -m pytest tests/ -v

# Run specific test file
python3 -m pytest tests/test_your_module.py -v

# Run with coverage
python3 -m pytest tests/ --cov=memory --cov=tools -v
```

**Test requirements:**
- New features must include tests
- Bug fixes should include a regression test
- Maintain or improve existing coverage

---

## Contribution Types

### Adding a New Skill

1. Create `skills/your-skill-name/SKILL.md`
2. Include YAML frontmatter: `name` and `description`
3. Structure: checklists → commands → decision trees → examples
4. Update `CLAUDE.md` skill table
5. Update `README.md` skill domains section

### Adding a New Command

1. Create `commands/your-command.md`
2. Define: trigger, arguments, agent routing, output format
3. Update `CLAUDE.md` commands table

### Adding a New Agent

1. Create `agents/your-agent.md`
2. Define: model tier, allowed tools, task scope, output format
3. Reference from relevant commands

### Adding a New Tool

1. Create `tools/your_tool.py` (or `.sh`)
2. Integrate: scope checker + audit log + schema validation
3. Add tests: `tests/test_your_tool.py`
4. Update `install_tools.sh` if external dependencies needed

---

## Pull Request Process

### Branch Naming

```
feature/description     New features
fix/description         Bug fixes
docs/description        Documentation updates
test/description        Test additions
security/description    Security improvements
```

### Commit Messages

```
Add: short description          New features
Fix: short description          Bug fixes
Update: short description       Updates to existing features
Remove: short description       Removing code/files
Docs: short description         Documentation only
Test: short description         Test additions
Security: short description     Security improvements
```

### PR Template

```markdown
## What

Brief description of the change.

## Why

Motivation for the change.

## How

Technical approach taken.

## Testing

- [ ] All existing tests pass
- [ ] New tests added for new functionality
- [ ] Security checklist verified
- [ ] Documentation updated

## Screenshots / Evidence

(If applicable — PoC output, test results, etc.)
```

### Review Process

1. Submit PR against `main` branch
2. At least 1 reviewer approval required
3. All tests must pass
4. Security checklist must be verified
5. Squash merge preferred for clean history

---

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

---

## Legal

### Ethical Use Requirement

All contributions must be designed for **authorized security testing only**:
- Bug bounty programs with explicit authorization
- Penetration testing with written permission
- Security research within responsible disclosure guidelines
- Educational purposes

Contributions that facilitate unauthorized access or malicious use will be rejected.

### License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

<div align="center">

**Questions?** Open an [issue](https://github.com/mlvpatel/sentinel-ai-offensive/issues) or reach out to [@mlvpatel](https://github.com/mlvpatel).

</div>
