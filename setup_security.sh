#!/bin/bash
# Local Security Setup Script for Contributors

set -e

echo "=== Sentinel AI Offensive: Contributor Security Setup ==="
echo "Configuring local environment to meet L99 security standards..."
echo ""

# 1. Enforce commit signing locally for this repository
echo "[*] Enforcing Git Commit Signing..."
git config commit.gpgsign true
echo "  ✅ Commit signing set to true for this local repository."
echo "     Note: If you don't have a GPG or SSH key configured with your Git account,"
echo "     commits will fail until you generate and add one to your GitHub profile."
echo ""

# 2. Add a pre-commit hook to block secrets (basic check)
echo "[*] Installing pre-commit secret scanning hook..."
HOOK_DIR=".git/hooks"
HOOK_FILE="$HOOK_DIR/pre-commit"

if [ -d "$HOOK_DIR" ]; then
    cat << 'EOF' > "$HOOK_FILE"
#!/bin/bash
# Pre-commit hook to catch hardcoded secrets
echo "Running pre-commit secret scan..."

PATTERNS=("AKIA[0-9A-Z]{16}" "ghp_[a-zA-Z0-9]{36}" "sk-[a-zA-Z0-9]{48}" "-----BEGIN.*PRIVATE KEY-----")

for pattern in "${PATTERNS[@]}"; do
    if git diff --cached -G"$pattern" --name-only | grep -q ".*"; then
        echo "❌ ERROR: Detected potential hardcoded secret matching pattern '$pattern'"
        echo "   Commit rejected. Please remove the secret and try again."
        exit 1
    fi
done
echo "✅ Secret scan passed."
exit 0
EOF
    chmod +x "$HOOK_FILE"
    echo "  ✅ Pre-commit hook installed to block basic secret patterns."
else
    echo "  ⚠️ Warning: .git/hooks directory not found. Are you in a git repository?"
fi
echo ""

echo "=== Setup Complete ==="
echo "Ensure you have uploaded your GPG or SSH public key to your GitHub account"
echo "and enabled 'Vigilant mode' in your GitHub SSH and GPG keys settings."
