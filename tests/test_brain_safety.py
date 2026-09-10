"""Unit tests for brain.py safety guardrails against destructive command execution (OWASP LLM08)."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from brain import Brain


class TestBrainCommandSafety:
    """Test LLM output command validation."""

    def test_safe_commands_allowed(self):
        safe, _ = Brain.is_safe_command("curl -s https://example.com/api")
        assert safe is True

        safe, _ = Brain.is_safe_command("cat findings.json | jq .")
        assert safe is True

        safe, _ = Brain.is_safe_command("python3 tools/oracle.py --check")
        assert safe is True

    def test_blocks_destructive_rm_root(self):
        safe, reason = Brain.is_safe_command("rm -rf /")
        assert safe is False
        assert "deletion" in reason.lower()

        safe, reason = Brain.is_safe_command("rm -r ~")
        assert safe is False

    def test_blocks_fork_bomb(self):
        safe, reason = Brain.is_safe_command(":(){ :|:& };:")
        assert safe is False
        assert "fork bomb" in reason.lower()

    def test_blocks_raw_disk_overwrite(self):
        safe, reason = Brain.is_safe_command("echo test > /dev/sda")
        assert safe is False

    def test_blocks_mkfs(self):
        safe, reason = Brain.is_safe_command("mkfs.ext4 /dev/sdb1")
        assert safe is False
