"""Unit tests for tools/cve_hunter.py — Domain validation, safe subprocesses, and CVE parsing."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from cve_hunter import validate_domain, run_cmd, search_cves


class TestDomainValidation:
    """Test domain format validator against valid domains and malicious inputs."""

    def test_valid_apex_domain(self):
        assert validate_domain("example.com") == "example.com"
        assert validate_domain("target.org") == "target.org"

    def test_valid_subdomains(self):
        assert validate_domain("api.example.com") == "api.example.com"
        assert validate_domain("dev.staging.corp.internal.co.uk") == "dev.staging.corp.internal.co.uk"

    def test_strips_protocol_and_trailing_paths(self):
        assert validate_domain("https://example.com/api/v1") == "example.com"
        assert validate_domain("http://sub.example.com:8080/test") == "sub.example.com"

    def test_rejects_command_injection_semicolon(self):
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("example.com; rm -rf /")

    def test_rejects_command_injection_quotes(self):
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain('example.com" && whoami')

    def test_rejects_command_injection_backticks(self):
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("`cat /etc/passwd`.example.com")

    def test_rejects_command_injection_subshell(self):
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("$(id).example.com")

    def test_rejects_path_traversal(self):
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("../../etc/passwd")

    def test_rejects_empty_or_none(self):
        with pytest.raises(ValueError):
            validate_domain("")
        with pytest.raises(ValueError):
            validate_domain(None)


class TestSafeCommandExecution:
    """Test run_cmd executing commands safely as lists without shell."""

    def test_run_cmd_list_echo(self):
        success, out = run_cmd(["echo", "sentinel_safe_test"])
        assert success is True
        assert "sentinel_safe_test" in out

    def test_run_cmd_handles_missing_binary(self):
        success, err = run_cmd(["non_existent_binary_xyz_123"])
        assert success is False
