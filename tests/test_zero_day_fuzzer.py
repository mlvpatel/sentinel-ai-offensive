"""Unit tests for tools/zero_day_fuzzer.py — Safe curl execution and logic flaw checks."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from zero_day_fuzzer import run_cmd, curl_request


class TestZeroDayFuzzerExecution:
    """Test safe command execution without shell=True."""

    def test_run_cmd_safe_list(self):
        success, stdout, stderr = run_cmd(["echo", "zero_day_safe"])
        assert success is True
        assert "zero_day_safe" in stdout

    def test_curl_request_constructs_safe_arguments(self, monkeypatch):
        captured_cmd = []

        def mock_run_cmd(cmd, timeout=15):
            captured_cmd.extend(cmd)
            # Return dummy HTTP response headers and body
            return True, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK", ""

        monkeypatch.setattr("zero_day_fuzzer.run_cmd", mock_run_cmd)

        url = 'https://example.com/api?param=";whoami;&other=val'
        headers = {"X-Custom": "test;echo injection", "Authorization": "Bearer tok"}
        status, resp_headers, body = curl_request(url, method="POST", headers=headers, data="foo=bar&baz=1")

        assert status == 200
        assert "OK" in body
        # Ensure arguments were passed as separate items without shell expansion
        assert url in captured_cmd
        assert "POST" in captured_cmd
        assert "-H" in captured_cmd
        assert "X-Custom: test;echo injection" in captured_cmd
