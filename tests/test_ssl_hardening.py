"""Security unit tests ensuring SSL contexts enforce TLS verification and disallow CERT_NONE."""

import pytest
import ssl
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp", "hackerone-mcp"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))


def test_hackerone_mcp_ssl_context_verification():
    import server as h1_server
    ctx = h1_server._SSL_CTX
    assert ctx.verify_mode != ssl.CERT_NONE, "HackerOne MCP SSL context must enforce certificate validation (CWE-295)"
    assert ctx.check_hostname is True, "HackerOne MCP SSL context must check hostnames (CWE-295)"


def test_validate_ssl_context_verification():
    import validate
    ctx = validate._SSL_CTX
    assert ctx.verify_mode != ssl.CERT_NONE, "validate.py SSL context must enforce certificate validation (CWE-295)"
    assert ctx.check_hostname is True, "validate.py SSL context must check hostnames (CWE-295)"


def test_learn_ssl_context_verification():
    import learn
    ctx = learn._SSL_CTX
    assert ctx.verify_mode != ssl.CERT_NONE, "learn.py SSL context must enforce certificate validation (CWE-295)"
    assert ctx.check_hostname is True, "learn.py SSL context must check hostnames (CWE-295)"
