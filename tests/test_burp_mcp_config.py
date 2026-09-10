"""Unit tests verifying MCP server configuration schemas."""

import json
from pathlib import Path


def test_burp_mcp_config_schema():
    burp_config_path = Path(__file__).resolve().parent.parent / "mcp" / "burp-mcp-client" / "config.json"
    assert burp_config_path.exists(), "mcp/burp-mcp-client/config.json must exist"

    with open(burp_config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "mcpServers" in data
    assert "burp" in data["mcpServers"]
    burp = data["mcpServers"]["burp"]
    assert "command" in burp
    assert "args" in burp
    assert "env" in burp


def test_hackerone_mcp_config_schema():
    h1_config_path = Path(__file__).resolve().parent.parent / "mcp" / "hackerone-mcp" / "config.json"
    assert h1_config_path.exists(), "mcp/hackerone-mcp/config.json must exist"

    with open(h1_config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "mcpServers" in data
    assert "hackerone" in data["mcpServers"]
    h1 = data["mcpServers"]["hackerone"]
    assert "command" in h1
    assert "args" in h1
