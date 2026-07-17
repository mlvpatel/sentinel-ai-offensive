"""Tests for memory/audit_log.py hash-chain + scope attestation."""

import json

from memory.audit_log import AuditLog, GENESIS_HASH, _entry_hash


class TestChain:

    def test_first_entry_prev_is_genesis(self, tmp_hunt_dir):
        log = AuditLog(tmp_hunt_dir / "audit.jsonl")
        log.log_request(url="https://api.target.com/1", method="GET", scope_check="pass")
        e = log.read_all()[0]
        assert e["prev_hash"] == GENESIS_HASH
        assert e["entry_hash"] == _entry_hash(e)

    def test_chain_links(self, tmp_hunt_dir):
        log = AuditLog(tmp_hunt_dir / "audit.jsonl")
        for i in range(3):
            log.log_request(url=f"https://api.target.com/{i}", method="GET", scope_check="pass")
        entries = log.read_all()
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
        assert entries[2]["prev_hash"] == entries[1]["entry_hash"]

    def test_verify_clean_log(self, tmp_hunt_dir):
        log = AuditLog(tmp_hunt_dir / "audit.jsonl")
        for i in range(3):
            log.log_request(url=f"https://api.target.com/{i}", method="GET", scope_check="pass")
        r = log.verify_chain()
        assert r["intact"] is True
        assert r["scope_clean"] is True
        assert r["total"] == 3
        assert r["chain_head"] == log.read_all()[-1]["entry_hash"]

    def test_detects_tampering(self, tmp_hunt_dir):
        path = tmp_hunt_dir / "audit.jsonl"
        log = AuditLog(path)
        for i in range(3):
            log.log_request(url=f"https://api.target.com/{i}", method="GET", scope_check="pass")

        lines = path.read_text().splitlines()
        tampered = json.loads(lines[1])
        tampered["url"] = "https://evil.com/x"
        lines[1] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")

        r = log.verify_chain()
        assert r["intact"] is False
        assert r["broken_at"] == 1
        assert r["scope_clean"] is False

    def test_detects_scope_violation(self, tmp_hunt_dir):
        log = AuditLog(tmp_hunt_dir / "audit.jsonl")
        log.log_request(url="https://api.target.com/1", method="GET", scope_check="pass")
        log.log_request(url="https://out.of.scope/x", method="GET", scope_check="fail")
        r = log.verify_chain()
        assert r["intact"] is True           # chain itself is valid
        assert r["scope_clean"] is False     # but a request was out of scope
        assert len(r["scope_violations"]) == 1
        assert r["scope_violations"][0]["scope_check"] == "fail"
