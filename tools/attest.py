#!/usr/bin/env python3
"""Verify an audit log's hash-chain + scope attestation. Exit 1 on break/violation.

Usage:
  python3 tools/attest.py <path/to/audit.jsonl>

Prints the chain head (a commitment to the whole log — any edit to a past entry
changes it) and any request whose scope check was not 'pass'. This is the
machine-checkable "every request stayed in scope" proof that ships alongside a
finding so a triager can trust the engine never went out of bounds.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from memory.audit_log import AuditLog


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Verify audit log hash-chain + scope attestation."
    )
    ap.add_argument("path", help="Path to audit.jsonl")
    args = ap.parse_args()

    r = AuditLog(args.path).verify_chain()
    print(f"entries:      {r['total']}")
    print(f"chain intact: {r['intact']}"
          + ("" if r["intact"] else f" (BROKEN at entry #{r['broken_at']})"))
    print(f"chain head:   {r['chain_head']}")
    print(f"scope clean:  {r['scope_clean']}")
    for v in r["scope_violations"]:
        print(f"  OUT-OF-SCOPE #{v['index']} scope_check={v['scope_check']}: {v['url']}")

    sys.exit(0 if r["scope_clean"] else 1)


if __name__ == "__main__":
    main()
