"""
Pattern database — successful techniques indexed by vuln class + tech stack.

Patterns are stored in a JSONL file, one entry per line.
Matching supports partial tech stack overlap for cross-target learning.
"""

import fcntl
import json
import os
import sys
from pathlib import Path

from memory.schemas import validate_pattern_entry, SchemaError
from memory.prior import rank_patterns


class PatternDB:
    """Read/write/match successful hunt patterns."""

    def __init__(self, path: str | Path):
        """
        Args:
            path: Path to the patterns.jsonl file. Parent dirs are created if needed.
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, entry: dict) -> bool:
        """Validate and save a pattern entry. Returns True if saved, False if duplicate.

        A duplicate is defined as same target + vuln_class + technique.
        """
        validated = validate_pattern_entry(entry)

        # Check for duplicates
        existing = self.read_all(validate=False)
        for e in existing:
            if (e.get("target") == validated["target"]
                    and e.get("vuln_class") == validated["vuln_class"]
                    and e.get("technique") == validated["technique"]):
                return False

        line = json.dumps(validated, separators=(",", ":")) + "\n"
        encoded = line.encode("utf-8")

        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                written = os.write(fd, encoded)
                if written != len(encoded):
                    raise OSError(f"Partial write: {written}/{len(encoded)} bytes")
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

        return True

    def read_all(self, *, validate: bool = True) -> list[dict]:
        """Read all pattern entries. Corrupted lines are skipped with a warning."""
        if not self.path.exists():
            return []

        entries = []
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    print(
                        f"WARNING: patterns line {lineno} is corrupted (skipping): {e}",
                        file=sys.stderr,
                    )
                    continue

                if validate:
                    try:
                        validate_pattern_entry(entry)
                    except SchemaError as e:
                        print(
                            f"WARNING: patterns line {lineno} failed validation (skipping): {e}",
                            file=sys.stderr,
                        )
                        continue

                entries.append(entry)

        return entries

    def match(self, *, vuln_class: str | None = None,
              tech_stack: list[str] | None = None,
              journal: list[dict] | None = None,
              drop_dead_ends: bool = True) -> list[dict]:
        """Find patterns matching vuln class and/or overlapping tech stack.

        Args:
            vuln_class: Exact match on vuln_class field.
            tech_stack: Partial overlap match — returns patterns where ANY tech in
                        the query overlaps with the pattern's tech_stack.
            journal: If given (a list of hunt-journal entries), rank by expected
                     value — P(confirm) x payout, learned from your own past
                     confirms/rejects — and drop known dead ends. If None, keep the
                     default payout sort (backward compatible).
            drop_dead_ends: When ranking by EV, drop N/N-rejected classes.

        Returns:
            Matching patterns, EV-ranked when a journal is given, else payout-sorted.
        """
        patterns = self.read_all()

        if vuln_class is not None:
            patterns = [p for p in patterns if p.get("vuln_class") == vuln_class]

        if tech_stack is not None:
            query_set = {t.lower() for t in tech_stack}
            patterns = [
                p for p in patterns
                if query_set & {t.lower() for t in p.get("tech_stack", [])}
            ]

        if journal is not None:
            return rank_patterns(patterns, journal, drop_dead_ends=drop_dead_ends)

        # Default: highest payout first, then most recent
        patterns.sort(
            key=lambda p: (p.get("payout", 0), p.get("ts", "")),
            reverse=True,
        )

        return patterns
