"""Outcome flywheel — turn recorded hunt outcomes into an expected-value prior.

Every confirmed/rejected finding in the hunt journal is a labelled sample. These
pure functions read those samples (plain journal-entry dicts) and produce:
  - hit_rate:    Beta(1,1) posterior P(confirm) per vuln_class[/technique]
  - is_dead_end: hard-KILL for classes that are N/N rejected (a stored loss)
  - ev_score:    expected value = P(confirm) x payout signal
  - rank_patterns: reorder pattern matches so the next hunt starts with the
                   highest-EV techniques and skips known dead ends.

No ML, no new storage — just a scoring function over the JSONL already persisted.
"""

from statistics import median


def _outcomes(journal: list[dict], vuln_class: str, technique: str | None = None) -> tuple[int, int]:
    """(confirmed, rejected) counts for a vuln_class, optionally narrowed by technique."""
    hits = fails = 0
    for e in journal:
        if e.get("vuln_class") != vuln_class:
            continue
        if technique is not None and e.get("technique") != technique:
            continue
        result = e.get("result")
        if result == "confirmed":
            hits += 1
        elif result == "rejected":
            fails += 1
    return hits, fails


def hit_rate(journal: list[dict], vuln_class: str, technique: str | None = None) -> tuple[float, int]:
    """Beta(1,1) posterior mean P(confirm) over confirmed vs rejected. Returns (mean, n).

    With no data the mean is 0.5 (n=0) — an honest uninformed prior, not a claim.
    """
    hits, fails = _outcomes(journal, vuln_class, technique)
    n = hits + fails
    return (hits + 1) / (n + 2), n


def is_dead_end(journal: list[dict], vuln_class: str, technique: str | None = None,
                min_rejects: int = 3) -> bool:
    """True when a class/technique has been rejected min_rejects+ times with zero confirms."""
    hits, fails = _outcomes(journal, vuln_class, technique)
    return hits == 0 and fails >= min_rejects


def median_payout(journal: list[dict], vuln_class: str) -> float:
    """Median payout of confirmed findings for a vuln_class (0.0 if none recorded)."""
    payouts = [
        e["payout"] for e in journal
        if e.get("vuln_class") == vuln_class and e.get("result") == "confirmed"
        and isinstance(e.get("payout"), (int, float)) and e["payout"] > 0
    ]
    return float(median(payouts)) if payouts else 0.0


def ev_score(pattern: dict, journal: list[dict]) -> float:
    """Expected value of a pattern = P(confirm) x payout signal. Higher = hunt first.

    Uses the pattern's technique-level hit rate, backing off to the class-level rate
    when that technique has no recorded history. Payout signal is the pattern's own
    payout, else the class's median confirmed payout, else 1.0.
    """
    vuln_class = pattern.get("vuln_class")
    mean, n = hit_rate(journal, vuln_class, pattern.get("technique"))
    if n == 0:  # no technique-level samples → use the class-level signal
        mean, _ = hit_rate(journal, vuln_class)
    payout = pattern.get("payout") or median_payout(journal, vuln_class) or 1.0
    return mean * payout


def rank_patterns(patterns: list[dict], journal: list[dict], *,
                  drop_dead_ends: bool = True) -> list[dict]:
    """Rank patterns by expected value (desc, recency tiebreak), dropping dead ends.

    Dead ends are checked at the vuln_class level — a class your history says is
    N/N-rejected is skipped regardless of which technique the pattern proposes.
    """
    ranked = [
        p for p in patterns
        if not (drop_dead_ends and is_dead_end(journal, p.get("vuln_class")))
    ]
    ranked.sort(key=lambda p: (ev_score(p, journal), p.get("ts", "")), reverse=True)
    return ranked
