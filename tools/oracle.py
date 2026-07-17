"""Deterministic Oracle — a finding is REAL only when a predicate fires K/K times.

The reasoning layer (LLM or human) proposes a finding; it never gets to *declare*
one. A deterministic predicate over replayable evidence judges. Running it K times
also quantifies reproducibility — the #1 triager complaint ("can't reproduce") —
and routes anything non-deterministic to a manual lane instead of auto-submitting.

A predicate is any callable returning (fired: bool, marker). See marker_predicate
for the canonical shape (canary exfil / reflected marker / secret-in-response).
"""

from typing import Any, Callable


def repro_gate(predicate: Callable[[], tuple[bool, Any]], k: int = 3, *,
               rate_limiter=None, host: str | None = None) -> dict:
    """Run predicate k times; a finding is REAL only if it fires every time.

    Args:
        predicate: callable() -> (fired, marker). Each call re-exercises the finding
                   from scratch (a clean replay), so K consistent fires prove
                   deterministic reproducibility, not a proxy/state artifact.
        k: number of trials (K). REAL requires k/k.
        rate_limiter: optional object with .wait(host) — paced between trials.
        host: host key for the rate limiter.

    Returns:
        {trials, reproduced, deterministic, verdict, markers} where verdict is
        REAL (k/k), NOT_REAL (0/k), or FLAKY (in between → route to manual).
    """
    if k < 1:
        raise ValueError("k must be >= 1")

    reproduced = 0
    markers = []
    for i in range(k):
        if rate_limiter is not None and host is not None and i > 0:
            rate_limiter.wait(host)
        fired, marker = predicate()
        if fired:
            reproduced += 1
            markers.append(marker)

    if reproduced == k:
        verdict = "REAL"
    elif reproduced == 0:
        verdict = "NOT_REAL"
    else:
        verdict = "FLAKY"

    return {
        "trials": k,
        "reproduced": reproduced,
        "deterministic": reproduced in (0, k),
        "verdict": verdict,
        "markers": markers,
    }


def marker_predicate(fetch: Callable[[], str], marker: str) -> Callable[[], tuple[bool, Any]]:
    """A predicate that fires when a planted marker appears in fetch()'s output.

    This is the canonical deterministic oracle: plant a unique canary (SSRF callback
    token, reflected-XSS marker, a secret you expect leaked) and confirm it comes
    back. fetch() re-issues the request each call so repro_gate can retry cleanly.
    """
    def _predicate() -> tuple[bool, Any]:
        body = fetch() or ""
        return (marker in body, {"marker": marker})

    return _predicate
