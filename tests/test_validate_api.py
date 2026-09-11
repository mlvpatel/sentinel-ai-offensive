"""Unit and API tests for tools/validate.py — CVSS 3.1 calculation and severity mapping."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from validate import calculate_cvss, severity_from_score


class TestCvssCalculator:
    """Test standard FIRST CVSS 3.1 base score formulas and edge cases."""

    def test_zero_impact_returns_zero(self):
        # When Confidentiality, Integrity, and Availability are all None (N)
        score, vector = calculate_cvss(
            av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N"
        )
        assert score == 0.0
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N" == vector
        assert severity_from_score(score) == "NONE"

    def test_critical_rce_max_score(self):
        # Critical unauthenticated network RCE with Scope Unchanged: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        score, vector = calculate_cvss(
            av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"
        )
        assert score == 9.8
        assert severity_from_score(score) == "CRITICAL"

    def test_critical_scope_changed(self):
        # Scope changed critical (e.g. VM escape / Sandbox escape): AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
        score, vector = calculate_cvss(
            av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"
        )
        assert score == 10.0
        assert severity_from_score(score) == "CRITICAL"

    def test_medium_xss(self):
        # Reflected XSS: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
        score, vector = calculate_cvss(
            av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"
        )
        assert 6.0 <= score <= 6.5
        assert severity_from_score(score) == "MEDIUM"

    def test_score_bounded_between_0_and_10(self):
        # Exhaustive permutation check on bounds
        for av in ("N", "A", "L", "P"):
            for s in ("U", "C"):
                score, _ = calculate_cvss(
                    av=av, ac="L", pr="N", ui="N", s=s, c="H", i="H", a="H"
                )
                assert 0.0 <= score <= 10.0
