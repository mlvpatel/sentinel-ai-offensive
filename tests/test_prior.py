"""Tests for memory/prior.py — EV prior + negative memory."""

import pytest

from memory.prior import hit_rate, is_dead_end, median_payout, ev_score, rank_patterns


def _j(vuln_class, result, technique=None, payout=None):
    e = {"vuln_class": vuln_class, "result": result}
    if technique is not None:
        e["technique"] = technique
    if payout is not None:
        e["payout"] = payout
    return e


class TestHitRate:

    def test_empty_journal_is_uninformed(self):
        mean, n = hit_rate([], "idor")
        assert mean == 0.5
        assert n == 0

    def test_counts_confirms_and_rejects(self):
        journal = [_j("idor", "confirmed"), _j("idor", "confirmed"), _j("idor", "rejected")]
        mean, n = hit_rate(journal, "idor")
        assert n == 3
        assert mean == pytest.approx((2 + 1) / (3 + 2))  # Beta(1,1) => 0.6

    def test_ignores_other_classes_and_nonterminal_results(self):
        journal = [_j("idor", "confirmed"), _j("xss", "confirmed"), _j("idor", "partial")]
        mean, n = hit_rate(journal, "idor")
        assert n == 1  # 'partial' is neither confirm nor reject
        assert mean == pytest.approx((1 + 1) / (1 + 2))

    def test_technique_narrows(self):
        journal = [_j("idor", "confirmed", "put_swap"), _j("idor", "rejected", "get_swap")]
        _, n = hit_rate(journal, "idor", technique="put_swap")
        assert n == 1


class TestDeadEnd:

    def test_all_rejected_is_dead_end(self):
        assert is_dead_end([_j("xss", "rejected")] * 3, "xss") is True

    def test_below_threshold_not_dead_end(self):
        assert is_dead_end([_j("xss", "rejected")] * 2, "xss") is False

    def test_any_confirm_not_dead_end(self):
        journal = [_j("xss", "rejected")] * 5 + [_j("xss", "confirmed")]
        assert is_dead_end(journal, "xss") is False


class TestMedianPayout:

    def test_median_of_confirmed_only(self):
        journal = [
            _j("idor", "confirmed", payout=1000),
            _j("idor", "confirmed", payout=3000),
            _j("idor", "rejected", payout=0),
        ]
        assert median_payout(journal, "idor") == 2000

    def test_none_returns_zero(self):
        assert median_payout([], "idor") == 0.0


class TestEvScore:

    def test_ev_uses_technique_rate_when_recorded(self):
        journal = [_j("idor", "confirmed", "put_swap"), _j("idor", "rejected", "get_swap")]
        pattern = {"vuln_class": "idor", "technique": "put_swap", "payout": 1000}
        tech_mean, n = hit_rate(journal, "idor", "put_swap")
        assert n == 1  # technique-level data exists
        assert ev_score(pattern, journal) == pytest.approx(tech_mean * 1000)

    def test_ev_backs_off_to_class_rate_when_technique_unrecorded(self):
        journal = [_j("idor", "confirmed")] * 3  # confirms recorded without a technique
        pattern = {"vuln_class": "idor", "technique": "put_swap", "payout": 1000}
        class_mean, _ = hit_rate(journal, "idor")  # 0.8
        assert ev_score(pattern, journal) == pytest.approx(class_mean * 1000)


class TestRankPatterns:

    def test_ranks_by_ev_and_drops_dead_ends(self):
        journal = (
            [_j("idor", "confirmed", payout=2000)] * 3
            + [_j("xss", "rejected")] * 3
        )
        patterns = [
            {"vuln_class": "xss", "technique": "reflected", "payout": 500, "ts": "2026-01-01T00:00:00Z"},
            {"vuln_class": "idor", "technique": "put_swap", "payout": 2000, "ts": "2026-01-02T00:00:00Z"},
        ]
        ranked = rank_patterns(patterns, journal)
        assert [p["vuln_class"] for p in ranked] == ["idor"]  # xss dropped as dead end

    def test_keep_dead_ends_when_disabled(self):
        journal = [_j("xss", "rejected")] * 3
        patterns = [{"vuln_class": "xss", "technique": "reflected", "ts": "2026-01-01T00:00:00Z"}]
        ranked = rank_patterns(patterns, journal, drop_dead_ends=False)
        assert len(ranked) == 1
