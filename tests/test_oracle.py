"""Tests for tools/oracle.py — deterministic K-repro gate."""

import pytest

from tools.oracle import repro_gate, marker_predicate


class TestReproGate:

    def test_all_fire_is_real(self):
        res = repro_gate(lambda: (True, "m"), k=3)
        assert res["verdict"] == "REAL"
        assert res["reproduced"] == 3
        assert res["deterministic"] is True

    def test_none_fire_is_not_real(self):
        res = repro_gate(lambda: (False, None), k=3)
        assert res["verdict"] == "NOT_REAL"
        assert res["reproduced"] == 0
        assert res["deterministic"] is True

    def test_intermittent_is_flaky(self):
        seq = iter([True, False, True])
        res = repro_gate(lambda: (next(seq), "m"), k=3)
        assert res["verdict"] == "FLAKY"
        assert res["reproduced"] == 2
        assert res["deterministic"] is False

    def test_k_less_than_one_raises(self):
        with pytest.raises(ValueError):
            repro_gate(lambda: (True, None), k=0)

    def test_markers_collected_only_on_fire(self):
        seq = iter([True, False, True])
        res = repro_gate(lambda: (next(seq), "hit"), k=3)
        assert res["markers"] == ["hit", "hit"]

    def test_rate_limiter_paced_between_trials_only(self):
        calls = []

        class FakeLimiter:
            def wait(self, host):
                calls.append(host)

        repro_gate(lambda: (True, None), k=3, rate_limiter=FakeLimiter(), host="target.com")
        # Paced between trials (k-1 waits), never before the first request.
        assert calls == ["target.com", "target.com"]


class TestMarkerPredicate:

    def test_fires_when_marker_present(self):
        pred = marker_predicate(lambda: "leak: CANARY123 here", "CANARY123")
        fired, marker = pred()
        assert fired is True
        assert marker == {"marker": "CANARY123"}

    def test_no_fire_when_absent(self):
        pred = marker_predicate(lambda: "clean response", "CANARY123")
        fired, _ = pred()
        assert fired is False

    def test_real_verdict_through_gate(self):
        pred = marker_predicate(lambda: "xx CANARY yy", "CANARY")
        assert repro_gate(pred, k=3)["verdict"] == "REAL"
