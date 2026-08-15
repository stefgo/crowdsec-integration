"""Tests for rate calculation and restart detection."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "custom_components" / "crowdsec")
)

from rates import RateTracker, error_ratio

START = 1_700_000_000.0


def test_first_sample_has_no_rate():
    tracker = RateTracker()
    assert tracker.update({"lines": 100.0}, START, 0.0) is None


def test_rate_per_minute():
    tracker = RateTracker()
    tracker.update({"lines": 100.0}, START, 0.0)
    window = tracker.update({"lines": 160.0}, START, 30.0)
    assert window is not None
    assert window.per_minute("lines") == 120.0


def test_restart_discards_interval():
    tracker = RateTracker()
    tracker.update({"lines": 1000.0}, START, 0.0)
    # Process restarted: counter back to 5, new start time.
    assert tracker.update({"lines": 5.0}, START + 500, 60.0) is None
    # After that the calculation is back to normal.
    window = tracker.update({"lines": 65.0}, START + 500, 120.0)
    assert window is not None
    assert window.per_minute("lines") == 60.0


def test_counter_drop_without_restart_discards_interval():
    tracker = RateTracker()
    tracker.update({"lines": 1000.0}, START, 0.0)
    assert tracker.update({"lines": 900.0}, START, 60.0) is None


def test_zero_elapsed_discards_interval():
    tracker = RateTracker()
    tracker.update({"lines": 1.0}, START, 10.0)
    assert tracker.update({"lines": 2.0}, START, 10.0) is None


def test_reset_clears_history():
    tracker = RateTracker()
    tracker.update({"lines": 10.0}, START, 0.0)
    tracker.reset()
    assert tracker.update({"lines": 20.0}, START, 60.0) is None


def test_missing_start_time_still_compares():
    tracker = RateTracker()
    tracker.update({"lines": 0.0}, None, 0.0)
    window = tracker.update({"lines": 30.0}, None, 60.0)
    assert window is not None
    assert window.per_minute("lines") == 30.0


def test_error_ratio():
    assert error_ratio(95.0, 5.0) == 5.0
    assert error_ratio(0.0, 0.0) is None
    assert error_ratio(None, None) is None


def test_error_ratio_treats_missing_counter_as_zero():
    # Error-free parser: the ko metric is missing entirely -> 0 %, not "unknown".
    assert error_ratio(1000.0, None) == 0.0
    # The other way round: only errors, no ok metric -> 100 %.
    assert error_ratio(None, 5.0) == 100.0
    # Without processed lines it stays unknown.
    assert error_ratio(None, 0.0) is None
    assert error_ratio(0.0, None) is None
