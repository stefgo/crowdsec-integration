"""Tests für die Zeitfenster der Alert-Abfrage."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "custom_components" / "crowdsec"))

from timewindow import (  # noqa: E402
    Window,
    parse_duration,
    split_window,
    window_params,
)


def test_parse_duration_units():
    assert parse_duration("24h") == 1440
    assert parse_duration("90m") == 90
    assert parse_duration("2d") == 2880
    assert parse_duration("1.5h") == 90


def test_parse_duration_rejects_nonsense():
    assert parse_duration("") is None
    assert parse_duration("24") is None
    assert parse_duration("h") is None
    assert parse_duration("0h") is None
    assert parse_duration("-2h") is None


def test_window_params_omit_until_for_the_newest_window():
    # Ein "until" am jüngsten Fenster würde gerade eintreffende Alerts
    # verschlucken.
    assert window_params(Window(1440, 0)) == {"since": "1440m"}


def test_window_params_with_until():
    assert window_params(Window(1440, 720)) == {"since": "1440m", "until": "720m"}


def test_split_halves_a_window():
    older, newer = split_window(Window(1440, 0))
    assert older == Window(1440, 720)
    assert newer == Window(720, 0)
    # Die Hälften decken das Ausgangsfenster lückenlos ab.
    assert older.end == newer.start
    assert older.minutes + newer.minutes == 1440


def test_split_of_an_odd_window_loses_no_minute():
    older, newer = split_window(Window(9, 0))
    assert older.end == newer.start
    assert older.minutes + newer.minutes == 9


def test_split_stops_at_one_minute():
    assert split_window(Window(1, 0)) is None
    assert split_window(Window(2, 0)) == (Window(2, 1), Window(1, 0))


def test_split_of_a_nested_window():
    older, newer = split_window(Window(720, 360))
    assert older == Window(720, 540)
    assert newer == Window(540, 360)
