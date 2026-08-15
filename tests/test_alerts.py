"""Tests for the evaluation of the LAPI alerts."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "custom_components" / "crowdsec"))

from alerts import (  # noqa: E402
    UNKNOWN,
    alert_id,
    new_bans,
    parse_timestamp,
    summarize_alerts,
)

TOP = 5


def make_alert(
    alert_id_value=1,
    ip="192.0.2.1",
    scenario="crowdsecurity/ssh-bf",
    country="DE",
    decisions=("ban",),
    simulated=False,
    created_at="2026-08-13T10:00:00Z",
):
    """An alert in the format of the LAPI."""
    return {
        "id": alert_id_value,
        "created_at": created_at,
        "scenario": scenario,
        "simulated": simulated,
        "source": {
            "ip": ip,
            "value": ip,
            "scope": "Ip",
            "cn": country,
            "as_name": "Example AS",
        },
        "decisions": [
            {"type": kind, "duration": "4h", "scope": "Ip", "value": ip}
            for kind in decisions
        ],
    }


def test_counts_alerts_and_bans():
    summary = summarize_alerts([make_alert(1), make_alert(2, ip="192.0.2.2")], TOP)
    assert summary.alerts == 2
    assert summary.ban_decisions == 2
    assert summary.unique_sources == 2
    assert summary.banned_sources == 2


def test_simulated_alerts_are_ignored():
    summary = summarize_alerts([make_alert(1, simulated=True), make_alert(2)], TOP)
    assert summary.alerts == 1
    assert summary.ban_decisions == 1


def test_repeated_source_counts_once_as_attacker():
    alerts = [make_alert(1), make_alert(2), make_alert(3)]
    summary = summarize_alerts(alerts, TOP)
    assert summary.alerts == 3
    # The same IP three times is one attacker, not three.
    assert summary.unique_sources == 1
    assert summary.banned_sources == 1
    assert summary.top_source == "192.0.2.1"
    assert summary.top_sources[0] == {"ip": "192.0.2.1", "alerts": 3}


def test_non_ban_decisions_do_not_count():
    summary = summarize_alerts([make_alert(1, decisions=("captcha",))], TOP)
    assert summary.alerts == 1
    assert summary.ban_decisions == 0
    assert summary.banned_sources == 0
    assert summary.bans == []


def test_multiple_ban_decisions_yield_one_event():
    # An alert with a ban on the IP and on the range is one incident.
    summary = summarize_alerts([make_alert(1, decisions=("ban", "ban"))], TOP)
    assert summary.ban_decisions == 2
    assert len(summary.bans) == 1


def test_top_scenario_and_country():
    alerts = [
        make_alert(1, scenario="a", country="DE"),
        make_alert(2, scenario="b", country="FR", ip="192.0.2.2"),
        make_alert(3, scenario="b", country="FR", ip="192.0.2.3"),
    ]
    summary = summarize_alerts(alerts, TOP)
    assert summary.top_scenario == "b"
    assert summary.top_country == "FR"
    assert summary.top_countries[0] == {"country": "FR", "alerts": 2}


def test_top_count_limits_the_lists():
    alerts = [make_alert(i, scenario=f"s{i}", ip=f"192.0.2.{i}") for i in range(1, 10)]
    summary = summarize_alerts(alerts, 3)
    assert len(summary.top_scenarios) == 3
    assert len(summary.top_sources) == 3


def test_missing_source_is_grouped_as_unknown():
    alert = make_alert(1)
    del alert["source"]
    summary = summarize_alerts([alert], TOP)
    assert summary.alerts == 1
    # The catch-all bucket does not count as an attacker of its own.
    assert summary.unique_sources == 0
    assert summary.top_sources[0] == {"ip": UNKNOWN, "alerts": 1}


def test_latest_alert_is_the_newest_timestamp():
    alerts = [
        make_alert(1, created_at="2026-08-13T08:00:00Z"),
        make_alert(2, created_at="2026-08-13T12:30:00Z", ip="192.0.2.2"),
        make_alert(3, created_at="2026-08-13T09:00:00Z", ip="192.0.2.3"),
    ]
    summary = summarize_alerts(alerts, TOP)
    assert summary.latest_alert is not None
    assert summary.latest_alert.hour == 12
    assert summary.latest_alert.tzinfo is not None


def test_ban_record_carries_the_context():
    summary = summarize_alerts([make_alert(7)], TOP)
    ban = summary.bans[0]
    assert ban.ip == "192.0.2.1"
    assert ban.country == "DE"
    assert ban.as_name == "Example AS"
    assert ban.duration == "4h"
    data = ban.as_event_data()
    assert data["scenario"] == "crowdsecurity/ssh-bf"
    assert data["created_at"].startswith("2026-08-13T10:00:00")


def test_first_cycle_fires_no_events():
    summary = summarize_alerts([make_alert(1), make_alert(2, ip="192.0.2.2")], TOP)
    # Without a known previous state nothing may count as new, otherwise every
    # restart dumps 24 hours of bans at once.
    assert new_bans(summary, None) == []


def test_only_unseen_alerts_are_new():
    first = summarize_alerts([make_alert(1)], TOP)
    second = summarize_alerts([make_alert(1), make_alert(2, ip="192.0.2.2")], TOP)
    fresh = new_bans(second, first.seen_ids)
    assert [ban.ip for ban in fresh] == ["192.0.2.2"]


def test_nothing_new_when_alerts_repeat():
    first = summarize_alerts([make_alert(1)], TOP)
    second = summarize_alerts([make_alert(1)], TOP)
    assert new_bans(second, first.seen_ids) == []


def test_alert_id_falls_back_to_fingerprint():
    alert = make_alert(1)
    del alert["id"]
    identifier = alert_id(alert)
    assert identifier is not None
    assert identifier.startswith("fp:")
    # The same alert yields the same identifier — otherwise every cycle would be "new".
    assert identifier == alert_id(dict(alert))


def test_alert_id_none_without_any_marker():
    assert alert_id({}) is None


def test_parse_timestamp_handles_offsets_and_garbage():
    assert parse_timestamp("2026-08-13T10:00:00+02:00").hour == 8
    assert parse_timestamp("not a time") is None
    assert parse_timestamp(None) is None


def test_empty_input():
    summary = summarize_alerts([], TOP)
    assert summary.alerts == 0
    assert summary.top_scenario is None
    assert summary.top_country is None
    assert summary.seen_ids == set()
