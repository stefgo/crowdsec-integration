"""Tests for the rolling alert window.

The cache is what makes the two-speed alert polling possible: a full query
fills it now and then, every cycle tops it up with the last few minutes. What
matters is that the deliberate overlap of those queries does not produce
duplicates and that nothing ages out too early.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from crowdsec_component.alerts import AlertCache, alert_timestamp, summarize_alerts

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
WINDOW = timedelta(hours=24)


def make_alert(
    alert_id, minutes_ago=0, scenario="crowdsecurity/ssh-bf", ip="192.0.2.1"
):
    created = NOW - timedelta(minutes=minutes_ago)
    return {
        "id": alert_id,
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "scenario": scenario,
        "source": {"value": ip, "cn": "DE"},
        "decisions": [{"type": "ban", "duration": "4h", "value": ip, "scope": "Ip"}],
    }


def test_the_overlap_of_two_queries_does_not_duplicate():
    cache = AlertCache(WINDOW)
    cache.replace([make_alert(1, 10), make_alert(2, 5)])
    # The incremental query deliberately reaches back further than the elapsed
    # time, so it sees alert 2 again.
    cache.add([make_alert(2, 5), make_alert(3, 1)])

    assert len(cache) == 3
    assert {alert["id"] for alert in cache.alerts} == {1, 2, 3}


def test_a_known_alert_is_updated_not_ignored():
    """CrowdSec keeps raising events_count on an ongoing alert."""
    cache = AlertCache(WINDOW)
    cache.replace([{**make_alert(1, 5), "events_count": 3}])
    cache.add([{**make_alert(1, 5), "events_count": 9}])

    assert len(cache) == 1
    assert cache.alerts[0]["events_count"] == 9


def test_a_full_query_replaces_the_content():
    cache = AlertCache(WINDOW)
    cache.replace([make_alert(1, 10), make_alert(2, 5)])
    cache.replace([make_alert(3, 1)])

    assert [alert["id"] for alert in cache.alerts] == [3]


def test_pruning_drops_what_left_the_window():
    cache = AlertCache(WINDOW)
    cache.replace([make_alert(1, 25 * 60), make_alert(2, 23 * 60), make_alert(3, 1)])

    assert cache.prune(NOW) == 1
    assert {alert["id"] for alert in cache.alerts} == {2, 3}


def test_an_alert_without_a_timestamp_survives_pruning():
    """It would otherwise vanish on the first cycle after the LAPI sent it."""
    cache = AlertCache(WINDOW)
    cache.replace([{"id": 1, "scenario": "x"}])

    assert cache.prune(NOW) == 0
    assert len(cache) == 1


def test_alerts_without_an_identifier_do_not_overwrite_each_other():
    cache = AlertCache(WINDOW)
    # No id and no fingerprint material at all.
    cache.replace([{"foo": 1}, {"foo": 2}])

    assert len(cache) == 2


def test_the_summary_over_the_cache_matches_a_single_full_query():
    """The two-speed polling must not change the 24h numbers."""
    alerts = [
        make_alert(1, 30, ip="192.0.2.1"),
        make_alert(2, 20, ip="192.0.2.2"),
        make_alert(3, 5, ip="192.0.2.1"),
    ]

    cache = AlertCache(WINDOW)
    cache.replace(alerts[:2])
    cache.add(alerts[1:])
    cache.prune(NOW)

    from_cache = summarize_alerts(cache.alerts, 5)
    from_one_query = summarize_alerts(alerts, 5)

    assert from_cache.alerts == from_one_query.alerts
    assert from_cache.unique_sources == from_one_query.unique_sources
    assert from_cache.ban_decisions == from_one_query.ban_decisions
    assert from_cache.seen_ids == from_one_query.seen_ids
    assert from_cache.latest_alert == from_one_query.latest_alert


def test_alert_timestamp_falls_back_to_start_at():
    assert alert_timestamp({"start_at": "2026-08-15T12:00:00Z"}) == NOW
    assert alert_timestamp({"created_at": "nonsense"}) is None
    assert alert_timestamp({}) is None
