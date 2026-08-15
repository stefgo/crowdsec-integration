"""Tests for the evaluation of the LAPI decisions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from crowdsec_component.decisions import (
    build_source_index,
    build_table,
    history_from_alerts,
    normalize_decision,
    normalize_decisions,
    origin_kind,
    parse_go_duration,
)

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)


def make_decision(
    decision_id=1,
    value="192.0.2.1",
    duration="3h59m58s",
    origin="crowdsec",
    decision_type="ban",
    scope="Ip",
    scenario="crowdsecurity/ssh-bf",
    **extra,
):
    """A decision in the format of ``/v1/decisions``."""
    return {
        "id": decision_id,
        "value": value,
        "duration": duration,
        "origin": origin,
        "type": decision_type,
        "scope": scope,
        "scenario": scenario,
        **extra,
    }


def make_alert(
    ip="192.0.2.1",
    scenario="crowdsecurity/ssh-bf",
    country="DE",
    as_name="Example AS",
    created_at="2026-08-15T10:00:00Z",
    decisions=(("ban", "4h"),),
    simulated=False,
):
    """An alert in the format of ``/v1/alerts``."""
    return {
        "id": 1,
        "created_at": created_at,
        "scenario": scenario,
        "simulated": simulated,
        "source": {
            "ip": ip,
            "value": ip,
            "scope": "Ip",
            "cn": country,
            "as_name": as_name,
            "as_number": "AS64500",
        },
        "decisions": [
            {
                "type": kind,
                "duration": duration,
                "scope": "Ip",
                "value": ip,
                "origin": "crowdsec",
                "scenario": scenario,
            }
            for kind, duration in decisions
        ],
    }


# -- Durations --------------------------------------------------------------


def test_go_duration_combines_all_parts():
    assert parse_go_duration("1h30m") == 5400
    assert parse_go_duration("168h0m0s") == 604800
    assert parse_go_duration("2m30.5s") == 150.5


def test_go_duration_keeps_the_sign_of_an_expired_decision():
    # CrowdSec counts backwards once a decision has run out — that sign is the
    # only hint some versions give.
    assert parse_go_duration("-1h") == -3600


def test_go_duration_rejects_what_it_cannot_read():
    assert parse_go_duration("") is None
    assert parse_go_duration(None) is None
    assert parse_go_duration("forever") is None
    # An unknown unit would be wrong by a factor — better nothing at all.
    assert parse_go_duration("5w") is None


# -- Origins ----------------------------------------------------------------


def test_origin_kind_separates_local_from_pushed():
    assert origin_kind("crowdsec") == "local"
    assert origin_kind("cscli") == "local"
    assert origin_kind("console") == "local"
    assert origin_kind("CAPI") == "capi"
    assert origin_kind("lists") == "lists"
    assert origin_kind(None) == "local"


# -- Normalisation ----------------------------------------------------------


def test_normalize_derives_the_expiry_from_the_duration():
    record = normalize_decision(make_decision(duration="2h"), NOW)
    assert record is not None
    assert record.until == NOW + timedelta(hours=2)
    assert record.seconds_left == 7200
    assert record.status == "active"
    assert record.deletable is True


def test_normalize_prefers_the_until_the_lapi_sends():
    record = normalize_decision(
        make_decision(until="2026-08-15T18:00:00Z", duration=None), NOW
    )
    assert record is not None
    assert record.until == datetime(2026, 8, 15, 18, 0, tzinfo=UTC)
    assert record.seconds_left == 6 * 3600


def test_normalize_marks_a_run_out_decision_as_expired():
    record = normalize_decision(make_decision(duration="-5m"), NOW)
    assert record is not None
    assert record.status == "expired"


def test_pushed_decisions_are_not_deletable():
    record = normalize_decision(make_decision(origin="CAPI"), NOW)
    assert record is not None
    assert record.origin_kind == "capi"
    # Deleting locally would only last until the next pull from the central API.
    assert record.deletable is False


def test_normalize_skips_what_cannot_be_shown():
    assert normalize_decision({"id": 1}, NOW) is None
    assert normalize_decision("nonsense", NOW) is None
    assert normalize_decisions([{"id": 1}, make_decision()], NOW) != []
    assert len(normalize_decisions([{"id": 1}, make_decision()], NOW)) == 1


# -- Enrichment -------------------------------------------------------------


def test_alerts_fill_in_country_and_as():
    index = build_source_index([make_alert()])
    record = normalize_decision(make_decision(), NOW, index)
    assert record is not None
    assert record.country == "DE"
    assert record.as_name == "Example AS"
    assert record.as_number == "AS64500"
    assert record.alerts_24h == 1


def test_the_newest_alert_describes_the_source():
    index = build_source_index(
        [
            make_alert(scenario="old", created_at="2026-08-15T08:00:00Z"),
            make_alert(scenario="new", created_at="2026-08-15T11:00:00Z"),
        ]
    )
    info = index["192.0.2.1"]
    assert info.scenario == "new"
    # Both alerts count, regardless of which one won the details.
    assert info.alerts == 2


def test_simulated_alerts_do_not_enrich_anything():
    index = build_source_index([make_alert(simulated=True)])
    assert index == {}


# -- History ----------------------------------------------------------------


def test_history_holds_the_bans_that_have_run_out():
    alert = make_alert(created_at="2026-08-15T06:00:00Z", decisions=(("ban", "1h"),))
    history = history_from_alerts([alert], [], NOW)
    assert len(history) == 1
    assert history[0].status == "expired"
    # Nothing left to remove — the decision is gone already.
    assert history[0].deletable is False
    assert history[0].country == "DE"


def test_history_leaves_out_what_is_still_enforced():
    alert = make_alert(created_at="2026-08-15T11:00:00Z", decisions=(("ban", "4h"),))
    # Runs until 15:00 — the live list owns this row, not the history.
    assert history_from_alerts([alert], [], NOW) == []


def test_history_skips_addresses_that_are_already_in_the_table():
    active = normalize_decisions([make_decision()], NOW)
    alert = make_alert(created_at="2026-08-15T06:00:00Z", decisions=(("ban", "1h"),))
    assert history_from_alerts([alert], active, NOW) == []


# -- The whole table --------------------------------------------------------


def test_build_table_merges_both_sources():
    decisions = [make_decision(value="192.0.2.1")]
    alerts = [
        make_alert(ip="192.0.2.1"),
        make_alert(
            ip="198.51.100.9",
            created_at="2026-08-15T06:00:00Z",
            decisions=(("ban", "1h"),),
        ),
    ]
    table = build_table(decisions, alerts, NOW)

    assert [row.value for row in table] == ["192.0.2.1", "198.51.100.9"]
    assert table[0].status == "active"
    assert table[1].status == "expired"
    # The active row got its details from the matching alert.
    assert table[0].country == "DE"


def test_build_table_can_leave_the_history_out():
    alerts = [
        make_alert(
            ip="198.51.100.9",
            created_at="2026-08-15T06:00:00Z",
            decisions=(("ban", "1h"),),
        )
    ]
    assert build_table([], alerts, NOW, include_history=False) == []


def test_build_table_sorts_active_first_and_by_remaining_time():
    decisions = [
        make_decision(decision_id=1, value="192.0.2.1", duration="1h"),
        make_decision(decision_id=2, value="192.0.2.2", duration="24h"),
        make_decision(decision_id=3, value="192.0.2.3", duration="-1h"),
    ]
    table = build_table(decisions, [], NOW)
    assert [row.value for row in table] == ["192.0.2.2", "192.0.2.1", "192.0.2.3"]


def test_as_dict_is_json_ready():
    record = normalize_decision(
        make_decision(), NOW, build_source_index([make_alert()])
    )
    assert record is not None
    payload = record.as_dict()
    assert payload["value"] == "192.0.2.1"
    assert payload["origin_kind"] == "local"
    assert payload["seconds_left"] == 14398
    assert isinstance(payload["until"], str)
    assert payload["deletable"] is True
