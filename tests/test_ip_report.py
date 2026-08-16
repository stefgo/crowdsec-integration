"""The lookup of a single address across every decision source."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from crowdsec_component.decisions import build_ip_report

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)


def decision(value, origin="crowdsec", duration="4h", decision_id=1):
    return {
        "id": decision_id,
        "origin": origin,
        "type": "ban",
        "scope": "Ip" if "/" not in value else "Range",
        "value": value,
        "duration": duration,
        "scenario": "crowdsecurity/ssh-bf",
    }


def alert(ip="192.0.2.10", scenario="crowdsecurity/ssh-bf", minutes_ago=10):
    created = NOW - timedelta(minutes=minutes_ago)
    return {
        "id": 1,
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "scenario": scenario,
        "source": {"value": ip, "cn": "DE", "as_name": "Example AS"},
    }


def test_an_unknown_address_is_reported_as_free():
    report = build_ip_report("192.0.2.10", [], [], NOW)

    assert report.blocked is False
    assert report.decisions == []
    assert report.alerts == 0
    assert report.deletable is False


def test_a_direct_ban_is_found():
    report = build_ip_report("192.0.2.10", [decision("192.0.2.10")], [], NOW)

    assert report.blocked is True
    assert report.seconds_left == 4 * 3600
    assert report.deletable is True
    # Nothing covers it through a range — the row names the address itself.
    assert report.covering_ranges == []


def test_a_covering_range_is_named():
    """This is the case the ban table structurally cannot show."""
    report = build_ip_report(
        "192.0.2.10", [decision("192.0.2.0/24", origin="lists")], [], NOW
    )

    assert report.blocked is True
    assert report.covering_ranges == ["192.0.2.0/24"]
    # Pushed centrally — a local delete would come back on the next pull.
    assert report.deletable is False


def test_the_longest_decision_decides_when_it_comes_free():
    report = build_ip_report(
        "192.0.2.10",
        [
            decision("192.0.2.10", duration="1h", decision_id=1),
            decision("192.0.2.0/24", origin="capi", duration="48h", decision_id=2),
        ],
        [],
        NOW,
    )

    assert report.seconds_left == 48 * 3600
    assert report.expires_at == NOW + timedelta(hours=48)
    # One of the two can be lifted, so the card may offer it.
    assert report.deletable is True


def test_expired_decisions_are_left_out():
    """The LAPI can return them, but they do not block anything."""
    report = build_ip_report(
        "192.0.2.10",
        [decision("192.0.2.10", duration="-2h")],
        [],
        NOW,
    )

    assert report.blocked is False
    assert report.decisions == []


def test_the_alert_history_fills_in_the_context():
    report = build_ip_report(
        "192.0.2.10",
        [],
        [
            alert(minutes_ago=60, scenario="crowdsecurity/ssh-bf"),
            alert(minutes_ago=5, scenario="crowdsecurity/http-probing"),
            alert(minutes_ago=30, scenario="crowdsecurity/ssh-bf"),
        ],
        NOW,
    )

    # Not blocked, but hardly harmless — that is the point of showing both.
    assert report.blocked is False
    assert report.alerts == 3
    assert report.first_seen == NOW - timedelta(minutes=60)
    assert report.last_seen == NOW - timedelta(minutes=5)
    assert report.scenarios == [
        "crowdsecurity/ssh-bf",
        "crowdsecurity/http-probing",
    ]
    assert report.country == "DE"
    assert report.as_name == "Example AS"


def test_simulated_alerts_do_not_count():
    report = build_ip_report("192.0.2.10", [], [{**alert(), "simulated": True}], NOW)

    assert report.alerts == 0


def test_a_failed_alert_query_is_reported_not_hidden():
    """Without the flag an outage would look like a clean record."""
    report = build_ip_report(
        "192.0.2.10", [decision("192.0.2.10")], [], NOW, alerts_available=False
    )

    assert report.blocked is True
    assert report.alerts == 0
    assert report.alerts_available is False


def test_the_answer_is_json_serialisable():
    report = build_ip_report("192.0.2.10", [decision("192.0.2.0/24")], [alert()], NOW)
    data = report.as_dict()

    assert data["target"] == "192.0.2.10"
    assert data["blocked"] is True
    assert data["covering_ranges"] == ["192.0.2.0/24"]
    assert isinstance(data["seconds_left"], int)
    assert data["expires_at"].startswith("2026-08-15T16:00")
    assert len(data["decisions"]) == 1
