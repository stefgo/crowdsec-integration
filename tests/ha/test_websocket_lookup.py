"""The lookup and ban commands behind the IP lookup card."""

from __future__ import annotations

from itertools import count

import pytest

from custom_components.crowdsec.api import CrowdSecConnectionError
from custom_components.crowdsec.const import WS_IP_BAN, WS_IP_LOOKUP

from .conftest import make_alert, make_decision

_next_id = count(1000)


@pytest.fixture
async def ws(hass, hass_ws_client, loaded_entry):
    return await hass_ws_client(hass)


async def send(ws, message):
    await ws.send_json({"id": next(_next_id), **message})
    return await ws.receive_json()


async def lookup(ws, entry, ip="192.0.2.10"):
    return await send(
        ws, {"type": WS_IP_LOOKUP, "config_entry_id": entry.entry_id, "ip": ip}
    )


# -- Lookup -----------------------------------------------------------------


async def test_an_unknown_address_comes_back_clean(ws, loaded_entry, fake_client):
    fake_client.lookup_decisions = []

    result = await lookup(ws, loaded_entry)

    assert result["success"]
    assert result["result"]["blocked"] is False
    assert result["result"]["decisions"] == []
    assert result["result"]["decisions_available"] is True


async def test_a_covering_range_is_found(ws, loaded_entry, fake_client):
    """The whole point: the ban table cannot show this."""
    fake_client.lookup_decisions = [make_decision(1, ip="192.0.2.0/24", origin="lists")]

    result = await lookup(ws, loaded_entry)

    assert result["result"]["blocked"] is True
    assert result["result"]["covering_ranges"] == ["192.0.2.0/24"]
    assert result["result"]["deletable"] is False


async def test_the_lookup_ignores_the_configured_scope(ws, loaded_entry, fake_client):
    """decisions_scope filters the table, never the question about one address."""
    fake_client.lookup_decisions = [make_decision(1, ip="192.0.2.10", origin="CAPI")]

    result = await lookup(ws, loaded_entry)

    assert result["result"]["blocked"] is True
    assert len(result["result"]["decisions"]) == 1


async def test_the_alert_history_travels_along(ws, loaded_entry, fake_client):
    fake_client.lookup_decisions = []
    fake_client.lookup_alerts = [
        make_alert(1, ip="192.0.2.10"),
        make_alert(2, ip="192.0.2.10", scenario="crowdsecurity/http-probing"),
    ]

    result = await lookup(ws, loaded_entry)

    # Not blocked but far from unknown — that combination is what makes the
    # lookup worth having.
    assert result["result"]["blocked"] is False
    assert result["result"]["alerts"] == 2
    assert result["result"]["country"] == "DE"
    assert len(result["result"]["scenarios"]) == 2


async def test_a_failed_alert_query_keeps_the_decisions(ws, loaded_entry, fake_client):
    fake_client.lookup_decisions = [make_decision(1, ip="192.0.2.10")]
    fake_client.lookup_alerts_error = CrowdSecConnectionError("alerts down")

    result = await lookup(ws, loaded_entry)

    assert result["success"]
    assert result["result"]["blocked"] is True
    assert result["result"]["alerts_available"] is False


async def test_a_failed_decision_query_is_an_error(ws, loaded_entry, fake_client):
    """ "Not blocked" would be a lie when the route is closed."""
    fake_client.lookup_error = CrowdSecConnectionError("lapi down")

    result = await lookup(ws, loaded_entry)

    assert not result["success"]
    assert result["error"]["code"] == "request_failed"


async def test_an_unreadable_decision_route_is_flagged(ws, loaded_entry, fake_client):
    fake_client.lookup_decisions = None

    result = await lookup(ws, loaded_entry)

    assert result["result"]["decisions_available"] is False


async def test_the_address_is_normalised_before_it_travels(
    ws, loaded_entry, fake_client
):
    await lookup(ws, loaded_entry, ip="  2001:0db8::1  ")

    assert fake_client.lookup_queries[-1] == "2001:db8::1"


@pytest.mark.parametrize("ip", ["1.2.3.4.5", "::::", "not-an-ip", ""])
async def test_a_malformed_address_is_refused(ws, loaded_entry, fake_client, ip):
    result = await lookup(ws, loaded_entry, ip=ip)

    assert not result["success"]
    assert result["error"]["code"] == "invalid_target"
    assert fake_client.lookup_queries == []


# -- Banning ----------------------------------------------------------------


async def test_a_ban_reaches_the_client(ws, loaded_entry, fake_client):
    result = await send(
        ws,
        {
            "type": WS_IP_BAN,
            "config_entry_id": loaded_entry.entry_id,
            "ip": "192.0.2.55",
            "duration": "2h",
            "reason": "From the card",
        },
    )

    assert result["success"]
    assert fake_client.bans == [("192.0.2.55", "2h", "From the card")]


async def test_a_ban_answers_with_the_fresh_state(ws, loaded_entry, fake_client):
    """So the click shows its own result without a second round trip."""
    fake_client.lookup_decisions = [make_decision(1, ip="192.0.2.55", origin="cscli")]

    result = await send(
        ws,
        {
            "type": WS_IP_BAN,
            "config_entry_id": loaded_entry.entry_id,
            "ip": "192.0.2.55",
        },
    )

    assert result["result"]["blocked"] is True
    assert result["result"]["deletable"] is True


async def test_a_ban_uses_the_defaults(ws, loaded_entry, fake_client):
    await send(
        ws,
        {
            "type": WS_IP_BAN,
            "config_entry_id": loaded_entry.entry_id,
            "ip": "192.0.2.55",
        },
    )

    assert fake_client.bans == [("192.0.2.55", "4h", "Home Assistant")]


@pytest.mark.parametrize("duration", ["1d", "nonsense", "-2h", "0s"])
async def test_an_unusable_duration_never_reaches_the_lapi(
    ws, loaded_entry, fake_client, duration
):
    result = await send(
        ws,
        {
            "type": WS_IP_BAN,
            "config_entry_id": loaded_entry.entry_id,
            "ip": "192.0.2.55",
            "duration": duration,
        },
    )

    assert not result["success"]
    assert result["error"]["code"] == "invalid_duration"
    assert fake_client.bans == []


async def test_a_ban_on_a_malformed_address_is_refused(ws, loaded_entry, fake_client):
    result = await send(
        ws,
        {
            "type": WS_IP_BAN,
            "config_entry_id": loaded_entry.entry_id,
            "ip": "1.2.3.4.5",
        },
    )

    assert not result["success"]
    assert result["error"]["code"] == "invalid_target"
    assert fake_client.bans == []


async def test_a_range_ban_is_normalised(ws, loaded_entry, fake_client):
    """CrowdSec stores the network, so a later unban has to match it."""
    await send(
        ws,
        {
            "type": WS_IP_BAN,
            "config_entry_id": loaded_entry.entry_id,
            "ip": "10.0.0.5/24",
        },
    )

    assert fake_client.bans[0][0] == "10.0.0.0/24"


async def test_a_rejected_ban_is_reported(ws, loaded_entry, fake_client):
    fake_client.ban_error = CrowdSecConnectionError("lapi down")

    result = await send(
        ws,
        {
            "type": WS_IP_BAN,
            "config_entry_id": loaded_entry.entry_id,
            "ip": "192.0.2.55",
        },
    )

    assert not result["success"]
    assert result["error"]["code"] == "request_failed"


async def test_a_non_admin_cannot_ban(
    hass, hass_ws_client, hass_admin_user, loaded_entry, fake_client
):
    hass_admin_user.groups = []
    client = await hass_ws_client(hass)

    result = await send(
        client,
        {
            "type": WS_IP_BAN,
            "config_entry_id": loaded_entry.entry_id,
            "ip": "192.0.2.55",
        },
    )

    assert not result["success"]
    assert result["error"]["code"] == "unauthorized"
    assert fake_client.bans == []
