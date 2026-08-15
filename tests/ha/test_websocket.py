"""The WebSocket commands behind the Lovelace card."""

from __future__ import annotations

from itertools import count
from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.crowdsec.const import (
    DOMAIN,
    WS_DECISIONS_DELETE,
    WS_DECISIONS_LIST,
    WS_INSTANCES,
)

from .conftest import ENTRY_DATA, make_decision


@pytest.fixture
async def ws(hass, hass_ws_client, loaded_entry):
    return await hass_ws_client(hass)


_next_id = count(1)


async def send(ws, message):
    """One command, one answer — with an id the client has not used yet."""
    await ws.send_json({"id": next(_next_id), **message})
    return await ws.receive_json()


# -- Listing ----------------------------------------------------------------


async def test_instances_are_listed(ws, loaded_entry):
    result = await send(ws, {"type": WS_INSTANCES})

    assert result["success"]
    assert result["result"]["instances"] == [
        {
            "config_entry_id": loaded_entry.entry_id,
            "title": "CrowdSec",
            "loaded": True,
        }
    ]


async def test_the_list_reports_the_total_next_to_the_page(
    hass, ws, loaded_entry, fake_client
):
    fake_client.decisions = [make_decision(i, ip=f"192.0.2.{i}") for i in range(1, 21)]
    await loaded_entry.runtime_data.async_refresh()

    result = await send(
        ws,
        {
            "type": WS_DECISIONS_LIST,
            "config_entry_id": loaded_entry.entry_id,
            "limit": 5,
        },
    )

    assert result["success"]
    assert len(result["result"]["decisions"]) == 5
    assert result["result"]["total"] == 20
    assert result["result"]["local_only"] is True


async def test_the_offset_walks_through_the_table(hass, ws, loaded_entry, fake_client):
    fake_client.decisions = [make_decision(i, ip=f"192.0.2.{i}") for i in range(1, 21)]
    await loaded_entry.runtime_data.async_refresh()

    first = await send(
        ws,
        {
            "type": WS_DECISIONS_LIST,
            "config_entry_id": loaded_entry.entry_id,
            "limit": 15,
        },
    )
    second = await send(
        ws,
        {
            "type": WS_DECISIONS_LIST,
            "config_entry_id": loaded_entry.entry_id,
            "limit": 15,
            "offset": 15,
        },
    )

    assert len(second["result"]["decisions"]) == 5
    keys = {row["key"] for row in first["result"]["decisions"]}
    assert not keys & {row["key"] for row in second["result"]["decisions"]}


async def test_a_refresh_asks_for_the_full_alert_window(
    hass, ws, loaded_entry, fake_client
):
    fake_client.alert_queries.clear()

    await send(
        ws,
        {
            "type": WS_DECISIONS_LIST,
            "config_entry_id": loaded_entry.entry_id,
            "refresh": True,
        },
    )

    assert fake_client.alert_queries[-1][0] == "24h"


async def test_an_unknown_entry_is_refused(ws):
    result = await send(
        ws, {"type": WS_DECISIONS_LIST, "config_entry_id": "does-not-exist"}
    )

    assert not result["success"]
    assert result["error"]["code"] == "entry_not_found"


async def test_an_unloaded_entry_is_refused(hass, ws, loaded_entry):
    await hass.config_entries.async_unload(loaded_entry.entry_id)
    await hass.async_block_till_done()

    result = await send(
        ws, {"type": WS_DECISIONS_LIST, "config_entry_id": loaded_entry.entry_id}
    )

    assert not result["success"]
    assert result["error"]["code"] == "entry_not_loaded"


# -- Deleting ---------------------------------------------------------------


async def test_a_local_decision_can_be_removed(hass, ws, loaded_entry, fake_client):
    fake_client.decisions = [make_decision(1, ip="192.0.2.10")]
    await loaded_entry.runtime_data.async_refresh()

    result = await send(
        ws,
        {
            "type": WS_DECISIONS_DELETE,
            "config_entry_id": loaded_entry.entry_id,
            "decision_id": 1,
        },
    )

    assert result["success"]
    assert result["result"]["deleted"] == 1
    assert "total" in result["result"]


async def test_a_capi_decision_is_refused(hass, ws, loaded_entry, fake_client):
    """Deleting it locally would only last until the next pull."""
    fake_client.decisions = [make_decision(2, ip="192.0.2.20", origin="CAPI")]
    await loaded_entry.runtime_data.async_refresh()

    result = await send(
        ws,
        {
            "type": WS_DECISIONS_DELETE,
            "config_entry_id": loaded_entry.entry_id,
            "decision_id": 2,
        },
    )

    assert not result["success"]
    assert result["error"]["code"] == "not_deletable"


async def test_an_address_with_only_central_decisions_is_refused(
    hass, ws, loaded_entry, fake_client
):
    fake_client.decisions = [
        make_decision(3, ip="192.0.2.30", origin="lists"),
        make_decision(4, ip="192.0.2.30", origin="CAPI"),
    ]
    await loaded_entry.runtime_data.async_refresh()

    result = await send(
        ws,
        {
            "type": WS_DECISIONS_DELETE,
            "config_entry_id": loaded_entry.entry_id,
            "ip": "192.0.2.30",
        },
    )

    assert not result["success"]
    assert result["error"]["code"] == "not_deletable"


async def test_an_address_with_one_local_decision_may_go(
    hass, ws, loaded_entry, fake_client
):
    fake_client.decisions = [
        make_decision(5, ip="192.0.2.40", origin="CAPI"),
        make_decision(6, ip="192.0.2.40", origin="cscli"),
    ]
    await loaded_entry.runtime_data.async_refresh()

    result = await send(
        ws,
        {
            "type": WS_DECISIONS_DELETE,
            "config_entry_id": loaded_entry.entry_id,
            "ip": "192.0.2.40",
        },
    )

    assert result["success"]


async def test_a_malformed_address_is_refused(ws, loaded_entry):
    """The command is a public interface, not only the card's back door."""
    result = await send(
        ws,
        {
            "type": WS_DECISIONS_DELETE,
            "config_entry_id": loaded_entry.entry_id,
            "ip": "1.2.3.4.5",
        },
    )

    assert not result["success"]
    assert result["error"]["code"] == "invalid_target"


async def test_a_delete_without_a_target_is_refused(ws, loaded_entry):
    result = await send(
        ws,
        {
            "type": WS_DECISIONS_DELETE,
            "config_entry_id": loaded_entry.entry_id,
        },
    )

    assert not result["success"]
    assert result["error"]["code"] == "invalid_target"


# -- Permissions ------------------------------------------------------------


async def test_a_non_admin_gets_nothing(
    hass, hass_ws_client, hass_admin_user, loaded_entry
):
    hass_admin_user.groups = []
    client = await hass_ws_client(hass)

    result = await send(client, {"type": WS_INSTANCES})

    assert not result["success"]
    assert result["error"]["code"] == "unauthorized"


async def test_an_entry_of_another_domain_is_refused(hass, ws):
    other = MockConfigEntry(domain="sun", data={})
    other.add_to_hass(hass)

    result = await send(
        ws, {"type": WS_DECISIONS_LIST, "config_entry_id": other.entry_id}
    )

    assert not result["success"]
    assert result["error"]["code"] == "entry_not_found"


async def test_a_second_instance_shows_up_in_the_picker(
    hass, ws, loaded_entry, fake_client
):
    second = MockConfigEntry(
        domain=DOMAIN,
        title="CrowdSec 2",
        data={**ENTRY_DATA, "lapi_url": "http://other:8080"},
        version=2,
        unique_id="http://other:8080|hass",
    )
    second.add_to_hass(hass)
    with (
        patch("custom_components.crowdsec.build_client", return_value=fake_client),
        patch(
            "custom_components.crowdsec._async_register_card",
            AsyncMock(return_value=None),
        ),
    ):
        await hass.config_entries.async_setup(second.entry_id)
        await hass.async_block_till_done()

    result = await send(ws, {"type": WS_INSTANCES})

    titles = [entry["title"] for entry in result["result"]["instances"]]
    assert titles == ["CrowdSec", "CrowdSec 2"]
