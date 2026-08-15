"""The update cycle: error routing, problem flag, ban events, alert polling."""

from __future__ import annotations

import pytest
from homeassistant.exceptions import ConfigEntryAuthFailed

from custom_components.crowdsec.api import (
    ENDPOINT_ALERTS,
    ENDPOINT_DECISIONS,
    ENDPOINT_LAPI,
    CrowdSecAuthError,
    CrowdSecConnectionError,
)
from custom_components.crowdsec.const import (
    EVENT_NEW_BAN,
    LOCAL_ORIGINS,
    MAX_DECISION_ROWS,
)

from .conftest import make_alert, make_decision


async def refresh(hass, coordinator):
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    return coordinator.data


# -- Error routing ----------------------------------------------------------


async def test_a_rejected_login_asks_for_reauth(hass, loaded_entry, fake_client):
    """Only the login itself means the credentials are wrong."""
    coordinator = loaded_entry.runtime_data
    fake_client.alerts_error = CrowdSecAuthError("nope", ENDPOINT_LAPI)

    with pytest.raises(ConfigEntryAuthFailed):
        await coordinator._async_update_data()


@pytest.mark.parametrize("endpoint", [ENDPOINT_ALERTS, ENDPOINT_DECISIONS])
async def test_a_single_denied_route_keeps_the_entry_alive(
    hass, loaded_entry, fake_client, endpoint
):
    """A valid token refused on one route says nothing about the credentials."""
    coordinator = loaded_entry.runtime_data
    fake_client.alerts_error = CrowdSecAuthError("denied here", endpoint)

    data = await refresh(hass, coordinator)

    assert data.reachable is False
    assert any("denied here" in message for message in data.errors)
    # The metrics still came through, so their values are there.
    assert data.version == "v1.6.3"


async def test_a_connection_error_becomes_a_message_not_an_exception(
    hass, loaded_entry, fake_client
):
    coordinator = loaded_entry.runtime_data
    fake_client.decisions_error = CrowdSecConnectionError("timeout")

    data = await refresh(hass, coordinator)

    assert data.reachable is False
    assert data.errors == ["timeout"]


async def test_an_unexpected_error_is_not_swallowed(hass, loaded_entry, fake_client):
    """Anything unforeseen must not quietly pass as "not reachable"."""
    coordinator = loaded_entry.runtime_data
    fake_client.metrics_error = RuntimeError("bug")

    with pytest.raises(RuntimeError):
        await coordinator._async_update_data()


async def test_a_failed_decision_query_keeps_the_previous_table(
    hass, loaded_entry, fake_client
):
    """The card must not show "no bans" for an instance that is merely down."""
    coordinator = loaded_entry.runtime_data
    fake_client.decisions = [make_decision(1)]
    first = await refresh(hass, coordinator)
    assert len(first.decisions) == 1

    fake_client.decisions_error = CrowdSecConnectionError("gone")
    second = await refresh(hass, coordinator)

    assert second.decisions_available is False
    assert len(second.decisions) == 1


async def test_timestamps_survive_an_outage(hass, loaded_entry, fake_client):
    coordinator = loaded_entry.runtime_data
    fake_client.alerts = [make_alert(1)]
    good = await refresh(hass, coordinator)
    assert good.last_update is not None

    fake_client.metrics_error = CrowdSecConnectionError("down")
    bad = await refresh(hass, coordinator)

    # last_update keeps pointing at the last *successful* cycle — that is how
    # an automation recognises stale values.
    assert bad.last_update == good.last_update
    assert bad.last_restart == good.last_restart
    assert bad.last_alert == good.last_alert


# -- Two-speed alert polling ------------------------------------------------


async def test_the_first_cycle_asks_for_the_whole_window(
    hass, loaded_entry, fake_client
):
    assert fake_client.alert_queries[0][0] == "24h"


async def test_the_following_cycles_only_ask_for_what_is_new(
    hass, loaded_entry, fake_client
):
    coordinator = loaded_entry.runtime_data
    fake_client.alert_queries.clear()

    await refresh(hass, coordinator)

    since = fake_client.alert_queries[-1][0]
    assert since.endswith("m")
    # Elapsed time plus the deliberate overlap — a couple of minutes, not 24h.
    assert int(since[:-1]) <= 5


async def test_a_new_alert_is_merged_into_the_window(hass, loaded_entry, fake_client):
    """The incremental result has to add to the aggregates, not replace them."""
    coordinator = loaded_entry.runtime_data
    fake_client.alerts = [make_alert(1, ip="192.0.2.1"), make_alert(2, ip="192.0.2.2")]
    first = await refresh(hass, coordinator)
    assert first.alerts_24h == 2

    # The incremental query only sees the newcomer.
    fake_client.alerts = [make_alert(3, ip="192.0.2.3")]
    second = await refresh(hass, coordinator)

    assert second.alerts_24h == 3
    assert second.unique_attackers_24h == 3


async def test_the_overlap_does_not_count_an_alert_twice(
    hass, loaded_entry, fake_client
):
    coordinator = loaded_entry.runtime_data
    fake_client.alerts = [make_alert(1), make_alert(2)]
    await refresh(hass, coordinator)

    # The overlapping window returns alert 2 again.
    fake_client.alerts = [make_alert(2), make_alert(3)]
    data = await refresh(hass, coordinator)

    assert data.alerts_24h == 3


async def test_a_manual_refresh_forces_the_full_window(hass, loaded_entry, fake_client):
    coordinator = loaded_entry.runtime_data
    await refresh(hass, coordinator)
    fake_client.alert_queries.clear()

    coordinator.request_full_alert_poll()
    await refresh(hass, coordinator)

    assert fake_client.alert_queries[-1][0] == "24h"


async def test_truncation_survives_until_a_full_query_clears_it(
    hass, loaded_entry, fake_client
):
    coordinator = loaded_entry.runtime_data
    fake_client.alerts_truncated = True
    assert (await refresh(hass, coordinator)).alerts_truncated is True

    # An incremental query that is not truncated cannot prove the window is
    # complete again — only a full one can.
    fake_client.alerts_truncated = False
    assert (await refresh(hass, coordinator)).alerts_truncated is True

    coordinator.request_full_alert_poll()
    assert (await refresh(hass, coordinator)).alerts_truncated is False


# -- Ban events -------------------------------------------------------------


async def test_the_first_cycle_stays_silent(hass, config_entry, fake_client):
    """A restart must not dump the last 24 hours onto the bus."""
    from unittest.mock import AsyncMock, patch

    events = []
    hass.bus.async_listen(EVENT_NEW_BAN, lambda event: events.append(event))

    fake_client.alerts = [make_alert(i) for i in range(1, 4)]
    config_entry.add_to_hass(hass)
    with (
        patch("custom_components.crowdsec.build_client", return_value=fake_client),
        patch(
            "custom_components.crowdsec._async_register_card",
            AsyncMock(return_value=None),
        ),
    ):
        await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done()

    assert events == []


async def test_a_new_ban_fires_exactly_one_event(hass, loaded_entry, fake_client):
    coordinator = loaded_entry.runtime_data
    events = []
    hass.bus.async_listen(EVENT_NEW_BAN, lambda event: events.append(event))

    fake_client.alerts = [make_alert(7, ip="192.0.2.7")]
    await refresh(hass, coordinator)
    await hass.async_block_till_done()

    assert len(events) == 1
    assert events[0].data["ip"] == "192.0.2.7"
    assert events[0].data["entry_id"] == loaded_entry.entry_id

    # The same alert in the next cycle is not new any more.
    await refresh(hass, coordinator)
    await hass.async_block_till_done()
    assert len(events) == 1


async def test_a_burst_is_capped_and_the_remainder_follows_later(
    hass, loaded_entry, fake_client
):
    """Nothing is dropped — the rest is reported in the following cycles."""
    coordinator = loaded_entry.runtime_data
    events = []
    hass.bus.async_listen(EVENT_NEW_BAN, lambda event: events.append(event))

    fake_client.alerts = [make_alert(i, ip=f"192.0.2.{i}") for i in range(1, 41)]
    await refresh(hass, coordinator)
    await hass.async_block_till_done()
    assert len(events) == 25

    await refresh(hass, coordinator)
    await hass.async_block_till_done()
    assert len(events) == 40


# -- Decisions --------------------------------------------------------------


async def test_the_query_is_restricted_to_local_origins_by_default(
    hass, loaded_entry, fake_client
):
    assert fake_client.decision_queries[0] == LOCAL_ORIGINS


async def test_the_scope_option_can_ask_for_everything(hass, config_entry, fake_client):
    from unittest.mock import AsyncMock, patch

    config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        config_entry, options={"decisions_scope": "all"}
    )
    with (
        patch("custom_components.crowdsec.build_client", return_value=fake_client),
        patch(
            "custom_components.crowdsec._async_register_card",
            AsyncMock(return_value=None),
        ),
    ):
        await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done()

    assert fake_client.decision_queries[0] is None


async def test_with_a_local_scope_the_metric_keeps_the_sensor(
    hass, loaded_entry, fake_client
):
    """Counting the restricted list would lose the CAPI and blocklist bans."""
    coordinator = loaded_entry.runtime_data
    fake_client.decisions = [make_decision(1), make_decision(2, ip="192.0.2.11")]

    data = await refresh(hass, coordinator)

    assert len(data.decisions) == 2
    # cs_active_decisions from the fixture says 7.
    assert data.active_decisions == 7
    assert data.decisions_local_only is True


async def test_the_table_is_capped(hass, loaded_entry, fake_client):
    coordinator = loaded_entry.runtime_data
    fake_client.decisions = [
        make_decision(i, ip=f"10.0.{i // 255}.{i % 255}")
        for i in range(MAX_DECISION_ROWS + 50)
    ]

    data = await refresh(hass, coordinator)

    assert len(data.decisions) == MAX_DECISION_ROWS
    assert data.decisions_truncated is True


# -- Problem flag -----------------------------------------------------------


async def test_the_parse_error_rate_raises_the_problem_flag(
    hass, config_entry, fake_client
):
    from unittest.mock import AsyncMock, patch

    config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        config_entry, options={"parse_error_threshold": 0.5}
    )
    with (
        patch("custom_components.crowdsec.build_client", return_value=fake_client),
        patch(
            "custom_components.crowdsec._async_register_card",
            AsyncMock(return_value=None),
        ),
    ):
        await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done()

    data = config_entry.runtime_data.data
    # 10 of 1010 parses failed — just under 1 %, above the 0.5 % threshold.
    assert data.problem is True
    assert any("Parse error rate" in reason for reason in data.problem_reasons)


async def test_an_unreachable_instance_is_a_problem(hass, loaded_entry, fake_client):
    coordinator = loaded_entry.runtime_data
    fake_client.metrics_error = CrowdSecConnectionError("down")

    data = await refresh(hass, coordinator)

    assert data.problem is True
    assert "down" in data.problem_reasons
