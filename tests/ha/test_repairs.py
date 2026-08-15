"""The repair that offers to add a bouncer API key."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.helpers import issue_registry as ir
from homeassistant.setup import async_setup_component

from custom_components.crowdsec.api import (
    ENDPOINT_BOUNCER,
    CrowdSecAuthError,
    CrowdSecConnectionError,
)
from custom_components.crowdsec.const import DOMAIN, ISSUE_DECISIONS_UNAVAILABLE
from custom_components.crowdsec.repairs import async_create_fix_flow


async def issue_for(hass, entry):
    registry = ir.async_get(hass)
    return registry.async_get_issue(
        DOMAIN, f"{ISSUE_DECISIONS_UNAVAILABLE}_{entry.entry_id}"
    )


async def test_no_issue_while_the_list_can_be_read(hass, loaded_entry):
    assert await issue_for(hass, loaded_entry) is None


async def test_an_issue_appears_when_the_key_is_missing(
    hass, loaded_entry, fake_client
):
    """So far the only trace of this was a warning in the log."""
    fake_client.decisions = None
    fake_client.decisions_need_bouncer_key = True

    await loaded_entry.runtime_data.async_refresh()
    await hass.async_block_till_done()

    issue = await issue_for(hass, loaded_entry)
    assert issue is not None
    assert issue.is_fixable is True
    assert issue.severity is ir.IssueSeverity.WARNING


async def test_the_issue_goes_away_again(hass, loaded_entry, fake_client):
    fake_client.decisions = None
    fake_client.decisions_need_bouncer_key = True
    await loaded_entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    assert await issue_for(hass, loaded_entry) is not None

    fake_client.decisions = []
    fake_client.decisions_need_bouncer_key = False
    await loaded_entry.runtime_data.async_refresh()
    await hass.async_block_till_done()

    assert await issue_for(hass, loaded_entry) is None


async def test_the_flow_stores_a_working_key(hass, loaded_entry):
    await async_setup_component(hass, "repairs", {})
    flow = await async_create_fix_flow(
        hass,
        f"{ISSUE_DECISIONS_UNAVAILABLE}_{loaded_entry.entry_id}",
        {"entry_id": loaded_entry.entry_id},
    )
    flow.hass = hass

    with (
        patch(
            "custom_components.crowdsec.build_client",
            return_value=AsyncMock(
                async_get_active_decision_count=AsyncMock(return_value=3)
            ),
        ),
        patch(
            "custom_components.crowdsec._async_register_card",
            AsyncMock(return_value=None),
        ),
    ):
        result = await flow.async_step_confirm({"bouncer_api_key": "fresh"})
        await hass.async_block_till_done()

    assert result["type"] == "create_entry"
    assert loaded_entry.data["bouncer_api_key"] == "fresh"


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (CrowdSecAuthError("rejected", ENDPOINT_BOUNCER), "invalid_auth_bouncer"),
        (CrowdSecConnectionError("no route"), "cannot_connect"),
    ],
)
async def test_a_bad_key_is_not_stored(hass, loaded_entry, error, expected):
    await async_setup_component(hass, "repairs", {})
    before = loaded_entry.data["bouncer_api_key"]
    flow = await async_create_fix_flow(
        hass,
        f"{ISSUE_DECISIONS_UNAVAILABLE}_{loaded_entry.entry_id}",
        {"entry_id": loaded_entry.entry_id},
    )
    flow.hass = hass

    with patch(
        "custom_components.crowdsec.build_client",
        return_value=AsyncMock(
            async_get_active_decision_count=AsyncMock(side_effect=error)
        ),
    ):
        result = await flow.async_step_confirm({"bouncer_api_key": "wrong"})

    assert result["type"] == "form"
    assert result["errors"] == {"base": expected}
    assert loaded_entry.data["bouncer_api_key"] == before


async def test_the_flow_gives_up_if_the_instance_was_removed(hass, loaded_entry):
    """The repair can sit in the list longer than the entry it belongs to."""
    await async_setup_component(hass, "repairs", {})
    flow = await async_create_fix_flow(
        hass,
        f"{ISSUE_DECISIONS_UNAVAILABLE}_{loaded_entry.entry_id}",
        {"entry_id": loaded_entry.entry_id},
    )
    flow.hass = hass
    await hass.config_entries.async_remove(loaded_entry.entry_id)
    await hass.async_block_till_done()

    result = await flow.async_step_init()

    assert result["type"] == "abort"
    assert result["reason"] == "entry_not_found"


async def test_an_unknown_issue_is_refused(hass):
    with pytest.raises(ValueError):
        await async_create_fix_flow(hass, "something_else", {})
