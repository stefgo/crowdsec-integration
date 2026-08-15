"""Setup, migration and teardown of a config entry."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from homeassistant.config_entries import ConfigEntryState
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.crowdsec.const import (
    CONF_LAPI_URL,
    CONF_MACHINE_ID,
    CONF_MACHINE_PASSWORD,
    CONF_METRICS_URL,
    DOMAIN,
    SERVICE_BAN_IP,
    SERVICE_REFRESH,
    SERVICE_UNBAN_IP,
)

from .conftest import ENTRY_DATA


async def test_setup_creates_entities_and_services(hass, loaded_entry):
    assert loaded_entry.state is ConfigEntryState.LOADED
    for service in (SERVICE_BAN_IP, SERVICE_UNBAN_IP, SERVICE_REFRESH):
        assert hass.services.has_service(DOMAIN, service)

    state = hass.states.get("sensor.crowdsec_active_decisions")
    assert state is not None


async def test_unload_removes_the_services_with_the_last_entry(hass, loaded_entry):
    assert await hass.config_entries.async_unload(loaded_entry.entry_id)
    await hass.async_block_till_done()

    assert loaded_entry.state is ConfigEntryState.NOT_LOADED
    assert not hass.services.has_service(DOMAIN, SERVICE_BAN_IP)


async def test_the_services_survive_while_a_second_entry_is_loaded(
    hass, loaded_entry, fake_client
):
    """Unloading one instance must not disarm the services of the other."""
    second = MockConfigEntry(
        domain=DOMAIN,
        title="CrowdSec 2",
        data={**ENTRY_DATA, CONF_LAPI_URL: "http://other:8080"},
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
        assert await hass.config_entries.async_setup(second.entry_id)
        await hass.async_block_till_done()

    assert await hass.config_entries.async_unload(loaded_entry.entry_id)
    await hass.async_block_till_done()

    assert hass.services.has_service(DOMAIN, SERVICE_BAN_IP)


async def test_migration_from_version_1_adds_the_machine_id(hass, fake_client):
    """Version 1 identified an instance by its LAPI address alone."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="CrowdSec",
        data={
            "name": "CrowdSec",
            CONF_METRICS_URL: "http://localhost:6060/metrics",
            CONF_LAPI_URL: "http://localhost:8080",
            CONF_MACHINE_ID: "hass",
            CONF_MACHINE_PASSWORD: "secret",
        },
        version=1,
        unique_id="http://localhost:8080",
    )
    entry.add_to_hass(hass)

    with (
        patch("custom_components.crowdsec.build_client", return_value=fake_client),
        patch(
            "custom_components.crowdsec._async_register_card",
            AsyncMock(return_value=None),
        ),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    assert entry.version == 2
    assert entry.unique_id == "http://localhost:8080|hass"


async def test_an_entry_from_a_newer_version_is_refused(hass):
    """A downgrade must not touch data it does not understand."""
    entry = MockConfigEntry(domain=DOMAIN, title="CrowdSec", data=ENTRY_DATA, version=3)
    entry.add_to_hass(hass)

    assert not await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.MIGRATION_ERROR


async def test_the_options_reload_the_entry(hass, loaded_entry):
    """The coordinator reads its options once, so a change has to reload."""
    with (
        patch(
            "custom_components.crowdsec.build_client",
            return_value=hass.config_entries.async_get_entry(
                loaded_entry.entry_id
            ).runtime_data.client,
        ),
        patch(
            "custom_components.crowdsec._async_register_card",
            AsyncMock(return_value=None),
        ),
    ):
        hass.config_entries.async_update_entry(
            loaded_entry, options={"scan_interval": 120}
        )
        await hass.async_block_till_done()

    coordinator = loaded_entry.runtime_data
    assert coordinator.update_interval.total_seconds() == 120
