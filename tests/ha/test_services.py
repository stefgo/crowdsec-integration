"""The ban_ip / unban_ip / refresh services."""

from __future__ import annotations

import pytest
from homeassistant.exceptions import ServiceValidationError
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.crowdsec.api import CrowdSecConnectionError
from custom_components.crowdsec.const import (
    DOMAIN,
    SERVICE_BAN_IP,
    SERVICE_REFRESH,
    SERVICE_UNBAN_IP,
)


async def call(hass, service, data):
    await hass.services.async_call(DOMAIN, service, data, blocking=True)


async def test_ban_reaches_the_client(hass, loaded_entry, fake_client, monkeypatch):
    seen = {}

    async def fake_ban(ip, duration, reason):
        seen.update(ip=ip, duration=duration, reason=reason)

    monkeypatch.setattr(fake_client, "async_ban_ip", fake_ban)

    await call(
        hass,
        SERVICE_BAN_IP,
        {
            "config_entry_id": loaded_entry.entry_id,
            "ip": "192.0.2.55",
            "duration": "2h",
            "reason": "Test",
        },
    )

    assert seen == {"ip": "192.0.2.55", "duration": "2h", "reason": "Test"}


async def test_a_composite_duration_is_accepted(
    hass, loaded_entry, fake_client, monkeypatch
):
    """The old pattern allowed one unit only and rejected this."""
    seen = {}

    async def fake_ban(ip, duration, reason):
        seen["duration"] = duration

    monkeypatch.setattr(fake_client, "async_ban_ip", fake_ban)

    await call(
        hass,
        SERVICE_BAN_IP,
        {
            "config_entry_id": loaded_entry.entry_id,
            "ip": "192.0.2.55",
            "duration": "1h30m",
        },
    )

    assert seen["duration"] == "1h30m"


async def test_a_range_is_normalised(hass, loaded_entry, fake_client, monkeypatch):
    """CrowdSec stores the network, so that is what an unban has to match."""
    seen = {}

    async def fake_ban(ip, duration, reason):
        seen["ip"] = ip

    monkeypatch.setattr(fake_client, "async_ban_ip", fake_ban)

    await call(
        hass,
        SERVICE_BAN_IP,
        {"config_entry_id": loaded_entry.entry_id, "ip": "10.0.0.5/24"},
    )

    assert seen["ip"] == "10.0.0.0/24"


@pytest.mark.parametrize("ip", ["1.2.3.4.5", "::::", "1.2.3.4/999", "localhost"])
async def test_a_malformed_address_never_reaches_the_lapi(
    hass, loaded_entry, fake_client, monkeypatch, ip
):
    async def fake_ban(*args):
        raise AssertionError("the LAPI must not be asked at all")

    monkeypatch.setattr(fake_client, "async_ban_ip", fake_ban)

    with pytest.raises(ServiceValidationError):
        await call(
            hass, SERVICE_BAN_IP, {"config_entry_id": loaded_entry.entry_id, "ip": ip}
        )


@pytest.mark.parametrize("duration", ["1d", "4 hours", "-2h", "0s", "nonsense"])
async def test_an_unusable_duration_is_refused(
    hass, loaded_entry, fake_client, monkeypatch, duration
):
    """Go has no day unit — 1d used to be passed on and failed at the LAPI."""

    async def fake_ban(*args):
        raise AssertionError("the LAPI must not be asked at all")

    monkeypatch.setattr(fake_client, "async_ban_ip", fake_ban)

    with pytest.raises(ServiceValidationError):
        await call(
            hass,
            SERVICE_BAN_IP,
            {
                "config_entry_id": loaded_entry.entry_id,
                "ip": "192.0.2.55",
                "duration": duration,
            },
        )


async def test_unban_reports_what_the_lapi_removed(
    hass, loaded_entry, fake_client, monkeypatch
):
    seen = {}

    async def fake_unban(ip):
        seen["ip"] = ip
        return 2

    monkeypatch.setattr(fake_client, "async_unban_ip", fake_unban)

    await call(
        hass,
        SERVICE_UNBAN_IP,
        {"config_entry_id": loaded_entry.entry_id, "ip": "192.0.2.55"},
    )

    assert seen["ip"] == "192.0.2.55"


async def test_an_api_error_becomes_a_readable_message(
    hass, loaded_entry, fake_client, monkeypatch
):
    async def fake_ban(*args):
        raise CrowdSecConnectionError("LAPI unreachable")

    monkeypatch.setattr(fake_client, "async_ban_ip", fake_ban)

    with pytest.raises(ServiceValidationError) as err:
        await call(
            hass,
            SERVICE_BAN_IP,
            {"config_entry_id": loaded_entry.entry_id, "ip": "192.0.2.55"},
        )

    assert err.value.translation_key == "service_failed"


async def test_an_unknown_entry_is_refused(hass, loaded_entry):
    with pytest.raises(ServiceValidationError) as err:
        await call(
            hass,
            SERVICE_REFRESH,
            {"config_entry_id": "01ABCDEF0123456789ABCDEFGH"},
        )

    assert err.value.translation_key == "entry_not_found"


async def test_an_unloaded_entry_is_refused(hass, loaded_entry):
    other = MockConfigEntry(domain=DOMAIN, title="Other", data={}, version=2)
    other.add_to_hass(hass)

    with pytest.raises(ServiceValidationError) as err:
        await call(hass, SERVICE_REFRESH, {"config_entry_id": other.entry_id})

    assert err.value.translation_key == "entry_not_loaded"


async def test_refresh_triggers_a_cycle(hass, loaded_entry, fake_client):
    before = len(fake_client.alert_queries)

    await call(hass, SERVICE_REFRESH, {"config_entry_id": loaded_entry.entry_id})
    await hass.async_block_till_done()

    assert len(fake_client.alert_queries) > before
