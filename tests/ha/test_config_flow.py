"""Setup, reauth and options flow."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.config_entries import SOURCE_USER
from homeassistant.data_entry_flow import FlowResultType

from custom_components.crowdsec.api import (
    ENDPOINT_ALERTS,
    ENDPOINT_BOUNCER,
    ENDPOINT_LAPI,
    ENDPOINT_METRICS,
    CrowdSecAuthError,
    CrowdSecConnectionError,
)
from custom_components.crowdsec.const import DOMAIN

from .conftest import ENTRY_DATA

USER_INPUT = {
    "name": "CrowdSec",
    "metrics_url": "http://localhost:6060/metrics",
    "lapi_url": "http://localhost:8080",
    "machine_id": "hass",
    "machine_password": "secret",
    "verify_ssl": True,
}


def patch_validation(error: Exception | None = None):
    """Replace the connection test — the client itself is covered elsewhere."""
    return patch(
        "custom_components.crowdsec.config_flow.build_client",
        return_value=AsyncMock(async_validate=AsyncMock(side_effect=error)),
    )


async def start(hass, user_input=None, error=None):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    if user_input is None:
        return result
    with (
        patch_validation(error),
        patch("custom_components.crowdsec.async_setup_entry", return_value=True),
    ):
        return await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input
        )


# -- Setup ------------------------------------------------------------------


async def test_the_form_comes_up_empty(hass):
    result = await start(hass)

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {}


async def test_a_working_instance_creates_an_entry(hass):
    result = await start(hass, USER_INPUT)

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "CrowdSec"
    assert result["data"]["machine_id"] == "hass"


async def test_the_unique_id_carries_the_machine_id(hass):
    """Two engines can sit behind the same URL through different machines."""
    result = await start(hass, USER_INPUT)
    entry = hass.config_entries.async_entries(DOMAIN)[0]

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert entry.unique_id == "http://localhost:8080|hass"


async def test_the_same_instance_cannot_be_added_twice(hass):
    await start(hass, USER_INPUT)
    result = await start(hass, USER_INPUT)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_a_second_machine_on_the_same_url_is_allowed(hass):
    await start(hass, USER_INPUT)
    result = await start(hass, {**USER_INPUT, "machine_id": "hass2"})

    assert result["type"] is FlowResultType.CREATE_ENTRY


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (CrowdSecConnectionError("no route"), "cannot_connect"),
        (CrowdSecAuthError("bad password", ENDPOINT_LAPI), "invalid_auth"),
        (CrowdSecAuthError("proxy asks", ENDPOINT_METRICS), "invalid_auth_metrics"),
        (CrowdSecAuthError("no alerts", ENDPOINT_ALERTS), "invalid_auth_alerts"),
        (CrowdSecAuthError("bad key", ENDPOINT_BOUNCER), "invalid_auth_bouncer"),
        (RuntimeError("something else"), "unknown"),
    ],
)
async def test_every_access_path_gets_its_own_message(hass, error, expected):
    """Otherwise you are left guessing which one rejected you."""
    result = await start(hass, USER_INPUT, error=error)

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": expected}
    # The plain text of the failure is shown in the form, not only logged.
    assert result["description_placeholders"]["error_detail"]


def suggested_values(schema) -> dict:
    """The values Home Assistant prefills the form with."""
    return {
        str(key): (key.description or {}).get("suggested_value")
        for key in schema.schema
    }


async def test_the_secrets_are_not_prefilled_after_an_error(hass):
    """Resubmitting would otherwise silently send the same wrong value."""
    result = await start(hass, USER_INPUT, error=CrowdSecConnectionError("nope"))

    values = suggested_values(result["data_schema"])
    assert values["machine_id"] == "hass"
    assert values["machine_password"] is None
    assert values["bouncer_api_key"] is None


# -- Reauth -----------------------------------------------------------------


async def test_reauth_updates_the_credentials(hass, config_entry):
    config_entry.add_to_hass(hass)
    result = await config_entry.start_reauth_flow(hass)

    assert result["step_id"] == "reauth_confirm"

    with (
        patch_validation(),
        patch("custom_components.crowdsec.async_setup_entry", return_value=True),
    ):
        done = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"machine_id": "hass", "machine_password": "new-secret"},
        )

    assert done["type"] is FlowResultType.ABORT
    assert done["reason"] == "reauth_successful"
    assert config_entry.data["machine_password"] == "new-secret"


async def test_reauth_moves_the_unique_id_with_the_machine_id(hass, config_entry):
    """The machine ID is part of the identifier, so it has to move along."""
    config_entry.add_to_hass(hass)
    result = await config_entry.start_reauth_flow(hass)

    with (
        patch_validation(),
        patch("custom_components.crowdsec.async_setup_entry", return_value=True),
    ):
        await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"machine_id": "renamed", "machine_password": "secret"},
        )

    assert config_entry.unique_id == "http://localhost:8080|renamed"


async def test_reauth_shows_the_error_and_stays_open(hass, config_entry):
    config_entry.add_to_hass(hass)
    result = await config_entry.start_reauth_flow(hass)

    with patch_validation(CrowdSecAuthError("still wrong", ENDPOINT_LAPI)):
        again = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"machine_id": "hass", "machine_password": "wrong"},
        )

    assert again["type"] is FlowResultType.FORM
    assert again["errors"] == {"base": "invalid_auth"}


# -- Options ----------------------------------------------------------------


async def test_the_options_are_stored(hass, loaded_entry):
    result = await hass.config_entries.options.async_init(loaded_entry.entry_id)
    assert result["step_id"] == "init"

    with patch(
        "custom_components.crowdsec._async_register_card",
        AsyncMock(return_value=None),
    ):
        done = await hass.config_entries.options.async_configure(
            result["flow_id"],
            {
                "scan_interval": 90,
                "timeout": 20,
                "parse_error_threshold": 7.5,
                "bouncer_idle_intervals": 3,
                "alerts_limit": 500,
                "alerts_full_interval": 600,
                "decisions_scope": "all",
            },
        )
        await hass.async_block_till_done()

    assert done["type"] is FlowResultType.CREATE_ENTRY
    assert loaded_entry.options["decisions_scope"] == "all"
    assert loaded_entry.options["alerts_full_interval"] == 600


async def test_a_timeout_above_the_interval_is_refused(hass, loaded_entry):
    """Otherwise the polling cycles overtake each other."""
    result = await hass.config_entries.options.async_init(loaded_entry.entry_id)

    done = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            "scan_interval": 30,
            "timeout": 30,
            "parse_error_threshold": 5.0,
            "bouncer_idle_intervals": 5,
            "alerts_limit": 1000,
            "alerts_full_interval": 300,
            "decisions_scope": "local",
        },
    )

    assert done["type"] is FlowResultType.FORM
    assert done["errors"] == {"timeout": "timeout_too_long"}


async def test_a_full_refresh_below_the_interval_is_refused(hass, loaded_entry):
    """Every cycle would be a full query — exactly what it should avoid."""
    result = await hass.config_entries.options.async_init(loaded_entry.entry_id)

    done = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            "scan_interval": 300,
            "timeout": 20,
            "parse_error_threshold": 5.0,
            "bouncer_idle_intervals": 5,
            "alerts_limit": 1000,
            "alerts_full_interval": 120,
            "decisions_scope": "local",
        },
    )

    assert done["type"] is FlowResultType.FORM
    assert done["errors"] == {"alerts_full_interval": "full_interval_too_short"}


# -- Reconfigure ------------------------------------------------------------


async def test_reconfigure_changes_the_urls(hass, config_entry):
    """Without it the entry has to be deleted and rebuilt to move an address."""
    config_entry.add_to_hass(hass)
    result = await config_entry.start_reconfigure_flow(hass)

    assert result["step_id"] == "reconfigure"

    with (
        patch_validation(),
        patch("custom_components.crowdsec.async_setup_entry", return_value=True),
    ):
        done = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "metrics_url": "http://newhost:6060/metrics",
                "lapi_url": "http://newhost:8080",
                "machine_id": "hass",
                "verify_ssl": True,
            },
        )

    assert done["type"] is FlowResultType.ABORT
    assert done["reason"] == "reconfigure_successful"
    assert config_entry.data["lapi_url"] == "http://newhost:8080"
    # Left empty means unchanged — the password is not lost.
    assert config_entry.data["machine_password"] == ENTRY_DATA["machine_password"]
    assert config_entry.unique_id == "http://newhost:8080|hass"


async def test_reconfigure_can_add_a_bouncer_key(hass, config_entry):
    config_entry.add_to_hass(hass)
    result = await config_entry.start_reconfigure_flow(hass)

    with (
        patch_validation(),
        patch("custom_components.crowdsec.async_setup_entry", return_value=True),
    ):
        await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "metrics_url": ENTRY_DATA["metrics_url"],
                "lapi_url": ENTRY_DATA["lapi_url"],
                "machine_id": "hass",
                "bouncer_api_key": "fresh-key",
                "verify_ssl": True,
            },
        )

    assert config_entry.data["bouncer_api_key"] == "fresh-key"


async def test_reconfigure_reports_a_failure_without_saving(hass, config_entry):
    config_entry.add_to_hass(hass)
    result = await config_entry.start_reconfigure_flow(hass)

    with patch_validation(CrowdSecConnectionError("no route")):
        done = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "metrics_url": "http://broken:6060/metrics",
                "lapi_url": "http://broken:8080",
                "machine_id": "hass",
                "verify_ssl": True,
            },
        )

    assert done["type"] is FlowResultType.FORM
    assert done["errors"] == {"base": "cannot_connect"}
    assert config_entry.data["lapi_url"] == ENTRY_DATA["lapi_url"]


async def test_reconfigure_refuses_an_already_configured_instance(hass, config_entry):
    """Two entries with one identifier would fight over the same device."""
    config_entry.add_to_hass(hass)
    other = type(config_entry)(
        domain=DOMAIN,
        title="Other",
        data={**ENTRY_DATA, "lapi_url": "http://other:8080"},
        version=2,
        unique_id="http://other:8080|hass",
    )
    other.add_to_hass(hass)

    result = await config_entry.start_reconfigure_flow(hass)
    with patch_validation():
        done = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "metrics_url": ENTRY_DATA["metrics_url"],
                "lapi_url": "http://other:8080",
                "machine_id": "hass",
                "verify_ssl": True,
            },
        )

    assert done["type"] is FlowResultType.ABORT
    assert done["reason"] == "already_configured"
