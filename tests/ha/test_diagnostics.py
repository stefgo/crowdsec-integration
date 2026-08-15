"""What a diagnostics download hands out — and what it does not."""

from __future__ import annotations

from custom_components.crowdsec.diagnostics import (
    _redact_host,
    async_get_config_entry_diagnostics,
)

from .conftest import make_alert, make_decision


async def test_the_secrets_are_gone(hass, loaded_entry):
    result = await async_get_config_entry_diagnostics(hass, loaded_entry)

    config = result["config"]
    assert config["machine_password"] == "**REDACTED**"
    assert config["machine_id"] == "**REDACTED**"
    assert config["bouncer_api_key"] == "**REDACTED**"


async def test_the_host_is_gone_but_the_shape_stays(hass, loaded_entry):
    """Diagnostics get pasted into public issues; internal names must not."""
    result = await async_get_config_entry_diagnostics(hass, loaded_entry)

    assert result["config"]["lapi_url"] == "http://**REDACTED**:8080"
    assert result["config"]["metrics_url"] == "http://**REDACTED**:6060/metrics"


async def test_the_banned_addresses_are_gone(hass, loaded_entry, fake_client):
    fake_client.decisions = [make_decision(1, ip="192.0.2.77")]
    fake_client.alerts = [make_alert(1, ip="192.0.2.77")]
    await loaded_entry.runtime_data.async_refresh()

    result = await async_get_config_entry_diagnostics(hass, loaded_entry)

    assert result["data"]["top_attacker"] == "**REDACTED**"
    assert all(row["value"] == "**REDACTED**" for row in result["data"]["decisions"])
    # The shape of a row is what a support question is about — it stays.
    assert "status" in result["data"]["decisions"][0]
    assert "192.0.2.77" not in str(result)


async def test_the_raw_metrics_are_included(hass, loaded_entry):
    """Without them there is no telling what CrowdSec actually returned."""
    result = await async_get_config_entry_diagnostics(hass, loaded_entry)

    assert "cs_active_decisions" in result["metrics"]


def test_redacting_a_host_keeps_scheme_port_and_path():
    assert _redact_host("https://crowdsec.home.example:8443/x") == (
        "https://**REDACTED**:8443/x"
    )
    assert _redact_host("http://10.0.0.5:6060/metrics") == (
        "http://**REDACTED**:6060/metrics"
    )
    # No port, no path.
    assert _redact_host("http://crowdsec") == "http://**REDACTED**"
    # Nothing usable to take apart — then nothing gets through either.
    assert _redact_host("not a url") == "**REDACTED**"
    assert _redact_host("") == ""
    assert _redact_host(None) is None
