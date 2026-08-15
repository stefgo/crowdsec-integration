"""Fixtures for the tests that need a real Home Assistant.

These are deliberately separate from ``tests/`` next door: that suite runs on
nothing but pytest and must stay that way, because the modules it covers are
the ones without a framework dependency. Everything here needs the real thing —
config flows, the reauth path, the WebSocket commands and the service registry
cannot be faked usefully.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.crowdsec.const import (
    CONF_BOUNCER_API_KEY,
    CONF_LAPI_URL,
    CONF_MACHINE_ID,
    CONF_MACHINE_PASSWORD,
    CONF_METRICS_URL,
    DOMAIN,
)
from custom_components.crowdsec.metrics import MetricSet, parse_prometheus

ENTRY_DATA = {
    "name": "CrowdSec",
    CONF_METRICS_URL: "http://localhost:6060/metrics",
    CONF_LAPI_URL: "http://localhost:8080",
    CONF_MACHINE_ID: "hass",
    CONF_MACHINE_PASSWORD: "secret",
    CONF_BOUNCER_API_KEY: "bouncer-key",
}

# Just enough of the Prometheus output for the coordinator to derive something
# from it — the parser itself is covered by the framework-free suite.
METRICS_TEXT = """
# HELP cs_info Information about CrowdSec.
# TYPE cs_info gauge
cs_info{version="v1.6.3"} 1
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.7e+09
# TYPE cs_active_decisions gauge
cs_active_decisions{action="ban",reason="crowdsecurity/ssh-bf"} 7
# TYPE cs_parser_hits_ok_total counter
cs_parser_hits_ok_total{source="file"} 1000
# TYPE cs_parser_hits_ko_total counter
cs_parser_hits_ko_total{source="file"} 10
# TYPE cs_lapi_route_requests_total counter
cs_lapi_route_requests_total{endpoint="/v1/decisions/stream",method="GET"} 50
"""


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Let Home Assistant find custom_components/crowdsec at all."""
    return enable_custom_integrations


@pytest.fixture
def metrics() -> MetricSet:
    return MetricSet(parse_prometheus(METRICS_TEXT))


def make_alert(
    alert_id: int = 1,
    ip: str = "192.0.2.10",
    scenario: str = "crowdsecurity/ssh-bf",
    created_at: str = "2026-08-15T11:59:00Z",
    ban: bool = True,
) -> dict[str, Any]:
    """One alert in the shape the LAPI returns it."""
    return {
        "id": alert_id,
        "created_at": created_at,
        "scenario": scenario,
        "source": {"value": ip, "ip": ip, "cn": "DE", "as_name": "Example AS"},
        "decisions": (
            [
                {
                    "id": alert_id * 100,
                    "type": "ban" if ban else "captcha",
                    "duration": "4h",
                    "value": ip,
                    "scope": "Ip",
                    "origin": "crowdsec",
                }
            ]
            if ban
            else []
        ),
    }


def make_decision(
    decision_id: int = 1,
    ip: str = "192.0.2.10",
    origin: str = "crowdsec",
    duration: str = "3h59m",
) -> dict[str, Any]:
    """One entry of ``/v1/decisions``."""
    return {
        "id": decision_id,
        "origin": origin,
        "type": "ban",
        "scope": "Ip",
        "value": ip,
        "duration": duration,
        "scenario": "crowdsecurity/ssh-bf",
    }


class FakeClient:
    """A stand-in for CrowdSecClient that records what it was asked for."""

    def __init__(self, metrics: MetricSet) -> None:
        from custom_components.crowdsec.api import AlertResult

        self._metrics = metrics
        self.alerts: list[dict[str, Any]] = []
        self.decisions: list[dict[str, Any]] | None = []
        self.alerts_truncated = False
        # (since, limit) of every alert query — this is how the two-speed
        # polling is checked.
        self.alert_queries: list[tuple[str, int]] = []
        self.decision_queries: list[Any] = []
        self.metrics_error: Exception | None = None
        self.alerts_error: Exception | None = None
        self.decisions_error: Exception | None = None
        # The real client sets this when a bouncer key would be the way
        # out of an unreadable decision list.
        self.decisions_need_bouncer_key = False
        self._AlertResult = AlertResult

    async def async_get_metrics(self) -> MetricSet:
        if self.metrics_error:
            raise self.metrics_error
        return self._metrics

    async def async_get_alerts(self, since: str = "24h", limit: int = 1000):
        self.alert_queries.append((since, limit))
        if self.alerts_error:
            raise self.alerts_error
        return self._AlertResult(list(self.alerts), self.alerts_truncated)

    async def async_get_decisions(self, origins=None):
        self.decision_queries.append(origins)
        if self.decisions_error:
            raise self.decisions_error
        return None if self.decisions is None else list(self.decisions)

    async def async_ban_ip(self, ip, duration, reason):
        return None

    async def async_unban_ip(self, ip):
        return 1

    async def async_delete_decision(self, decision_id):
        return 1


@pytest.fixture
def fake_client(metrics: MetricSet) -> FakeClient:
    return FakeClient(metrics)


@pytest.fixture
def config_entry() -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        title="CrowdSec",
        data=ENTRY_DATA,
        options={},
        version=2,
        unique_id="http://localhost:8080|hass",
    )


@pytest.fixture
async def loaded_entry(hass, config_entry: MockConfigEntry, fake_client: FakeClient):
    """A set-up entry whose client is the fake one."""
    config_entry.add_to_hass(hass)
    with (
        patch(
            "custom_components.crowdsec.build_client",
            return_value=fake_client,
        ),
        # The card build is not in a checkout, and its absence is only a
        # warning — the registration itself is covered by its own test.
        patch(
            "custom_components.crowdsec._async_register_card",
            AsyncMock(return_value=None),
        ),
    ):
        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done()
    return config_entry
