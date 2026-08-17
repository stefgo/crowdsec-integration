"""The measured values of a CrowdSec instance."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import CrowdSecConfigEntry, CrowdSecData
from .entity import CrowdSecEntity

# State values in Home Assistant are limited to 255 characters.
MAX_STATE_LENGTH = 255

# Language-neutral unit for the rates: Home Assistant does not translate
# ``native_unit_of_measurement``, so a localised "lines/min" would show up in
# every language. What is counted is stated by the entity name.
UNIT_PER_MINUTE = "1/min"
UNIT_LINES = "lines"


def _from_metrics(data: CrowdSecData) -> bool:
    """Values read off the Prometheus endpoint."""
    return data.metrics_ok


def _from_alerts(data: CrowdSecData) -> bool:
    """Values derived from the LAPI alert window."""
    return data.alerts_ok


@dataclass(frozen=True, kw_only=True)
class CrowdSecSensorDescription(SensorEntityDescription):
    """Description with a value and an attribute function."""

    value_fn: Callable[[CrowdSecData], float | int | str | datetime | None]
    attrs_fn: Callable[[CrowdSecData], dict[str, Any]] | None = None
    # Which of the coordinator's queries the value comes from. A cycle can lose
    # one of them and keep the others, so a sensor waits on its own source
    # instead of on the cycle as a whole. Most values come off the metrics
    # endpoint, so that is the default; the alert-derived ones say so.
    source_fn: Callable[[CrowdSecData], bool] = _from_metrics
    # Timestamps stay valid even when a scrape fails.
    survives_outage: bool = False


SENSORS: tuple[CrowdSecSensorDescription, ...] = (
    CrowdSecSensorDescription(
        key="scrape_duration",
        translation_key="scrape_duration",
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        suggested_display_precision=2,
        survives_outage=True,
        value_fn=lambda data: data.scrape_duration,
    ),
    CrowdSecSensorDescription(
        key="last_restart",
        translation_key="last_restart",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        survives_outage=True,
        value_fn=lambda data: data.last_restart,
    ),
    CrowdSecSensorDescription(
        key="last_update",
        translation_key="last_update",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        survives_outage=True,
        value_fn=lambda data: data.last_update,
    ),
    CrowdSecSensorDescription(
        key="active_decisions",
        translation_key="active_decisions",
        icon="mdi:shield-lock",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.active_decisions,
        attrs_fn=lambda data: {
            "by_reason": data.decisions_by_reason,
            "by_action": data.decisions_by_action,
        },
    ),
    CrowdSecSensorDescription(
        key="new_bans_24h",
        translation_key="new_bans_24h",
        icon="mdi:gavel",
        state_class=SensorStateClass.MEASUREMENT,
        source_fn=_from_alerts,
        value_fn=lambda data: data.new_bans_24h,
        attrs_fn=lambda data: {
            "alerts_24h": data.alerts_24h,
            "banned_attackers_24h": data.banned_attackers_24h,
            "truncated": data.alerts_truncated,
        },
    ),
    CrowdSecSensorDescription(
        key="unique_attackers_24h",
        translation_key="unique_attackers_24h",
        icon="mdi:account-multiple-outline",
        state_class=SensorStateClass.MEASUREMENT,
        source_fn=_from_alerts,
        value_fn=lambda data: data.unique_attackers_24h,
        attrs_fn=lambda data: {
            "banned": data.banned_attackers_24h,
            "top_attackers": data.top_attackers,
        },
    ),
    CrowdSecSensorDescription(
        key="top_scenario_24h",
        translation_key="top_scenario_24h",
        icon="mdi:target",
        source_fn=_from_alerts,
        value_fn=lambda data: data.top_scenario,
        attrs_fn=lambda data: {"top_scenarios": data.top_scenarios},
    ),
    CrowdSecSensorDescription(
        key="top_country_24h",
        translation_key="top_country_24h",
        icon="mdi:earth",
        source_fn=_from_alerts,
        value_fn=lambda data: data.top_country,
        attrs_fn=lambda data: {"top_countries": data.top_countries},
    ),
    CrowdSecSensorDescription(
        key="top_attacker_24h",
        translation_key="top_attacker_24h",
        icon="mdi:crosshairs-gps",
        source_fn=_from_alerts,
        value_fn=lambda data: data.top_attacker,
        attrs_fn=lambda data: {"top_attackers": data.top_attackers},
    ),
    CrowdSecSensorDescription(
        key="last_alert",
        translation_key="last_alert",
        device_class=SensorDeviceClass.TIMESTAMP,
        icon="mdi:clock-alert-outline",
        source_fn=_from_alerts,
        survives_outage=True,
        value_fn=lambda data: data.last_alert,
    ),
    CrowdSecSensorDescription(
        key="active_buckets",
        translation_key="active_buckets",
        icon="mdi:bucket-outline",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.active_buckets,
        attrs_fn=lambda data: {"by_scenario": data.buckets_by_name},
    ),
    CrowdSecSensorDescription(
        key="lines_total",
        translation_key="lines_total",
        icon="mdi:file-document-outline",
        native_unit_of_measurement=UNIT_LINES,
        # The counter runs since the start of the service and jumps back on a
        # restart; TOTAL_INCREASING absorbs exactly that and therefore yields
        # usable daily and weekly sums.
        state_class=SensorStateClass.TOTAL_INCREASING,
        entity_category=EntityCategory.DIAGNOSTIC,
        suggested_display_precision=0,
        value_fn=lambda data: data.lines_total,
    ),
    CrowdSecSensorDescription(
        key="lines_per_minute",
        translation_key="lines_per_minute",
        icon="mdi:file-document-multiple-outline",
        native_unit_of_measurement=UNIT_PER_MINUTE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda data: data.lines_per_minute,
    ),
    CrowdSecSensorDescription(
        key="parse_error_rate",
        translation_key="parse_error_rate",
        icon="mdi:alert-decagram-outline",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=2,
        value_fn=lambda data: data.parse_error_rate,
    ),
    CrowdSecSensorDescription(
        key="bouncer_queries_per_minute",
        translation_key="bouncer_queries_per_minute",
        icon="mdi:transit-connection-variant",
        native_unit_of_measurement=UNIT_PER_MINUTE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda data: data.bouncer_queries_per_minute,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CrowdSecConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Create the sensors of an instance."""
    coordinator = entry.runtime_data
    async_add_entities(
        CrowdSecSensor(coordinator, entry, description) for description in SENSORS
    )


class CrowdSecSensor(CrowdSecEntity, SensorEntity):
    """A single measured value."""

    entity_description: CrowdSecSensorDescription

    @property
    def available(self) -> bool:
        """Diagnostic values stay available, measured values do not.

        When a query fails, the counters and rates *it* feeds must not live on
        with stale values — "Last update" and "Last restart" should, because
        that is exactly when they provide the context.

        Deliberately per source rather than per cycle: the three queries are
        independent, and letting a stuttering alert route blank the numbers of
        a metrics scrape that succeeded would put gaps into the recorder's
        statistics for data that was never in doubt.
        """
        if self.coordinator.data is None:
            return False
        if self.entity_description.survives_outage:
            return True
        return self.entity_description.source_fn(self.coordinator.data)

    @property
    def native_value(self) -> float | int | str | datetime | None:
        value = self.entity_description.value_fn(self.data)
        if isinstance(value, str) and len(value) > MAX_STATE_LENGTH:
            return value[:MAX_STATE_LENGTH]
        return value

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs_fn is None:
            return None
        return self.entity_description.attrs_fn(self.data)
