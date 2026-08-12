"""Binäre Sensoren: Erreichbarkeit und Sammelstörung."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import CrowdSecConfigEntry, CrowdSecData
from .entity import CrowdSecEntity


@dataclass(frozen=True, kw_only=True)
class CrowdSecBinarySensorDescription(BinarySensorEntityDescription):
    """Beschreibung mit Wert- und Attributfunktion."""

    value_fn: Callable[[CrowdSecData], bool]
    attrs_fn: Callable[[CrowdSecData], dict[str, Any]] | None = None


BINARY_SENSORS: tuple[CrowdSecBinarySensorDescription, ...] = (
    CrowdSecBinarySensorDescription(
        key="reachable",
        translation_key="reachable",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        value_fn=lambda data: data.reachable,
        attrs_fn=lambda data: {"errors": data.errors},
    ),
    CrowdSecBinarySensorDescription(
        key="problem",
        translation_key="problem",
        device_class=BinarySensorDeviceClass.PROBLEM,
        value_fn=lambda data: data.problem,
        attrs_fn=lambda data: {"reasons": data.problem_reasons},
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CrowdSecConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Lege die binären Sensoren einer Instanz an."""
    coordinator = entry.runtime_data
    async_add_entities(
        CrowdSecBinarySensor(coordinator, entry, description)
        for description in BINARY_SENSORS
    )


class CrowdSecBinarySensor(CrowdSecEntity, BinarySensorEntity):
    """Erreichbarkeit bzw. Sammelstörung einer Instanz."""

    entity_description: CrowdSecBinarySensorDescription

    @property
    def available(self) -> bool:
        """Bewusst immer verfügbar.

        Diese beiden Entitäten *melden* den Ausfall — sie dürfen bei einem
        fehlgeschlagenen Scrape nicht selbst auf ``unavailable`` gehen.
        """
        return self.coordinator.data is not None

    @property
    def is_on(self) -> bool:
        return self.entity_description.value_fn(self.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs_fn is None:
            return None
        return self.entity_description.attrs_fn(self.data)
