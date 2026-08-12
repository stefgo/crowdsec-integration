"""Gemeinsame Basis aller CrowdSec-Entitäten."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import EntityDescription
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_LAPI_URL, DOMAIN
from .coordinator import CrowdSecConfigEntry, CrowdSecCoordinator, CrowdSecData


class CrowdSecEntity(CoordinatorEntity[CrowdSecCoordinator]):
    """Bindet eine Entität an das Gerät ihrer Instanz."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: CrowdSecCoordinator,
        entry: CrowdSecConfigEntry,
        description: EntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.title,
            manufacturer="CrowdSec",
            model="Security Engine",
            sw_version=coordinator.data.version if coordinator.data else None,
            configuration_url=entry.data.get(CONF_LAPI_URL),
        )

    @property
    def data(self) -> CrowdSecData:
        """Aktueller Datenstand des Coordinators."""
        return self.coordinator.data
