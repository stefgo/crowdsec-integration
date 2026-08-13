"""Auswertung der Alert-Objekte der LAPI.

Bewusst frei von Home-Assistant-Importen: Die Auswertung ist reine Logik über
die JSON-Antwort von ``/v1/alerts`` und lässt sich damit ohne laufende Instanz
testen. Der Coordinator legt nur noch die Ergebnisse auf seine Datenklasse.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

# Ein Alert ohne verwertbare Quelle bekommt diesen Schlüssel, damit er in den
# Verteilungen nicht unter dem leeren String verschwindet.
UNKNOWN = "unknown"


def _text(value: Any) -> str | None:
    """Nicht-leerer String oder ``None`` — die LAPI liefert beides gemischt."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def parse_timestamp(raw: Any) -> datetime | None:
    """Parse einen RFC3339-Zeitstempel der LAPI nach UTC."""
    text = _text(raw)
    if text is None:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def alert_id(alert: dict[str, Any]) -> str | None:
    """Stabile Kennung eines Alerts.

    Die numerische ``id`` der LAPI ist der Normalfall. Fehlt sie — manche
    Versionen liefern sie bei gefilterten Abfragen nicht mit —, dient das
    Tripel aus Zeitpunkt, Szenario und Quelle als Ersatz. Beides zusammen
    reicht, um denselben Alert über zwei Abfragen hinweg wiederzuerkennen.
    """
    raw_id = alert.get("id")
    if isinstance(raw_id, (int, float)) and not isinstance(raw_id, bool):
        return f"id:{int(raw_id)}"
    if isinstance(raw_id, str) and raw_id.strip():
        return f"id:{raw_id.strip()}"

    created = _text(alert.get("created_at")) or _text(alert.get("start_at"))
    scenario = _text(alert.get("scenario"))
    source = source_value(alert)
    if created is None and scenario is None and source is None:
        return None
    return f"fp:{created}|{scenario}|{source}"


def source_value(alert: dict[str, Any]) -> str | None:
    """Die Quelle eines Alerts — in aller Regel die Angreifer-IP."""
    source = alert.get("source")
    if not isinstance(source, dict):
        return None
    return _text(source.get("value")) or _text(source.get("ip"))


def _source_field(alert: dict[str, Any], key: str) -> str | None:
    source = alert.get("source")
    if not isinstance(source, dict):
        return None
    return _text(source.get(key))


@dataclass(frozen=True, slots=True)
class BanRecord:
    """Ein Ban, wie er als Event an den Bus geht."""

    alert_id: str
    ip: str | None
    scenario: str | None
    country: str | None
    as_name: str | None
    duration: str | None
    scope: str | None
    value: str | None
    created_at: datetime | None

    def as_event_data(self) -> dict[str, Any]:
        """Flaches Dict für ``hass.bus.async_fire``."""
        return {
            "alert_id": self.alert_id,
            "ip": self.ip,
            "scenario": self.scenario,
            "country": self.country,
            "as_name": self.as_name,
            "duration": self.duration,
            "scope": self.scope,
            "value": self.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


@dataclass(slots=True)
class AlertSummary:
    """Alles, was sich aus einem Satz Alerts ableiten lässt."""

    alerts: int = 0
    ban_decisions: int = 0
    unique_sources: int = 0
    banned_sources: int = 0

    top_scenarios: list[dict[str, Any]] = field(default_factory=list)
    top_countries: list[dict[str, Any]] = field(default_factory=list)
    top_sources: list[dict[str, Any]] = field(default_factory=list)

    latest_alert: datetime | None = None
    # Kennungen aller gewerteten Alerts — Grundlage der Neuerkennung im
    # nächsten Zyklus.
    seen_ids: set[str] = field(default_factory=set)
    bans: list[BanRecord] = field(default_factory=list)

    @property
    def top_scenario(self) -> str | None:
        return self.top_scenarios[0]["scenario"] if self.top_scenarios else None

    @property
    def top_country(self) -> str | None:
        return self.top_countries[0]["country"] if self.top_countries else None

    @property
    def top_source(self) -> str | None:
        return self.top_sources[0]["ip"] if self.top_sources else None


def _ranked(
    counter: Counter[str], key: str, limit: int
) -> list[dict[str, Any]]:
    """Die häufigsten Einträge als Liste von Dicts für die Attribute."""
    return [
        {key: name, "alerts": count} for name, count in counter.most_common(limit)
    ]


def summarize_alerts(
    alerts: Iterable[dict[str, Any]], top_count: int
) -> AlertSummary:
    """Werte eine Alert-Liste aus.

    Simulierte Alerts bleiben durchgehend außen vor: Sie beschreiben, was
    CrowdSec *getan hätte*, und würden jede Kennzahl verfälschen.
    """
    summary = AlertSummary()
    scenarios: Counter[str] = Counter()
    countries: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    banned: set[str] = set()

    for alert in alerts:
        if not isinstance(alert, dict) or alert.get("simulated"):
            continue

        summary.alerts += 1

        identifier = alert_id(alert)
        if identifier is not None:
            summary.seen_ids.add(identifier)

        scenario = _text(alert.get("scenario"))
        if scenario is not None:
            scenarios[scenario] += 1

        ip = source_value(alert)
        sources[ip or UNKNOWN] += 1
        countries[_source_field(alert, "cn") or UNKNOWN] += 1

        created = parse_timestamp(alert.get("created_at")) or parse_timestamp(
            alert.get("start_at")
        )
        if created is not None and (
            summary.latest_alert is None or created > summary.latest_alert
        ):
            summary.latest_alert = created

        ban_seen = False
        for decision in alert.get("decisions") or []:
            if not isinstance(decision, dict):
                continue
            if str(decision.get("type", "")).lower() != "ban":
                continue
            summary.ban_decisions += 1
            if ip is not None:
                banned.add(ip)
            if ban_seen or identifier is None:
                # Pro Alert genau ein Ban-Event: mehrere Decisions am selben
                # Alert sind derselbe Vorgang (z. B. IP und Range).
                continue
            ban_seen = True
            summary.bans.append(
                BanRecord(
                    alert_id=identifier,
                    ip=ip,
                    scenario=scenario,
                    country=_source_field(alert, "cn"),
                    as_name=_source_field(alert, "as_name"),
                    duration=_text(decision.get("duration")),
                    scope=_text(decision.get("scope")),
                    value=_text(decision.get("value")),
                    created_at=created,
                )
            )

    # Die Quelle „unknown" ist ein Sammelposten und keine eigene Adresse.
    summary.unique_sources = len([name for name in sources if name != UNKNOWN])
    summary.banned_sources = len(banned)

    summary.top_scenarios = _ranked(scenarios, "scenario", top_count)
    summary.top_countries = _ranked(countries, "country", top_count)
    summary.top_sources = _ranked(sources, "ip", top_count)

    return summary


def new_bans(summary: AlertSummary, known_ids: set[str] | None) -> list[BanRecord]:
    """Die Bans, die seit dem letzten Zyklus dazugekommen sind.

    ``known_ids is None`` heißt „erster Zyklus": Dann gilt kein Ban als neu.
    Sonst würde jeder Neustart von Home Assistant die letzten 24 Stunden auf
    einen Schlag als Events ausschütten.
    """
    if known_ids is None:
        return []
    return [ban for ban in summary.bans if ban.alert_id not in known_ids]
