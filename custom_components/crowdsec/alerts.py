"""Evaluation of the LAPI alert objects.

Deliberately free of Home Assistant imports: the evaluation is pure logic over
the JSON response of ``/v1/alerts`` and can therefore be tested without a
running instance. The coordinator only puts the results on its data class.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

# An alert without a usable source gets this key so that it does not disappear
# under the empty string in the distributions.
UNKNOWN = "unknown"


def _text(value: Any) -> str | None:
    """Non-empty string or ``None`` — the LAPI returns both, mixed."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def parse_timestamp(raw: Any) -> datetime | None:
    """Parse an RFC3339 timestamp from the LAPI into UTC."""
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
    """Stable identifier of an alert.

    The numeric ``id`` of the LAPI is the normal case. If it is missing — some
    versions do not include it in filtered queries — the triple of timestamp,
    scenario and source serves as a substitute. Together this is enough to
    recognise the same alert across two queries.
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
    """The source of an alert — as a rule the attacker IP."""
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
    """A ban as it goes onto the bus as an event."""

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
        """Flat dict for ``hass.bus.async_fire``."""
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
    """Everything that can be derived from a set of alerts."""

    alerts: int = 0
    ban_decisions: int = 0
    unique_sources: int = 0
    banned_sources: int = 0

    top_scenarios: list[dict[str, Any]] = field(default_factory=list)
    top_countries: list[dict[str, Any]] = field(default_factory=list)
    top_sources: list[dict[str, Any]] = field(default_factory=list)

    latest_alert: datetime | None = None
    # Identifiers of all evaluated alerts — the basis for detecting new ones in
    # the next cycle.
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
    """The most frequent entries as a list of dicts for the attributes."""
    return [
        {key: name, "alerts": count} for name, count in counter.most_common(limit)
    ]


def summarize_alerts(
    alerts: Iterable[dict[str, Any]], top_count: int
) -> AlertSummary:
    """Evaluate a list of alerts.

    Simulated alerts are left out throughout: they describe what CrowdSec
    *would have done* and would distort every metric.
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
                # Exactly one ban event per alert: several decisions on the
                # same alert are the same incident (e.g. IP and range).
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

    # The source "unknown" is a catch-all bucket, not an address of its own.
    summary.unique_sources = len([name for name in sources if name != UNKNOWN])
    summary.banned_sources = len(banned)

    summary.top_scenarios = _ranked(scenarios, "scenario", top_count)
    summary.top_countries = _ranked(countries, "country", top_count)
    summary.top_sources = _ranked(sources, "ip", top_count)

    return summary


def new_bans(summary: AlertSummary, known_ids: set[str] | None) -> list[BanRecord]:
    """The bans that have been added since the last cycle.

    ``known_ids is None`` means "first cycle": then no ban counts as new.
    Otherwise every restart of Home Assistant would dump the last 24 hours
    onto the bus as events all at once.
    """
    if known_ids is None:
        return []
    return [ban for ban in summary.bans if ban.alert_id not in known_ids]


def partition_bans(
    bans: list[BanRecord], cap: int
) -> tuple[list[BanRecord], set[str]]:
    """Split a batch of new bans into "report now" and "report later".

    A burst must not flood the event bus, but nothing may be lost either. The
    most recent bans are reported first — a notification about the ongoing
    attack is worth more than chronological order — and the identifiers of the
    remainder are returned so that the caller can keep them out of its set of
    known alerts.
    """
    if cap < 1:
        return [], {ban.alert_id for ban in bans}
    if len(bans) <= cap:
        return list(bans), set()

    ordered = sorted(
        bans,
        key=lambda ban: ban.created_at or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return ordered[:cap], {ban.alert_id for ban in ordered[cap:]}
