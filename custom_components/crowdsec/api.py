"""HTTP-Client für den Metrics-Endpunkt und die LAPI einer CrowdSec-Instanz."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, NamedTuple

import aiohttp

from .alerts import alert_id
from .const import (
    ALERTS_SINCE,
    DECISION_ORIGIN,
    DEFAULT_ALERTS_LIMIT,
    DEFAULT_BAN_DURATION,
    DEFAULT_BAN_REASON,
    DEFAULT_TIMEOUT,
    MAX_WINDOW_SPLITS,
    USER_AGENT,
)
from .metrics import MetricSet, parse_prometheus
from .timewindow import Window, parse_duration, split_window, window_params

_LOGGER = logging.getLogger(__name__)

# Das JWT der LAPI läuft nach einer Stunde ab; kurz vorher erneuern.
TOKEN_REFRESH_MARGIN = timedelta(minutes=2)
TOKEN_FALLBACK_TTL = timedelta(minutes=50)

# Die Zugänge einer Instanz. Nur ENDPOINT_LAPI — der Login selbst — bedeutet
# falsche Zugangsdaten; die übrigen dürfen einzeln ausfallen, ohne die
# Integration lahmzulegen.
ENDPOINT_METRICS = "metrics"
ENDPOINT_LAPI = "lapi"
ENDPOINT_ALERTS = "alerts"
ENDPOINT_BOUNCER = "bouncer"


class CrowdSecError(Exception):
    """Basisfehler der Integration."""


class CrowdSecConnectionError(CrowdSecError):
    """Instanz war nicht erreichbar oder hat unbrauchbar geantwortet."""


class CrowdSecAuthError(CrowdSecError):
    """Anmeldedaten wurden abgelehnt.

    ``endpoint`` benennt den Zugang, der abgelehnt hat — die drei sind
    unabhängig voneinander und die Meldung soll sagen, welcher klemmt.
    """

    def __init__(self, message: str, endpoint: str = ENDPOINT_LAPI) -> None:
        super().__init__(message)
        self.endpoint = endpoint


class AlertResult(NamedTuple):
    """Ergebnis einer Alert-Abfrage samt Hinweis auf Vollständigkeit."""

    alerts: list[dict[str, Any]]
    truncated: bool


def _fingerprint(secret: str) -> str:
    """Gekürzter SHA-256 eines Geheimnisses für den Soll-Ist-Vergleich im Log."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:8]


def _parse_expiry(raw: Any) -> datetime | None:
    """Parse das RFC3339-Ablaufdatum aus der Login-Antwort."""
    if not isinstance(raw, str):
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class CrowdSecClient:
    """Kapselt beide Endpunkte einer Instanz."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        *,
        metrics_url: str,
        lapi_url: str,
        machine_id: str,
        machine_password: str,
        bouncer_api_key: str | None = None,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._session = session
        self._metrics_url = metrics_url.rstrip("/")
        self._lapi_url = lapi_url.rstrip("/")
        # Beim Kopieren aus der cscli-Ausgabe rutscht leicht Leerraum mit. Die
        # ID hat nie welchen, beim Passwort wird nur gewarnt statt korrigiert.
        self._machine_id = machine_id.strip()
        self._machine_password = machine_password
        if machine_password != machine_password.strip():
            _LOGGER.warning(
                "Das Machine-Passwort beginnt oder endet mit Leerraum — beim "
                "Kopieren mit übernommen?"
            )
        self._bouncer_api_key = bouncer_api_key or None
        self._ssl: bool | None = None if verify_ssl else False
        # Ohne eigenen User-Agent erbt die Anfrage den von Home Assistant, und
        # CrowdSec lehnt den Login ab, weil er sich nicht als name/version
        # parsen lässt.
        self._headers = {"User-Agent": USER_AGENT}
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._token: str | None = None
        self._token_expires: datetime | None = None
        self._login_lock = asyncio.Lock()

    @property
    def has_bouncer_key(self) -> bool:
        """Ob exakte Decision-Abfragen über die Bouncer-API möglich sind."""
        return self._bouncer_api_key is not None

    # -- Metrics ----------------------------------------------------------

    async def async_get_metrics(self) -> MetricSet:
        """Scrape den Prometheus-Endpunkt."""
        try:
            async with self._session.get(
                self._metrics_url,
                headers=self._headers,
                ssl=self._ssl,
                timeout=self._timeout,
            ) as response:
                if response.status in (401, 403):
                    raise CrowdSecAuthError(
                        f"Metrics-Endpunkt verweigert den Zugriff ({response.status})",
                        ENDPOINT_METRICS,
                    )
                if response.status != 200:
                    raise CrowdSecConnectionError(
                        f"Metrics-Endpunkt antwortete mit HTTP {response.status}"
                    )
                text = await response.text()
        except asyncio.TimeoutError as err:
            raise CrowdSecConnectionError("Zeitüberschreitung beim Metrics-Scrape") from err
        except aiohttp.ClientError as err:
            raise CrowdSecConnectionError(f"Metrics-Endpunkt nicht erreichbar: {err}") from err

        if not text.strip():
            raise CrowdSecConnectionError("Metrics-Endpunkt lieferte eine leere Antwort")
        return MetricSet(parse_prometheus(text))

    # -- LAPI -------------------------------------------------------------

    async def _async_token(self, force: bool = False) -> str:
        """Liefere ein gültiges Machine-JWT, ggf. per Login."""
        async with self._login_lock:
            now = datetime.now(timezone.utc)
            if (
                not force
                and self._token is not None
                and self._token_expires is not None
                and now < self._token_expires - TOKEN_REFRESH_MARGIN
            ):
                return self._token

            payload = {
                "machine_id": self._machine_id,
                "password": self._machine_password,
            }
            url = f"{self._lapi_url}/v1/watchers/login"
            try:
                async with self._session.post(
                    url,
                    json=payload,
                    headers=self._headers,
                    ssl=self._ssl,
                    timeout=self._timeout,
                ) as response:
                    body = await response.text()
                    # Länge und gekürzter Hash statt Passwort: genug, um einen
                    # Tippfehler gegen den Sollwert zu prüfen, aber nicht
                    # umkehrbar.
                    _LOGGER.debug(
                        "LAPI-Login an %s für machine_id %r "
                        "(Passwort: %d Zeichen, sha256 %s): HTTP %s, %d Byte Antwort",
                        url,
                        self._machine_id,
                        len(self._machine_password),
                        _fingerprint(self._machine_password),
                        response.status,
                        len(body),
                    )
                    if response.status in (401, 403):
                        raise CrowdSecAuthError(
                            f"LAPI wies den Login ab (HTTP {response.status}): "
                            f"{body.strip()[:200]}",
                            ENDPOINT_LAPI,
                        )
                    if response.status != 200:
                        raise CrowdSecConnectionError(
                            f"LAPI-Login antwortete mit HTTP {response.status}: "
                            f"{body.strip()[:200]}"
                        )
                    try:
                        data = json.loads(body) if body.strip() else None
                    except ValueError as err:
                        raise CrowdSecConnectionError(
                            "LAPI-Login lieferte kein JSON — antwortet dort wirklich "
                            "CrowdSec und kein Proxy?"
                        ) from err
            except asyncio.TimeoutError as err:
                raise CrowdSecConnectionError("Zeitüberschreitung beim LAPI-Login") from err
            except aiohttp.ClientError as err:
                raise CrowdSecConnectionError(f"LAPI nicht erreichbar: {err}") from err

            token = (data or {}).get("token")
            if not token:
                # HTTP 200 ohne Token ist kein Anmeldefehler, sondern eine
                # unerwartete Antwort — die beiden nicht vermischen.
                raise CrowdSecConnectionError(
                    "LAPI-Login antwortete mit 200, aber ohne Token: "
                    f"{sorted((data or {}).keys())}"
                )

            self._token = token
            self._token_expires = _parse_expiry((data or {}).get("expire")) or (
                datetime.now(timezone.utc) + TOKEN_FALLBACK_TTL
            )
            return token

    async def _async_lapi_request(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        payload: Any = None,
    ) -> Any:
        """Anfrage an die LAPI mit Machine-Auth, einmaliger Retry bei 401."""
        for attempt in range(2):
            token = await self._async_token(force=attempt > 0)
            try:
                async with self._session.request(
                    method,
                    f"{self._lapi_url}{path}",
                    params=params,
                    json=payload,
                    headers={**self._headers, "Authorization": f"Bearer {token}"},
                    ssl=self._ssl,
                    timeout=self._timeout,
                ) as response:
                    if response.status in (401, 403):
                        if attempt == 0:
                            # Token evtl. serverseitig verfallen: neu anmelden.
                            continue
                        body = await response.text()
                        raise CrowdSecAuthError(
                            f"LAPI verweigert {path} trotz gültigem Token "
                            f"(HTTP {response.status}): {body.strip()[:200]}",
                            ENDPOINT_ALERTS,
                        )
                    if response.status not in (200, 201):
                        body = await response.text()
                        raise CrowdSecConnectionError(
                            f"LAPI {path} antwortete mit HTTP {response.status}: "
                            f"{body.strip()[:200]}"
                        )
                    return await response.json(content_type=None)
            except asyncio.TimeoutError as err:
                raise CrowdSecConnectionError(
                    f"Zeitüberschreitung bei LAPI {path}"
                ) from err
            except aiohttp.ClientError as err:
                raise CrowdSecConnectionError(f"LAPI {path} fehlgeschlagen: {err}") from err

        raise CrowdSecAuthError(f"LAPI verweigert {path}", ENDPOINT_ALERTS)

    async def _async_alerts_window(
        self, window: Window, limit: int
    ) -> list[dict[str, Any]]:
        """Eine einzelne Alert-Abfrage über ein Zeitfenster."""
        params = {**window_params(window), "limit": str(limit)}
        data = await self._async_lapi_request("GET", "/v1/alerts", params)
        if not data:
            return []
        if not isinstance(data, list):
            raise CrowdSecConnectionError("LAPI /v1/alerts lieferte kein Array")
        return [alert for alert in data if isinstance(alert, dict)]

    async def async_get_alerts(
        self, since: str = ALERTS_SINCE, limit: int = DEFAULT_ALERTS_LIMIT
    ) -> AlertResult:
        """Alerts eines Zeitfensters, standardmäßig der letzten 24 Stunden.

        Die LAPI kennt keine Pagination: Bei mehr Treffern als ``limit``
        schneidet sie ab. Passiert das, wird das Zeitfenster halbiert und in
        Teilen erneut abgefragt. Erst wenn auch ein Fenster von einer Minute
        noch anschlägt oder die Teilungstiefe erschöpft ist, gilt das Ergebnis
        als abgeschnitten.
        """
        minutes = parse_duration(since)
        if minutes is None:
            raise ValueError(f"Unbrauchbares Zeitfenster: {since!r}")

        collected: dict[str, dict[str, Any]] = {}
        truncated = False
        # (Fenster, verbleibende Teilungen) — iterativ statt rekursiv, damit
        # die Zahl der Anfragen jederzeit ablesbar bleibt.
        pending: list[tuple[Window, int]] = [(Window(minutes, 0), MAX_WINDOW_SPLITS)]

        while pending:
            window, splits_left = pending.pop(0)
            alerts = await self._async_alerts_window(window, limit)

            if len(alerts) < limit:
                self._collect(collected, alerts)
                continue

            halves = split_window(window) if splits_left > 0 else None
            if halves is None:
                # Nicht weiter teilbar: das Teilergebnis ist besser als nichts,
                # aber die Zahlen sind unvollständig.
                self._collect(collected, alerts)
                truncated = True
                _LOGGER.debug(
                    "Alert-Fenster %s liefert weiterhin %d Treffer am Limit — "
                    "Ergebnis unvollständig",
                    window,
                    len(alerts),
                )
                continue

            pending.extend((half, splits_left - 1) for half in halves)

        return AlertResult(list(collected.values()), truncated)

    @staticmethod
    def _collect(
        target: dict[str, dict[str, Any]], alerts: list[dict[str, Any]]
    ) -> None:
        """Übernimm Alerts und halte Überschneidungen der Fenster heraus."""
        for index, alert in enumerate(alerts):
            key = alert_id(alert) or f"anon:{len(target)}:{index}"
            target.setdefault(key, alert)

    # -- Decisions setzen und löschen -------------------------------------

    async def async_ban_ip(
        self,
        ip: str,
        duration: str = DEFAULT_BAN_DURATION,
        reason: str = DEFAULT_BAN_REASON,
    ) -> None:
        """Setze eine Ban-Decision über einen selbst erzeugten Alert.

        Die LAPI kennt keinen Weg, eine Decision einzeln anzulegen — sie hängt
        immer an einem Alert. Genau das macht ``cscli decisions add`` auch.
        """
        now = datetime.now(timezone.utc).isoformat()
        scenario = f"manual '{reason}' from 'hass'"
        alert = {
            "scenario": scenario,
            "scenario_hash": "",
            "scenario_version": "",
            "message": reason,
            "events_count": 1,
            "start_at": now,
            "stop_at": now,
            "capacity": 0,
            "leakspeed": "0",
            "simulated": False,
            "events": [],
            "remediation": True,
            "labels": None,
            "source": {"scope": "Ip", "value": ip, "ip": ip},
            "decisions": [
                {
                    "duration": duration,
                    "origin": DECISION_ORIGIN,
                    "scenario": scenario,
                    "scope": "Ip",
                    "type": "ban",
                    "value": ip,
                }
            ],
        }
        await self._async_lapi_request("POST", "/v1/alerts", payload=[alert])

    async def async_unban_ip(self, ip: str) -> int:
        """Lösche alle Decisions zu einer IP; liefert deren Anzahl."""
        data = await self._async_lapi_request(
            "DELETE", "/v1/decisions", {"scope": "Ip", "value": ip}
        )
        if isinstance(data, dict):
            raw = data.get("nbDeleted")
            try:
                return int(raw)
            except (TypeError, ValueError):
                return 0
        return 0

    async def async_get_active_decision_count(self) -> int | None:
        """Anzahl aktiver Decisions über die Bouncer-API.

        ``None``, wenn kein Bouncer-Key konfiguriert ist oder der Endpunkt
        nichts zu melden hat — dann übernimmt die Metrik
        ``cs_active_decisions``.
        """
        if self._bouncer_api_key is None:
            return None
        try:
            async with self._session.get(
                f"{self._lapi_url}/v1/decisions",
                headers={**self._headers, "X-Api-Key": self._bouncer_api_key},
                ssl=self._ssl,
                timeout=self._timeout,
            ) as response:
                if response.status in (401, 403):
                    raise CrowdSecAuthError(
                        "Bouncer-API-Key wurde abgelehnt", ENDPOINT_BOUNCER
                    )
                if response.status == 404:
                    # Nicht jede CrowdSec-Version liefert hier ein leeres
                    # Array — ein 404 heißt "nichts vorhanden", nicht "kaputt".
                    _LOGGER.debug(
                        "/v1/decisions antwortete mit 404, Fallback auf die Metrik"
                    )
                    return None
                if response.status != 200:
                    raise CrowdSecConnectionError(
                        f"LAPI /v1/decisions antwortete mit HTTP {response.status}"
                    )
                data = await response.json(content_type=None)
        except asyncio.TimeoutError as err:
            raise CrowdSecConnectionError("Zeitüberschreitung bei /v1/decisions") from err
        except aiohttp.ClientError as err:
            raise CrowdSecConnectionError(f"/v1/decisions fehlgeschlagen: {err}") from err

        if not data:
            return 0
        if not isinstance(data, list):
            raise CrowdSecConnectionError("LAPI /v1/decisions lieferte kein Array")
        return len(data)

    async def async_validate(self) -> None:
        """Prüfe alle Zugänge, die der Coordinator später braucht.

        Auch ``/v1/alerts``: Ein erfolgreicher Login sagt nichts darüber aus,
        ob die Alert-Route erreichbar ist — scheitert sie erst beim Setup,
        landet man in einer Reauth-Schleife.
        """
        await self.async_get_metrics()
        await self._async_token(force=True)
        # Bewusst ein winziges Fenster: Geprüft wird die Erreichbarkeit der
        # Route, nicht der Inhalt — die Einrichtung soll nicht an tausenden
        # Alerts hängen.
        await self._async_alerts_window(Window(60, 0), 1)
        if self._bouncer_api_key is not None:
            await self.async_get_active_decision_count()
