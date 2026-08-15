"""HTTP client for the metrics endpoint and the LAPI of a CrowdSec instance."""

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

# The JWT of the LAPI expires after an hour; renew it shortly before that.
TOKEN_REFRESH_MARGIN = timedelta(minutes=2)
TOKEN_FALLBACK_TTL = timedelta(minutes=50)

# The access paths of an instance. Only ENDPOINT_LAPI — the login itself —
# means wrong credentials; the others may fail individually without bringing
# the integration down.
ENDPOINT_METRICS = "metrics"
ENDPOINT_LAPI = "lapi"
ENDPOINT_ALERTS = "alerts"
ENDPOINT_BOUNCER = "bouncer"


class CrowdSecError(Exception):
    """Base error of the integration."""


class CrowdSecConnectionError(CrowdSecError):
    """Instance was unreachable or answered with something unusable."""


class CrowdSecAuthError(CrowdSecError):
    """Credentials were rejected.

    ``endpoint`` names the access path that rejected them — the three are
    independent of each other and the message should say which one is stuck.
    """

    def __init__(self, message: str, endpoint: str = ENDPOINT_LAPI) -> None:
        super().__init__(message)
        self.endpoint = endpoint


class AlertResult(NamedTuple):
    """Result of an alert query, including a hint about completeness."""

    alerts: list[dict[str, Any]]
    truncated: bool


def _fingerprint(secret: str) -> str:
    """Truncated SHA-256 of a secret, to compare expected and actual in the log."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:8]


def _parse_expiry(raw: Any) -> datetime | None:
    """Parse the RFC3339 expiry date from the login response."""
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
    """Wraps both endpoints of an instance."""

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
        # Copying from the cscli output easily drags whitespace along. The ID
        # never has any; for the password we only warn instead of correcting.
        self._machine_id = machine_id.strip()
        self._machine_password = machine_password
        if machine_password != machine_password.strip():
            _LOGGER.warning(
                "The machine password starts or ends with whitespace — copied "
                "along by accident?"
            )
        self._bouncer_api_key = bouncer_api_key or None
        self._ssl: bool | None = None if verify_ssl else False
        # Without its own user agent the request inherits the one from Home
        # Assistant, and CrowdSec rejects the login because it cannot be parsed
        # as name/version.
        self._headers = {"User-Agent": USER_AGENT}
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._token: str | None = None
        self._token_expires: datetime | None = None
        self._login_lock = asyncio.Lock()

    @property
    def has_bouncer_key(self) -> bool:
        """Whether exact decision queries via the bouncer API are possible."""
        return self._bouncer_api_key is not None

    # -- Metrics ----------------------------------------------------------

    async def async_get_metrics(self) -> MetricSet:
        """Scrape the Prometheus endpoint."""
        try:
            async with self._session.get(
                self._metrics_url,
                headers=self._headers,
                ssl=self._ssl,
                timeout=self._timeout,
            ) as response:
                if response.status in (401, 403):
                    raise CrowdSecAuthError(
                        f"Metrics endpoint denied access ({response.status})",
                        ENDPOINT_METRICS,
                    )
                if response.status != 200:
                    raise CrowdSecConnectionError(
                        f"Metrics endpoint answered with HTTP {response.status}"
                    )
                text = await response.text()
        except asyncio.TimeoutError as err:
            raise CrowdSecConnectionError("Timeout during the metrics scrape") from err
        except aiohttp.ClientError as err:
            raise CrowdSecConnectionError(f"Metrics endpoint unreachable: {err}") from err

        if not text.strip():
            raise CrowdSecConnectionError("Metrics endpoint returned an empty response")
        return MetricSet(parse_prometheus(text))

    # -- LAPI -------------------------------------------------------------

    async def _async_token(self, force: bool = False) -> str:
        """Return a valid machine JWT, logging in if necessary."""
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
                    # Length and truncated hash instead of the password:
                    # enough to check a typo against the expected value, but
                    # not reversible.
                    _LOGGER.debug(
                        "LAPI login to %s for machine_id %r "
                        "(password: %d characters, sha256 %s): HTTP %s, %d byte response",
                        url,
                        self._machine_id,
                        len(self._machine_password),
                        _fingerprint(self._machine_password),
                        response.status,
                        len(body),
                    )
                    if response.status in (401, 403):
                        raise CrowdSecAuthError(
                            f"LAPI rejected the login (HTTP {response.status}): "
                            f"{body.strip()[:200]}",
                            ENDPOINT_LAPI,
                        )
                    if response.status != 200:
                        raise CrowdSecConnectionError(
                            f"LAPI login answered with HTTP {response.status}: "
                            f"{body.strip()[:200]}"
                        )
                    try:
                        data = json.loads(body) if body.strip() else None
                    except ValueError as err:
                        raise CrowdSecConnectionError(
                            "LAPI login did not return JSON — is that really "
                            "CrowdSec answering and not a proxy?"
                        ) from err
            except asyncio.TimeoutError as err:
                raise CrowdSecConnectionError("Timeout during the LAPI login") from err
            except aiohttp.ClientError as err:
                raise CrowdSecConnectionError(f"LAPI unreachable: {err}") from err

            token = (data or {}).get("token")
            if not token:
                # HTTP 200 without a token is not an authentication failure but
                # an unexpected response — do not conflate the two.
                raise CrowdSecConnectionError(
                    "LAPI login answered with 200 but without a token: "
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
        """Request to the LAPI with machine auth, retried once on a 401."""
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
                            # Token may have expired server-side: log in again.
                            continue
                        body = await response.text()
                        raise CrowdSecAuthError(
                            f"LAPI denies {path} despite a valid token "
                            f"(HTTP {response.status}): {body.strip()[:200]}",
                            ENDPOINT_ALERTS,
                        )
                    if response.status not in (200, 201):
                        body = await response.text()
                        raise CrowdSecConnectionError(
                            f"LAPI {path} answered with HTTP {response.status}: "
                            f"{body.strip()[:200]}"
                        )
                    return await response.json(content_type=None)
            except asyncio.TimeoutError as err:
                raise CrowdSecConnectionError(
                    f"Timeout on LAPI {path}"
                ) from err
            except aiohttp.ClientError as err:
                raise CrowdSecConnectionError(f"LAPI {path} failed: {err}") from err

        raise CrowdSecAuthError(f"LAPI denies {path}", ENDPOINT_ALERTS)

    async def _async_alerts_window(
        self, window: Window, limit: int
    ) -> list[dict[str, Any]]:
        """A single alert query over one time window."""
        params = {**window_params(window), "limit": str(limit)}
        data = await self._async_lapi_request("GET", "/v1/alerts", params)
        if not data:
            return []
        if not isinstance(data, list):
            raise CrowdSecConnectionError("LAPI /v1/alerts did not return an array")
        return [alert for alert in data if isinstance(alert, dict)]

    async def async_get_alerts(
        self, since: str = ALERTS_SINCE, limit: int = DEFAULT_ALERTS_LIMIT
    ) -> AlertResult:
        """Alerts of a time window, by default the last 24 hours.

        The LAPI has no pagination: with more hits than ``limit`` it truncates.
        When that happens, the time window is halved and queried again in
        parts. Only when even a one-minute window still hits the limit, or the
        split depth is exhausted, is the result considered truncated.
        """
        minutes = parse_duration(since)
        if minutes is None:
            raise ValueError(f"Unusable time window: {since!r}")

        collected: dict[str, dict[str, Any]] = {}
        truncated = False
        # (window, remaining splits) — iterative instead of recursive so that
        # the number of requests stays readable at any time.
        pending: list[tuple[Window, int]] = [(Window(minutes, 0), MAX_WINDOW_SPLITS)]

        while pending:
            window, splits_left = pending.pop(0)
            alerts = await self._async_alerts_window(window, limit)

            if len(alerts) < limit:
                self._collect(collected, alerts)
                continue

            halves = split_window(window) if splits_left > 0 else None
            if halves is None:
                # Cannot be split further: the partial result is better than
                # nothing, but the numbers are incomplete.
                self._collect(collected, alerts)
                truncated = True
                _LOGGER.debug(
                    "Alert window %s still returns %d hits at the limit — "
                    "result incomplete",
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
        """Take over alerts and keep overlaps of the windows out."""
        for index, alert in enumerate(alerts):
            key = alert_id(alert) or f"anon:{len(target)}:{index}"
            target.setdefault(key, alert)

    # -- Creating and deleting decisions ----------------------------------

    async def async_ban_ip(
        self,
        ip: str,
        duration: str = DEFAULT_BAN_DURATION,
        reason: str = DEFAULT_BAN_REASON,
    ) -> None:
        """Create a ban decision via a self-generated alert.

        The LAPI offers no way to create a decision on its own — it always
        hangs off an alert. That is exactly what ``cscli decisions add`` does.
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
        """Delete all decisions for an IP; returns their count."""
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
        """Number of active decisions via the bouncer API.

        ``None`` if no bouncer key is configured or the endpoint has nothing to
        report — the ``cs_active_decisions`` metric then takes over.
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
                        "Bouncer API key was rejected", ENDPOINT_BOUNCER
                    )
                if response.status == 404:
                    # Not every CrowdSec version returns an empty array here —
                    # a 404 means "nothing there", not "broken".
                    _LOGGER.debug(
                        "/v1/decisions answered with 404, falling back to the metric"
                    )
                    return None
                if response.status != 200:
                    raise CrowdSecConnectionError(
                        f"LAPI /v1/decisions answered with HTTP {response.status}"
                    )
                data = await response.json(content_type=None)
        except asyncio.TimeoutError as err:
            raise CrowdSecConnectionError("Timeout on /v1/decisions") from err
        except aiohttp.ClientError as err:
            raise CrowdSecConnectionError(f"/v1/decisions failed: {err}") from err

        if not data:
            return 0
        if not isinstance(data, list):
            raise CrowdSecConnectionError("LAPI /v1/decisions did not return an array")
        return len(data)

    async def async_validate(self) -> None:
        """Check every access path the coordinator will need later.

        ``/v1/alerts`` included: a successful login says nothing about whether
        the alert route is reachable — if it only fails during setup, you end
        up in a reauth loop.
        """
        await self.async_get_metrics()
        await self._async_token(force=True)
        # Deliberately a tiny window: what is checked is the reachability of
        # the route, not the content — setup should not hang on thousands of
        # alerts.
        await self._async_alerts_window(Window(60, 0), 1)
        if self._bouncer_api_key is not None:
            await self.async_get_active_decision_count()
