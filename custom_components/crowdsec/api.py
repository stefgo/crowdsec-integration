"""HTTP client for the metrics endpoint and the LAPI of a CrowdSec instance."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
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
ENDPOINT_DECISIONS = "decisions"


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


def _fingerprint(secret: str, salt: str) -> str:
    """Short fingerprint of a secret, to compare expected and actual in the log.

    Keyed with the machine ID rather than a plain hash: a plain SHA-256 of a
    short password can simply be looked up, and a debug log is not the place to
    hand out something that recovers the password. Keyed with a value that
    differs per installation, the digest is only comparable against another
    digest from the same installation — which is exactly what it is for.
    """
    return hmac.new(
        salt.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:8]


def _deleted_count(data: Any) -> int:
    """Read ``nbDeleted`` from a delete response.

    CrowdSec answers with the count as a string in some versions and as a
    number in others; both mean the same thing.
    """
    if not isinstance(data, dict):
        return 0
    try:
        return int(data.get("nbDeleted"))
    except (TypeError, ValueError):
        return 0


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
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


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
        # Set when the decision list cannot be read and a bouncer key would be
        # the way out. The coordinator turns it into a repair issue — this
        # module stays free of Home Assistant imports.
        self.decisions_need_bouncer_key = False

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
        except TimeoutError as err:
            raise CrowdSecConnectionError("Timeout during the metrics scrape") from err
        except aiohttp.ClientError as err:
            raise CrowdSecConnectionError(
                f"Metrics endpoint unreachable: {err}"
            ) from err

        if not text.strip():
            raise CrowdSecConnectionError("Metrics endpoint returned an empty response")
        return MetricSet(parse_prometheus(text))

    # -- LAPI -------------------------------------------------------------

    async def _async_token(self, force: bool = False) -> str:
        """Return a valid machine JWT, logging in if necessary."""
        async with self._login_lock:
            now = datetime.now(UTC)
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
                        "(password: %d characters, fingerprint %s): "
                        "HTTP %s, %d byte response",
                        url,
                        self._machine_id,
                        len(self._machine_password),
                        _fingerprint(self._machine_password, self._machine_id),
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
            except TimeoutError as err:
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
                datetime.now(UTC) + TOKEN_FALLBACK_TTL
            )
            return token

    async def _async_lapi_request(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        payload: Any = None,
        endpoint: str = ENDPOINT_ALERTS,
        none_on_404: bool = False,
    ) -> Any:
        """Request to the LAPI with machine auth, retried once on a 401.

        ``endpoint`` names the access path in an auth error — the coordinator
        decides per path whether the outage blocks the entry. With
        ``none_on_404`` a 404 counts as "this route does not exist here"
        instead of an error; older CrowdSec versions do not serve every route
        to a machine token.
        """
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
                            endpoint,
                        )
                    if response.status == 404 and none_on_404:
                        return None
                    if response.status not in (200, 201):
                        body = await response.text()
                        raise CrowdSecConnectionError(
                            f"LAPI {path} answered with HTTP {response.status}: "
                            f"{body.strip()[:200]}"
                        )
                    return await response.json(content_type=None)
            except TimeoutError as err:
                raise CrowdSecConnectionError(f"Timeout on LAPI {path}") from err
            except aiohttp.ClientError as err:
                raise CrowdSecConnectionError(f"LAPI {path} failed: {err}") from err

        raise CrowdSecAuthError(f"LAPI denies {path}", endpoint)

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

    async def async_lookup_alerts(
        self, target: str, since: str = ALERTS_SINCE, limit: int = 50
    ) -> list[dict[str, Any]]:
        """The recent alerts for one address or range.

        Context for the lookup: an address can be unknown to the decision list
        and still have shown up twenty times in the last day. A small limit is
        deliberate — what is wanted is "what did it do", not a full export.
        """
        key = "range" if "/" in target else "ip"
        params = {key: target, "since": since, "limit": str(limit)}
        data = await self._async_lapi_request("GET", "/v1/alerts", params)
        if not data:
            return []
        if not isinstance(data, list):
            raise CrowdSecConnectionError("LAPI /v1/alerts did not return an array")
        return [alert for alert in data if isinstance(alert, dict)]

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
        now = datetime.now(UTC).isoformat()
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
        return _deleted_count(data)

    async def async_delete_decision(self, decision_id: int) -> int:
        """Delete a single decision by its ID; returns how many were removed.

        The route by ID is what makes a targeted unban possible: an address can
        carry several decisions — from different scenarios, or one local and
        one from the CAPI — and removing all of them because one row was
        clicked would take away more than the click asked for.
        """
        data = await self._async_lapi_request(
            "DELETE",
            f"/v1/decisions/{int(decision_id)}",
            endpoint=ENDPOINT_DECISIONS,
        )
        return _deleted_count(data)

    async def async_get_decisions(
        self, origins: Sequence[str] | None = None
    ) -> list[dict[str, Any]] | None:
        """Active decisions, the way ``cscli decisions list`` sees them.

        The machine token is asked first — it is always configured, whereas the
        bouncer key is optional. Only if the LAPI denies the route to a machine
        does the bouncer key take over. ``None`` means neither path works; the
        caller then falls back to the ``cs_active_decisions`` metric, which
        knows the count but no details.

        ``origins`` restricts the query server-side. That matters: an instance
        subscribed to a blocklist enforces hundreds of thousands of decisions,
        and transferring all of them once a minute costs far more than the
        handful the card can actually act on.
        """
        params = {"origins": ",".join(origins)} if origins else None
        return await self._async_decisions(params)

    async def async_lookup_ip(self, target: str) -> list[dict[str, Any]] | None:
        """Every decision that applies to one address or range.

        This is the one question the ban table cannot answer. It lists what is
        enforced; it cannot show that an address is covered by a ``/24`` from a
        blocklist, because that row is about the range, not about the address
        somebody is asking about. ``contains`` is exactly that lookup — and
        unlike the list, it goes to *all* origins regardless of the configured
        scope, since here the point is to find out whether this address is
        blocked at all.
        """
        key = "range" if "/" in target else "ip"
        return await self._async_decisions({key: target, "contains": "true"})

    async def _async_decisions(
        self, params: dict[str, str] | None
    ) -> list[dict[str, Any]] | None:
        """A decision query with the full fallback chain.

        The machine token is asked first — it is always configured, whereas the
        bouncer key is optional. Only if the LAPI denies the route to a machine
        does the bouncer key take over.
        """
        try:
            data = await self._async_lapi_request(
                "GET",
                "/v1/decisions",
                params,
                endpoint=ENDPOINT_DECISIONS,
                none_on_404=True,
            )
        except CrowdSecAuthError as err:
            if self._bouncer_api_key is not None:
                _LOGGER.debug(
                    "LAPI denies /v1/decisions to the machine token — using "
                    "the bouncer key instead"
                )
                return await self._async_bouncer_decisions(params)
            # A valid token that is refused on this one route says something
            # about the CrowdSec version, not about the credentials. Treating
            # it as an outage would mark the whole instance unreachable over a
            # feature the rest does not depend on.
            _LOGGER.warning(
                "LAPI denies /v1/decisions to the machine token (%s) — the ban "
                "list stays empty. A bouncer API key would provide it",
                err,
            )
            self.decisions_need_bouncer_key = True
            return None

        if data is None:
            # 404: some builds only serve the route to bouncers.
            if self._bouncer_api_key is None:
                self.decisions_need_bouncer_key = True
                return None
            return await self._async_bouncer_decisions(params)

        self.decisions_need_bouncer_key = False
        if not isinstance(data, list):
            raise CrowdSecConnectionError("LAPI /v1/decisions did not return an array")
        return [item for item in data if isinstance(item, dict)]

    async def _async_bouncer_decisions(
        self, params: dict[str, str] | None = None
    ) -> list[dict[str, Any]] | None:
        """The decision list via the bouncer API."""
        if self._bouncer_api_key is None:
            return None
        try:
            async with self._session.get(
                f"{self._lapi_url}/v1/decisions",
                params=params,
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
        except TimeoutError as err:
            raise CrowdSecConnectionError("Timeout on /v1/decisions") from err
        except aiohttp.ClientError as err:
            raise CrowdSecConnectionError(f"/v1/decisions failed: {err}") from err

        if not data:
            return []
        if not isinstance(data, list):
            raise CrowdSecConnectionError("LAPI /v1/decisions did not return an array")
        return [item for item in data if isinstance(item, dict)]

    async def async_get_active_decision_count(self) -> int | None:
        """Number of active decisions via the bouncer API.

        ``None`` if no bouncer key is configured or the endpoint has nothing to
        report — the ``cs_active_decisions`` metric then takes over.

        Deliberately the bouncer path only: this is what the config flow uses
        to check the key. Going through the machine token here would let a
        wrong bouncer key pass validation unnoticed.
        """
        decisions = await self._async_bouncer_decisions()
        return None if decisions is None else len(decisions)

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
