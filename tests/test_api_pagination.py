"""Tests for splitting the alert query.

The HTTP layer stays out of it: what is tested is how the client reacts to a
truncated window — which windows it queries next, how it removes overlaps and
when it gives up.
"""

from __future__ import annotations

import asyncio

import pytest

# The client itself depends on aiohttp; without that dependency there is
# nothing to check here.
pytest.importorskip("aiohttp")

# api.py references its neighbouring modules relatively — import it through
# the package registered in conftest.py, not flat.
from crowdsec_component.api import CrowdSecClient
from crowdsec_component.timewindow import Window

LIMIT = 3


def build_client() -> CrowdSecClient:
    """A client without a session — the HTTP calls are replaced.

    Has to be called inside a running event loop: the constructor creates an
    ``asyncio.Lock``.
    """
    return CrowdSecClient(
        session=None,
        metrics_url="http://localhost:6060/metrics",
        lapi_url="http://localhost:8080",
        machine_id="hass",
        machine_password="secret",
    )


def alert(identifier: int) -> dict:
    return {"id": identifier, "scenario": "test", "source": {"ip": "192.0.2.1"}}


def query(answer, limit=LIMIT, since="24h"):
    """Query alerts and return (result, queried windows).

    ``answer`` is a function window -> list of alerts.
    """
    asked: list[Window] = []

    async def run():
        client = build_client()

        async def fake_window(window: Window, window_limit: int):
            asked.append(window)
            assert window_limit == limit
            return list(answer(window))

        client._async_alerts_window = fake_window  # type: ignore[assignment]
        return await client.async_get_alerts(since=since, limit=limit)

    return asyncio.run(run()), asked


def run_with_windows(responses, limit=LIMIT):
    """Like ``query``, but with a table window -> response.

    Windows that are not listed answer empty.
    """
    return query(lambda window: responses.get(window, []), limit)


def test_single_query_when_below_the_limit():
    result, asked = run_with_windows({Window(1440, 0): [alert(1), alert(2)]})
    assert asked == [Window(1440, 0)]
    assert len(result.alerts) == 2
    assert result.truncated is False


def test_full_window_gets_split():
    responses = {
        Window(1440, 0): [alert(i) for i in range(LIMIT)],
        Window(1440, 720): [alert(10), alert(11)],
        Window(720, 0): [alert(20)],
    }
    result, asked = run_with_windows(responses)

    assert asked[0] == Window(1440, 0)
    assert set(asked[1:]) == {Window(1440, 720), Window(720, 0)}
    # The truncated result is discarded, the halves replace it.
    assert sorted(a["id"] for a in result.alerts) == [10, 11, 20]
    assert result.truncated is False


def test_duplicates_across_windows_are_removed():
    shared = alert(10)
    responses = {
        Window(1440, 0): [alert(i) for i in range(LIMIT)],
        Window(1440, 720): [shared, alert(11)],
        # The same alert shows up at the edge of both windows.
        Window(720, 0): [shared, alert(12)],
    }
    result, _ = run_with_windows(responses)
    assert sorted(a["id"] for a in result.alerts) == [10, 11, 12]


def test_gives_up_and_reports_truncation():
    # Every window stays at the limit: at some point splitting has to stop.
    always_full = [alert(i) for i in range(LIMIT)]
    result, asked = query(lambda window: always_full)

    assert result.truncated is True
    # The split depth is bounded, otherwise one cycle would flood the LAPI.
    assert len(asked) < 64
    assert result.alerts


def test_invalid_window_is_rejected():
    async def run():
        client = build_client()
        await client.async_get_alerts(since="yesterday")

    with pytest.raises(ValueError):
        asyncio.run(run())
