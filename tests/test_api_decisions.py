"""Tests for the decision routes of the client.

The HTTP layer stays out of it: what is tested is which path the client takes
when the LAPI refuses the machine token or does not know the route at all.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("aiohttp")

from crowdsec_component.api import (
    ENDPOINT_BOUNCER,
    CrowdSecAuthError,
    CrowdSecClient,
    CrowdSecConnectionError,
    _deleted_count,
)


def build_client(bouncer_api_key=None) -> CrowdSecClient:
    """A client without a session — the HTTP calls are replaced."""
    return CrowdSecClient(
        session=None,
        metrics_url="http://localhost:6060/metrics",
        lapi_url="http://localhost:8080",
        machine_id="hass",
        machine_password="secret",
        bouncer_api_key=bouncer_api_key,
    )


def run(coroutine_factory):
    """Run a coroutine built inside the loop (the client needs one)."""
    return asyncio.run(coroutine_factory())


DECISION = {"id": 1, "value": "192.0.2.1", "duration": "4h", "type": "ban"}


# -- Reading the list -------------------------------------------------------


def test_machine_token_is_asked_first():
    calls: list[tuple] = []

    async def scenario():
        client = build_client(bouncer_api_key="key")

        async def fake_request(method, path, *args, **kwargs):
            calls.append((method, path))
            return [DECISION]

        async def fake_bouncer():
            raise AssertionError("the bouncer key must stay untouched here")

        client._async_lapi_request = fake_request  # type: ignore[assignment]
        client._async_bouncer_decisions = fake_bouncer  # type: ignore[assignment]
        return await client.async_get_decisions()

    assert run(scenario) == [DECISION]
    assert calls == [("GET", "/v1/decisions")]


def test_a_404_falls_back_to_the_bouncer_key():
    async def scenario():
        client = build_client(bouncer_api_key="key")

        async def fake_request(*args, **kwargs):
            # none_on_404 turns the 404 into None.
            return None

        async def fake_bouncer():
            return [DECISION]

        client._async_lapi_request = fake_request  # type: ignore[assignment]
        client._async_bouncer_decisions = fake_bouncer  # type: ignore[assignment]
        return await client.async_get_decisions()

    assert run(scenario) == [DECISION]


def test_a_404_without_a_bouncer_key_gives_up():
    async def scenario():
        client = build_client()

        async def fake_request(*args, **kwargs):
            return None

        client._async_lapi_request = fake_request  # type: ignore[assignment]
        return await client.async_get_decisions()

    # None means "the metric has to take over" — not an empty ban list.
    assert run(scenario) is None


def test_a_denied_route_falls_back_to_the_bouncer_key():
    async def scenario():
        client = build_client(bouncer_api_key="key")

        async def fake_request(*args, **kwargs):
            raise CrowdSecAuthError("denied", "decisions")

        async def fake_bouncer():
            return [DECISION]

        client._async_lapi_request = fake_request  # type: ignore[assignment]
        client._async_bouncer_decisions = fake_bouncer  # type: ignore[assignment]
        return await client.async_get_decisions()

    assert run(scenario) == [DECISION]


def test_a_denied_route_without_a_key_does_not_break_the_instance():
    """A refusal on this one route must not look like an outage.

    The rest of the integration does not depend on the decision list; raising
    here would mark the whole instance unreachable over a single feature.
    """

    async def scenario():
        client = build_client()

        async def fake_request(*args, **kwargs):
            raise CrowdSecAuthError("denied", "decisions")

        client._async_lapi_request = fake_request  # type: ignore[assignment]
        return await client.async_get_decisions()

    assert run(scenario) is None


def test_a_rejected_bouncer_key_still_surfaces():
    """A wrong key is a configuration error and has to be reported."""

    async def scenario():
        client = build_client(bouncer_api_key="wrong")

        async def fake_request(*args, **kwargs):
            return None

        async def fake_bouncer():
            raise CrowdSecAuthError("rejected", ENDPOINT_BOUNCER)

        client._async_lapi_request = fake_request  # type: ignore[assignment]
        client._async_bouncer_decisions = fake_bouncer  # type: ignore[assignment]
        return await client.async_get_decisions()

    with pytest.raises(CrowdSecAuthError):
        run(scenario)


def test_non_objects_are_dropped_and_junk_is_rejected():
    async def scenario(answer):
        client = build_client()

        async def fake_request(*args, **kwargs):
            return answer

        client._async_lapi_request = fake_request  # type: ignore[assignment]
        return await client.async_get_decisions()

    assert asyncio.run(scenario([DECISION, "nonsense", None])) == [DECISION]
    with pytest.raises(CrowdSecConnectionError):
        asyncio.run(scenario({"decisions": []}))


# -- Deleting ---------------------------------------------------------------


def test_delete_targets_a_single_decision():
    calls: list[tuple] = []

    async def scenario():
        client = build_client()

        async def fake_request(method, path, *args, **kwargs):
            calls.append((method, path))
            return {"nbDeleted": "1"}

        client._async_lapi_request = fake_request  # type: ignore[assignment]
        return await client.async_delete_decision(42)

    assert run(scenario) == 1
    assert calls == [("DELETE", "/v1/decisions/42")]


def test_deleted_count_reads_both_shapes():
    # CrowdSec sends the count as a string in some versions, as a number in
    # others — both mean the same thing.
    assert _deleted_count({"nbDeleted": "3"}) == 3
    assert _deleted_count({"nbDeleted": 3}) == 3
    assert _deleted_count({"nbDeleted": None}) == 0
    assert _deleted_count({}) == 0
    assert _deleted_count(None) == 0
