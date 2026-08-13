"""Tests für das Aufteilen der Alert-Abfrage.

Die HTTP-Ebene bleibt außen vor: Getestet wird, wie der Client auf ein
abgeschnittenes Fenster reagiert — welche Fenster er nachfragt, wie er
Überschneidungen entfernt und wann er aufgibt.
"""

from __future__ import annotations

import asyncio

import pytest

# Der Client selbst hängt an aiohttp; ohne die Abhängigkeit gibt es hier
# nichts zu prüfen.
pytest.importorskip("aiohttp")

# api.py verweist relativ auf seine Nachbarmodule — deshalb über das in
# conftest.py angemeldete Paket importieren, nicht flach.
from crowdsec_component.api import CrowdSecClient  # noqa: E402
from crowdsec_component.timewindow import Window  # noqa: E402

LIMIT = 3


def build_client() -> CrowdSecClient:
    """Ein Client ohne Session — die HTTP-Aufrufe werden ersetzt.

    Muss innerhalb eines laufenden Event-Loops aufgerufen werden: Der
    Konstruktor legt ein ``asyncio.Lock`` an.
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
    """Frage Alerts ab und liefere (Ergebnis, abgefragte Fenster).

    ``answer`` ist eine Funktion Fenster -> Alert-Liste.
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
    """Wie ``query``, aber mit einer Tabelle Fenster -> Antwort.

    Nicht aufgeführte Fenster antworten leer.
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
    # Das abgeschnittene Ergebnis wird verworfen, die Hälften ersetzen es.
    assert sorted(a["id"] for a in result.alerts) == [10, 11, 20]
    assert result.truncated is False


def test_duplicates_across_windows_are_removed():
    shared = alert(10)
    responses = {
        Window(1440, 0): [alert(i) for i in range(LIMIT)],
        Window(1440, 720): [shared, alert(11)],
        # Derselbe Alert taucht am Rand beider Fenster auf.
        Window(720, 0): [shared, alert(12)],
    }
    result, _ = run_with_windows(responses)
    assert sorted(a["id"] for a in result.alerts) == [10, 11, 12]


def test_gives_up_and_reports_truncation():
    # Jedes Fenster bleibt am Limit: irgendwann ist Schluss mit Teilen.
    always_full = [alert(i) for i in range(LIMIT)]
    result, asked = query(lambda window: always_full)

    assert result.truncated is True
    # Die Teilungstiefe ist begrenzt, sonst würde ein Zyklus die LAPI fluten.
    assert len(asked) < 64
    assert result.alerts


def test_invalid_window_is_rejected():
    async def run():
        client = build_client()
        await client.async_get_alerts(since="gestern")

    with pytest.raises(ValueError):
        asyncio.run(run())
