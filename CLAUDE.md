# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Home Assistant custom integration (`custom_components/crowdsec/`) that polls one or
more CrowdSec Security Engines, plus a Lit/TypeScript Lovelace card (`card/`) that the
integration serves itself. Each CrowdSec instance is one config entry and one HA device;
the integration can be added multiple times.

## Commands

```bash
# Python tests (no Home Assistant needed — see "Testing" below)
pip install -r requirements_test.txt
python -m pytest
python -m pytest tests/test_decisions.py::test_name    # single test

# The Home-Assistant-dependent tests, in their own environment
pip install -r requirements_test_ha.txt
python -m pytest -c pytest_ha.ini

# Lint and types (ruff over everything, mypy over the HA-free modules)
ruff check . && ruff format --check . && mypy

# Card
npm --prefix card ci
npm --prefix card run build     # writes custom_components/crowdsec/www/ (gitignored)
npm --prefix card run watch     # rebuild on change
npm --prefix card test          # vitest
npm --prefix card test -- filters.test.ts   # single file

# Build the card and rsync the integration to a live HA instance
./builddeploy.sh                # host/path via CROWDSEC_HOST / CROWDSEC_CONFIG
```

`builddeploy.sh` is in `.gitignore` (contains a private host) — it exists locally but is
not tracked.

## Architecture

Data flows in one direction: `api.py` → `coordinator.py` → `CrowdSecData` → entities /
websocket / diagnostics.

- **`api.py`** — the only HTTP layer. Talks to two endpoints per instance: the Prometheus
  `/metrics` endpoint and the LAPI (`/v1/watchers/login`, `/v1/alerts`, `/v1/decisions`).
  Holds the LAPI JWT and renews it before expiry. Raises `CrowdSecAuthError` carrying the
  `ENDPOINT_*` that rejected — only `ENDPOINT_LAPI` (the login) means bad credentials and
  triggers reauth; the other endpoints may fail individually without taking the entry down.
- **`coordinator.py`** — a `DataUpdateCoordinator` producing one `CrowdSecData` dataclass
  per cycle. The three queries (metrics, alerts, decisions) run via `asyncio.gather` so
  their timeouts do not add up. Also owns the cross-cycle state: `RateTracker` history,
  the `AlertCache`, seen alert IDs for ban events, bouncer-idle counter, raw metrics for
  diagnostics.
- **Pure-logic modules, deliberately free of Home Assistant imports** (this is what the
  test suite covers): `metrics.py` (Prometheus text parser → `MetricSet`), `rates.py`
  (counter deltas per minute, discards the interval when `process_start_time_seconds`
  shows a restart), `alerts.py` (alert JSON → `AlertSummary`, ban detection, alert IDs,
  plus the rolling `AlertCache`),
  `decisions.py` (merges `/v1/decisions` with `/v1/alerts` into flat `DecisionRecord`s,
  parses Go durations), `timewindow.py` (window splitting arithmetic). Keep these
  HA-free — the tests import them without Home Assistant installed.
- **`entity.py` / `sensor.py` / `binary_sensor.py`** — `CrowdSecEntity` binds every entity
  to the entry's device; platforms are description-driven over `CrowdSecData`.
- **`websocket_api.py`** — `crowdsec/decisions/list|delete`, `crowdsec/instances` and
  `crowdsec/ip/lookup|ban`. The cards use these instead of entity attributes: a ban table
  would blow past attribute size limits and end up in the recorder. Admin-only; deletes
  are restricted to local-origin decisions. The two `ip/*` commands go to the LAPI live
  rather than reading the coordinator's data — see the lookup note under "Things that
  bite".
- **`services.py` / `services.yaml`** — `ban_ip`, `unban_ip`, `refresh`, all targeting a
  `config_entry_id`.
- **`config_flow.py`** — setup, reauth, reconfigure and options. `build_unique_id()` is
  also used by `async_migrate_entry` in `__init__.py` (v1 → v2 added the machine ID to
  the identifier). Reconfigure cannot use `_abort_if_unique_id_mismatch`: the identifier
  is derived from the address, so it moves with any change — it checks instead that no
  *other* entry already holds the new one.
- **`repairs.py`** — one flow so far, for the LAPI that refuses `/v1/decisions` to a
  machine token. `api.py` only sets a flag (`decisions_need_bouncer_key`), the
  coordinator raises the issue — that is what keeps `api.py` free of HA imports.
- **`validation.py`** — HA-free input checking (addresses, ban durations) shared by
  `services.py` and `websocket_api.py`.

### Things that bite

- **Alerts are polled in two speeds.** Only every `alerts_full_interval` (default 300 s)
  does a cycle fetch the whole 24h window; the rest only ask for the minutes since the
  last query and merge into the `AlertCache`. The aggregates are recomputed from the
  cache each cycle with the same `summarize_alerts`, so nothing about the evaluation
  changed. `alerts_truncated` is remembered rather than recomputed — a truncated
  increment means alerts were missed and only a full query can clear it.
- **The lookup is not the table.** `crowdsec/ip/lookup` queries `/v1/decisions` with
  `ip=`/`range=` plus `contains=true`, which is what finds a range covering the address —
  the one thing the table structurally cannot show, since that row is about the range.
  It covers every origin, unlike the table: the table is a list of what can be acted on,
  the lookup answers whether an address is blocked at all. `origins` is *not* sent here.
- **The ban table is local-only, always.** The LAPI query carries an `origins` filter,
  but that parameter is honoured on some versions and ignored on others — the official
  Go client lists it for `/v1/decisions/stream`, not for the list route. So
  `build_table(local_only=True)` filters again on this side, over both sources: the
  decision list *and* the alert history, which has no such filter at the LAPI at all.
  `active_decisions` therefore comes from the `cs_active_decisions` metric, not from the
  list length — counting a filtered list would silently drop the CAPI and blocklist bans.
  The table is capped at `MAX_DECISION_ROWS`.
- **The delete guard for an address asks the LAPI, not the table.** Since the table holds
  local rows only, a purely central address is absent from it and a table-based check
  would never fire — while the lookup card can show exactly such an address and offers
  the unban behind it. The by-id path keeps a table check as a safety net; the LAPI has
  no way to look a decision up by id.

- **No LAPI pagination.** `/v1/alerts` silently truncates at `limit`. When that happens
  the client halves the time window and re-queries, up to `MAX_WINDOW_SPLITS` (4) levels
  deep. If it is still truncated, a repair issue is raised and `alerts_truncated` is set.
- **User agent.** CrowdSec parses the UA as the machine's version and requires exactly
  `name/version`; HA's composite UA causes a 401 on login. Hence `USER_AGENT` in
  `const.py`.
- **Version single source of truth.** `const.INTEGRATION_VERSION` is read from
  `manifest.json`. Never add a second version constant.
- **`/v1/decisions` 404 is normal** on some versions. Fallback chain: machine token →
  bouncer API key → `cs_active_decisions` metric (count only, empty card table).
- **Card registration is per-HA-run**, not per entry (`CARD_REGISTERED` flag in
  `hass.data`); the static path is registered once and the JS URL carries `?v=<version>`
  for cache busting. A missing build only logs a warning.
- **Ban events** (`crowdsec_new_ban`) stay silent on the first cycle and are capped at
  `MAX_BAN_EVENTS_PER_CYCLE` (25); the remainder is deferred to later cycles, not dropped.
- **Availability is per query, not per cycle.** The three queries are independent, so
  `CrowdSecData` carries one flag each (`metrics_ok`, `alerts_ok`, `decisions_ok`) and
  every sensor description names its source via `source_fn`; a sensor goes `unavailable`
  only when *its* query failed. Letting a stuttering alert route blank the counters of a
  successful metrics scrape put gaps into the recorder for data that was never in doubt.
  No sensor reads `decisions_ok` — the table travels over the WebSocket.
  `reachable` therefore means "the instance answered at all" (any of the three), which is
  what a connectivity device class is about; a single failed route surfaces through
  `errors` and the `problem` flag, which lists them unconditionally. `last_update` keeps
  the strict condition (`not errors`), since that is what an automation compares against
  to spot stale values. `last_restart` / `last_alert` are carried over from the previous
  cycle only when *their* query failed — a working alert query with an empty window has
  to be able to clear the timestamp.

### Cards

Two elements in **one bundle**: `crowdsec-bans-card.ts` is the rollup entry point and
imports `ip-lookup-card.ts`, so both are defined by the single file the integration
serves. Adding a third card means importing it there too, plus a `window.customCards`
entry.

`filters.ts` (search/filter/sort), `localize.ts` (DE/EN) and `api.ts` (including the
paging of `fetchAllDecisions`) hold the logic that vitest covers; the elements themselves
are not unit-tested, since the card setup has no DOM environment. `editor.ts` and
`ip-lookup-editor.ts` are the visual editors.

**`table.ts` renders the decision table for both cards** — same columns, same cells,
same action column — while each card keeps its own frame around it: the ban card sorts,
pages and expands, the lookup card has a handful of rows and needs none of that.

**`styles.ts` holds the visual vocabulary both cards share** — header, type scale,
controls, table, tags, label/value grid — and both do `static styles = [sharedStyles,
css\`…\`]` with only their own rules in the second block. Sizes are px, matching Home
Assistant's own cards, and padding sits on the sections rather than on `ha-card` so a
table can run edge to edge while text keeps its 12px inset. A new card belongs on
`sharedStyles` too; writing its own set is how the two drifted apart the first time. Rollup writes straight into
`custom_components/crowdsec/www/` — the built file is **not committed**; HACS installs
get it from the release zip.

## Testing

Two suites, deliberately apart. `tests/` runs on nothing but pytest — that is what keeps
the pure-logic modules free of Home Assistant — and its coverage floor
(`--cov-fail-under=90`) applies to exactly those modules; the omit list lives in
`pyproject.toml`. `tests/ha/` needs the real framework (`requirements_test_ha.txt`,
`pytest_ha.ini`, its own CI job) and covers the flows, the coordinator, the WebSocket
commands, the services, repairs and diagnostics.

`tests/conftest.py` registers `custom_components/crowdsec` as a synthetic package
(`crowdsec_component`) so relative imports resolve without executing `__init__.py` and
without Home Assistant. Tests must therefore only touch the HA-free modules. `pytest.ini`
sets `--import-mode=importlib` because module names collide otherwise.
`tests/test_integrity.py` keeps `manifest.json`, `const.py`, `strings.json` and the
translations in sync; the card's vitest checks DE and EN carry the same keys and
placeholders.

## Releasing

1. Add a `## [x.y.z]` section to `CHANGELOG.md` — the release workflow reads it as the
   release notes and **fails without it**.
2. Bump `version` in `manifest.json` (and `card/package.json`) — the workflow aborts if
   the tag does not match the manifest.
3. Push a `v*` tag. `.github/workflows/release.yml` runs pytest + vitest, builds the card,
   zips `custom_components/crowdsec` (manifest at the archive root, as HACS expects) and
   publishes.

`.github/workflows/validate.yml` runs hassfest, HACS validation and pytest on push/PR.
