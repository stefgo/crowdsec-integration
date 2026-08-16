# Changelog

All notable changes to this integration are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [semantic versioning](https://semver.org/lang/de/).

The section headings have to match the release tags: the release workflow
reads the section for the tag it was started with and refuses to publish
without one.

## [1.2.0] – 2026-08-17

### Added

- **Lookup card** (`custom:crowdsec-ip-lookup-card`): checks one address or
  range against every source — local decisions, CAPI and blocklists — and
  finds a range that contains it, which the ban table structurally cannot
  show. Includes the 24 h alert history for the address, plus ban and unban.
  It queries live and covers every origin, because the question is whether the
  address is blocked at all — unlike the ban table, which lists what can be
  acted on.
- Reconfigure flow: addresses and credentials of an existing instance can be
  changed in place instead of deleting the entry and setting it up again.
  Leaving a secret field empty keeps the stored value.
- Repair issue when the LAPI refuses the decision list to the machine token.
  It offers to add a bouncer API key and checks it before storing it — so far
  the reason for an empty ban table sat in a log warning.
- Option `alerts_full_interval` (see below).
- Tests for everything with a Home Assistant dependency (`tests/ha/`), plus
  ruff, mypy, coverage and dependabot in CI.

### Changed

- **Alerts are polled in two speeds.** Every cycle used to refetch the whole
  24h window, which with the window splitting behind it could mean sixteen
  requests per cycle. The window is now kept in the coordinator: a full query
  refreshes it every `alerts_full_interval` seconds (default 300), and each
  cycle only asks for the minutes since the last one. A new ban is still
  noticed within one cycle.
- **The ban card shows local decisions only.** An instance subscribed to a
  blocklist enforces hundreds of thousands of decisions, none of which can be
  lifted from the card, and an address caught by a range would not be findable
  in a table anyway — the lookup card answers that instead. The origin filter
  chips and the card's `origins` option are gone with it, and the "Active
  decisions" sensor keeps counting everything via the metric.
- The card's table is capped at 2000 rows and the rows travel through the
  WebSocket connection page by page instead of in one message.
- The diagnostics no longer contain the LAPI and metrics host names; scheme,
  port and path stay.
- Both cards render the same decision table from one module: same columns,
  same expandable rows, same per-row unban. The lookup card gained the
  country, operator and action columns it lacked.
- The "AS" column is called "Netzblock-Betreiber" / "Network operator" — the
  cell holds the operator of the address block, not the protocol's acronym.
- German wording of the lookup card: it used its own keys and said "Alle
  Decisions entfernen"; it now shares the ban card's phrasing, which names
  the address it acts on.

### Fixed

- Unloading one instance removed the services while a second instance was
  still loaded.
- IP addresses are validated with `ipaddress` instead of a pattern, which let
  `1.2.3.4.5`, `::::` and a `/999` prefix through to the LAPI.
- Ban durations may be composite (`1h30m`); the day unit is now refused up
  front, since neither Go nor CrowdSec knows it.
- The `ip` field of the WebSocket delete command was not validated at all.

## [1.1.0] – 2026-08-15

### Added

- Decision management from Home Assistant: bans can be created and deleted
  through the LAPI, including duration and reason (`decisions.py`).
- WebSocket API as the bridge between the frontend and the decision
  handling (`websocket_api.py`).
- Lovelace card `crowdsec-bans-card` with search, filters, unban button, a
  graphical editor and German/English localisation.
- Release pipeline that runs the tests, builds `crowdsec.zip` for HACS and
  publishes the release.

### Changed

- Reworked API and coordinator layer: pagination, error handling and the
  alert processing were pulled apart into separate modules.
- Code comments and documentation translated from German to English.

## [1.0.1] – 2026-08-14

### Added

- Example package for push notifications and the app badge in the Home
  Assistant Companion app on iOS/iPadOS. It is built for attack peaks and
  sends one buffered summary instead of a push per ban
  (`examples/ios_push_badge.yaml`).

## [1.0.0] – 2026-08-14

### Added

- First release: CrowdSec instance as a device in Home Assistant, with
  sensors for the Prometheus metrics, a problem indicator, services and an
  event on a new ban.

[unreleased]: https://github.com/stefgo/ha-crowdsec-integration/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/stefgo/ha-crowdsec-integration/releases/tag/v1.2.0
[1.1.0]: https://github.com/stefgo/ha-crowdsec-integration/releases/tag/v1.1.0
[1.0.1]: https://github.com/stefgo/ha-crowdsec-integration/releases/tag/1.0.1
[1.0.0]: https://github.com/stefgo/ha-crowdsec-integration/releases/tag/1.0.0
