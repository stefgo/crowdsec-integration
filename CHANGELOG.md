# Changelog

All notable changes to this integration are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [semantic versioning](https://semver.org/lang/de/).

The section headings have to match the release tags: the release workflow
reads the section for the tag it was started with and refuses to publish
without one.

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

[1.1.0]: https://github.com/stefgo/ha-crowdsec-integration/releases/tag/v1.1.0
[1.0.1]: https://github.com/stefgo/ha-crowdsec-integration/releases/tag/1.0.1
[1.0.0]: https://github.com/stefgo/ha-crowdsec-integration/releases/tag/1.0.0
