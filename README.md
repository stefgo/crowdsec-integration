# CrowdSec for Home Assistant

Custom integration that maps one or more CrowdSec instances into Home
Assistant — reachability, attack volume, throughput and enforcement.

Every instance is created as its own device; the integration can be added as
often as you like.

## Entities per instance

| Entity | Type | Source |
| --- | --- | --- |
| Reachable | `binary_sensor` (connectivity) | success of the scrape |
| Status | `binary_sensor` (problem) | aggregate flag, see below |
| Scrape duration | sensor, s (diagnostic) | measured duration of both queries |
| Last restart | sensor, timestamp | `process_start_time_seconds` |
| Last update | sensor, timestamp | last **successful** scrape |
| Last alert | sensor, timestamp | most recent alert of the last 24 h |
| Active decisions | sensor | `/v1/decisions` or `cs_active_decisions` |
| New bans 24h | sensor | `/v1/alerts?since=24h` |
| Unique attackers 24h | sensor | distinct source IPs of the same alerts |
| Top scenario 24h | sensor, text | most frequent scenario of the same alerts |
| Top country 24h | sensor, text | `source.cn` of the same alerts |
| Top attacker 24h | sensor, text | most frequent source IP of the same alerts |
| Active buckets | sensor | `cs_buckets` |
| Lines processed | sensor (diagnostic) | `cs_parser_hits_total`, cumulative |
| Lines per minute | sensor | rate from `cs_parser_hits_total` |
| Parse error rate | sensor, % | `cs_parser_hits_ko_total` / (ok + ko) |
| Bouncer queries per minute | sensor | rate from `cs_lapi_route_requests_total` |

Useful attributes: `Active decisions` carries `by_reason`/`by_action`,
`Top scenario 24h` the top 5 as `top_scenarios`, `Top country 24h` the
`top_countries`, `Unique attackers 24h` the `top_attackers` together with their
alert count, `Active buckets` the open buckets per scenario, and `Status` the
triggering `reasons`.

`Lines processed` is deliberately `total_increasing`: the counter runs since
the start of the service and is reset on a restart — Home Assistant absorbs
that and yields usable daily and weekly sums, which the instantaneous
`Lines per minute` cannot provide.

## Services

| Service | Effect |
| --- | --- |
| `crowdsec.ban_ip` | creates a ban decision (`ip`, `duration`, `reason`) |
| `crowdsec.unban_ip` | deletes all decisions for an `ip` |
| `crowdsec.refresh` | polls immediately instead of waiting for the interval |

All three expect the instance as `config_entry_id`. `ip` takes a single address
or a CIDR range, `duration` the cscli format (`30m`, `4h`, `1d`). After a ban
and an unban the integration refreshes the values by itself.

```yaml
action:
  - service: crowdsec.ban_ip
    data:
      config_entry_id: "{{ config_entry_id('binary_sensor.crowdsec_edge_reachable') }}"
      ip: 192.0.2.10
      duration: 24h
      reason: Failed attempts on the reverse proxy
```

## Event on a new ban

For every newly detected ban the integration fires `crowdsec_new_ban` with
`ip`, `scenario`, `country`, `as_name`, `duration`, `scope`, `value`,
`created_at`, `alert_id` as well as `entry_id`/`instance`.

The first cycle after a start stays silent — otherwise the bans of the last 24
hours would be dumped all at once. If more than 25 bans occur in one interval,
the integration only reports the 25 most recent ones and writes the rest to the
log.

```yaml
automation:
  - alias: CrowdSec banned someone
    trigger:
      - platform: event
        event_type: crowdsec_new_ban
    action:
      - service: notify.persistent_notification
        data:
          message: >-
            {{ trigger.event.data.ip }} ({{ trigger.event.data.country }})
            banned for {{ trigger.event.data.duration }}
            because of {{ trigger.event.data.scenario }}
```

## Lovelace card: bans with search, filters and unban

The integration ships a card that shows every decision CrowdSec is currently
enforcing, together with the bans of the last 24 hours that have already run
out. It is served by the integration itself — no Lovelace resource has to be
added by hand. After the update it appears in the card picker as **CrowdSec
Bans** (`custom:crowdsec-bans-card`).

![The ban card: search field, status chips and the table of local decisions with
country, network operator, origin, remaining time and the unban
action](screenshots/crowdsec-bans-card.png)

| Column | Source |
| --- | --- |
| Address | `value` of the decision, IP or CIDR range |
| Type | `ban`, `captcha`, … |
| Scenario | the scenario, namespace stripped; manual bans as `manual: <reason>` |
| Country / network operator | from the alert belonging to the address |
| Origin | `local` (deletable), `CAPI` or `blocklist` |
| Remaining | derived from `duration`, or from `until` where the LAPI sends it |

The table holds **local decisions only** — the ones this Home Assistant owns
and can lift. The CAPI and the blocklists contribute thousands of rows that can
neither be removed nor read usefully, and an address caught by a range from a
blocklist would not be findable in a table anyway. That question belongs to the
[lookup card](#lookup-card-is-this-address-blocked); this one stays a list of
what you can act on. The integration does not fetch central decisions for it at
all.

Because of that the row count and the **Active decisions** sensor deliberately
disagree: the sensor counts everything the LAPI enforces, the table shows the
part you can do something about.

Clicking a row opens the details — every raw field of the decision plus the
alert context. The search box works over address, scenario, operator, country,
origin, type and scope; several words all have to match but may sit in
different fields, so `de ssh` finds the German SSH bruteforcers. The chips
filter by status, origin, type and scope; column headers sort.

The card speaks **German and English** and follows the language set in the
Home Assistant profile; anything else falls back to English. Error messages
from the integration are localised by their error code, so they also arrive in
the user's language.

**Unban** removes exactly the decision of that row. An address can carry
several decisions — from different scenarios, or one local and one from the
CAPI — and the detail panel additionally offers *Remove all decisions for this
address*. Decisions from the CAPI or from a blocklist have no button: they are
pushed centrally, and a local delete would be undone on the next pull.

Only administrators can see the card and remove decisions.

### Options

Everything except `type` is optional, and every option below can also be set in
the visual editor — with the exception of `sort_desc`, which is YAML only.

| Option | Type | Default | What it does |
| --- | --- | --- | --- |
| `type` | string | — | `custom:crowdsec-bans-card`. Required. |
| `title` | string | localised | Heading of the card — "CrowdSec bans" / "CrowdSec-Sperren" when left out. The count line below it is not affected. |
| `config_entry_id` | string | first instance | Which CrowdSec instance to show. Left out, the card takes the first loaded one; with more than one instance configured a picker appears in the header either way. Set it when a dashboard should always open on one particular engine. |
| `status` | `active` \| `expired` \| `all` | `active` | Which rows the card opens with. `expired` shows the bans of the last 24 hours that have already run out, `all` both. The chips change it at runtime; anything else is refused when the card is saved. |
| `sort` | see below | `seconds_left` | Column the table is sorted by. Clicking a column header changes it at runtime. |
| `sort_desc` | boolean | `true` | Sort direction. With the default `seconds_left` this puts the bans with the most time left on top. |
| `page_size` | number | `25` | Rows per page. The editor offers 5–200; in YAML anything from 1 up is accepted. This is the display page, unrelated to how the rows are fetched. |
| `hide_filters` | boolean | `false` | Hides the search field and all filter chips. For a compact dashboard tile where the card is only meant to show the current state, not to be worked with. |

Values for `sort`: `seconds_left`, `value` (address), `scenario`, `country`,
`as_name`, `origin`, `type`. Rows without a remaining time always go last,
in either direction — they say nothing about the ordering.

A full example, with every option spelled out:

```yaml
type: custom:crowdsec-bans-card
title: CrowdSec
config_entry_id: 01JABCDEF0123456789ABCDEFG
status: active
sort: seconds_left
sort_desc: true
page_size: 25
hide_filters: false
```

One behaviour is not a card option but an *integration* option, because it
decides what is fetched in the first place: **Full alert refresh** governs how
current the expired 24 h history is. The active decisions come from the polling
cycle either way. See [Configuration](#configuration).

## Lookup card: is this address blocked?

The ban table answers "what is CrowdSec enforcing". It cannot answer "is
`192.0.2.10` blocked" — because an address caught by a `/24` from a blocklist
appears nowhere in it: that row is about the range. Scanning the table for the
address finds nothing, and the address is blocked all the same.

The second card asks that question directly. It appears in the card picker as
**CrowdSec IP Lookup** (`custom:crowdsec-ip-lookup-card`).

![The lookup card: the verdict for an address, the decisions in force, the last
24 hours from the alerts and the ban/unban
controls](screenshots/crowdsec-ip-lookup-card.png)

Type an address or a CIDR range, press *Check*, and the card asks the LAPI with
`contains`, which is exactly the "what covers this" lookup. The answer is one
request, made only when you ask:

* **the verdict** — blocked or not, and when it comes free again, taken from
  whichever decision runs longest;
* **the covering range**, called out separately when the address is not banned
  by name. This is the finding the table cannot show, so it gets its own block
  rather than a footnote;
* **every decision in force**, with origin — including CAPI and blocklists. The
  table is the one from the ban card: same columns, same expandable rows, same
  per-row unban where the decision is a local one;
* **the last 24 hours** from the alerts: how often, since when, country, network operator and
  the scenarios. An address can be unknown to the decision list and still have
  shown up twenty times today.

Two things are deliberately different from the table:

* It covers **every origin** — local, CAPI and blocklists. The ban table is a
  list of what you can act on; here the question is whether the address is
  blocked *at all*, so nothing is filtered out.
* It reads **live**, not from the polling cycle. Nothing is cached — a lookup
  costs one request and always shows the current state.

**Ban and unban** sit below the answer, next to the per-row unban in the table. *Ban* takes a duration and a reason,
prefilled from the card configuration, and confirms before acting; the fresh
result comes straight back, so the click shows its own effect. *Remove all
decisions* appears only when something local is actually there to remove — a
decision from the CAPI or a blocklist has no button and says why. After an
unban the card asks again instead of trusting the delete count: a covering
range can still be in force once the address's own ban is gone.

Only administrators can use the card.

### Options

| Option | Type | Default | What it does |
| --- | --- | --- | --- |
| `type` | string | — | `custom:crowdsec-ip-lookup-card`. Required. |
| `title` | string | localised | Heading of the card. |
| `config_entry_id` | string | first instance | Which instance to query. As with the ban card, a picker appears when several are configured. |
| `ban_duration` | string | `4h` | Prefills the duration field. Go syntax, so `30m`, `4h` or `1h30m`; CrowdSec has no day unit, use `168h` for a week. |
| `ban_reason` | string | `Home Assistant` | Prefills the reason field. It ends up in the scenario of the decision CrowdSec creates. |
| `hide_ban` | boolean | `false` | Hides the ban controls. Unban stays available — for a dashboard where looking up and lifting is wanted but creating bans is not. |

```yaml
type: custom:crowdsec-ip-lookup-card
title: Check an address
ban_duration: 24h
ban_reason: Blocked from Home Assistant
hide_ban: false
```

## Push and badge on iOS/iPadOS

A ready-made package for the Home Assistant companion app is available at
[`examples/ios_push_badge.yaml`](examples/ios_push_badge.yaml). It sends a push
notification on new bans and keeps the number on the app icon up to date.

Pushing directly on `crowdsec_new_ban` is not a good idea during a burst of
attacks — 25 events per cycle would mean 25 notifications. The package
therefore takes a detour:

1. A trigger-based template sensor `sensor.crowdsec_ban_buffer` collects the
   bans: the state is the count, the attributes hold the affected IPs,
   scenarios and countries. No event triggers a notification here.
2. An automation sends **one** summarised notification from it as soon as
   there have been 45 seconds of quiet, immediately from 20 buffered bans on,
   and at the latest every five minutes if the barrage does not stop. A
   `crowdsec_push_flush` event then empties the buffer.
3. All notifications share `tag: crowdsec-digest` — iOS uses it to replace the
   previous notification instead of building a stack on the lock screen. On a
   detected wave the notification additionally rises to
   `interruption-level: time-sensitive` and thus gets through in focus mode.

The badge does not hang off the buffer but off
`sensor.crowdsec_active_decisions`: on iOS the badge is an absolute value, not
a counter — tied to the active decisions it also counts down again when bans
expire. A second automation sets it via a silent push
(`message: delete_alert`), throttled to at most one update per 30 seconds.

To adjust before use: the service name of the companion app in the notify group
(`mobile_app_iphone`) and the entity IDs, if the instance is not called
`crowdsec`.

## Requirements on the CrowdSec side

1. **Enable the Prometheus endpoint** in `/etc/crowdsec/config.yaml`:

   ```yaml
   prometheus:
     enabled: true
     level: full          # "full" is needed for lines/min and parse errors
     listen_addr: 0.0.0.0 # or the address Home Assistant can reach
     listen_port: 6060
   ```

   With `level: aggregated` the parser metrics are missing; `Lines per minute`
   and `Parse error rate` then stay empty.

2. **Create machine credentials** for the LAPI:

   ```bash
   sudo cscli machines add homeassistant --password '<password>'
   ```

   They are needed for `/v1/alerts` (New bans 24h, Top scenario) and for
   `/v1/decisions` — the list behind the card and the exact decision count.

3. **Optional: a bouncer API key**:

   ```bash
   sudo cscli bouncers add homeassistant
   ```

   The machine credentials already cover the decision list. The key is only a
   fallback for CrowdSec versions that serve `/v1/decisions` to bouncers alone;
   if neither path works, the `cs_active_decisions` metric takes over, which
   knows the count but no details and therefore leaves the card's table empty.

## Installation

**HACS:** add the repository as a custom repository of type *Integration*,
install it, restart Home Assistant.

**Manually:** copy `custom_components/crowdsec/` to
`<config>/custom_components/` and restart Home Assistant.

Then go to *Settings → Devices & services → Add integration → CrowdSec*.

What changed between versions is listed in [CHANGELOG.md](CHANGELOG.md); the
same text is on the release page of each version.

## Configuration

| Field | Example |
| --- | --- |
| Name | `CrowdSec Edge` |
| Metrics URL | `http://10.0.0.5:6060/metrics` |
| LAPI URL | `http://10.0.0.5:8080` |
| Machine ID / password | from `cscli machines add` |
| Bouncer API key | optional, from `cscli bouncers add` |
| Verify SSL | turn off for self-signed certificates |

Under *Configure* you can adjust the polling interval (default 60 s), the
timeout per request (15 s), the threshold for the parse error rate (5 %), the
number of intervals without bouncer queries before a problem is raised (5),
the number of alerts per query (1000) and how often the whole 24h alert window
is refetched (300 s). The
timeout applies per request and has to be lower than the polling interval —
for an instance behind a VPN or a slow proxy a higher value helps. The three
queries of a cycle run in parallel, so the timeouts do not add up.

Addresses and credentials can be changed later under *Reconfigure*; leaving
the password or the bouncer key empty keeps the stored one.

### How much the instance is asked for

**Full alert refresh** is the one setting for it, and it does not slow down how
quickly a new ban is noticed: the 24h numbers come from a window the
integration keeps itself, refetched in full on this interval, while every cycle
only asks for the minutes since the last one and merges the result in.
Refetching 24 hours every minute transfers the same alerts over and over, and
with the window splitting below that can be sixteen requests per cycle.

The decision query is restricted to local origins and needs no setting. An
instance subscribed to a blocklist enforces hundreds of thousands of decisions
that no click can change; `Active decisions` keeps counting all of them through
the `cs_active_decisions` metric, and the lookup card answers any question
about a specific address. The table stops at 2000 rows and says so when it
does.

### Completeness of the 24h numbers

The LAPI has no pagination: it truncates at the requested number. When that
happens, the integration halves the time window and queries the halves
separately — up to four levels deep. The 24h numbers therefore stay complete
even with tens of thousands of alerts, without every query having to be huge.

If even that is not enough — more alerts in a single minute than one query
returns — a repair issue appears under *Settings → System → Repairs*, and
`New bans 24h` carries `truncated: true`. Only a higher number of alerts per
query helps then.

## When "Status" turns on

* the instance is unreachable
* the parse error rate is above the threshold — the log format no longer
  matches the parser
* no log lines are processed any more although there were some before —
  CrowdSec is blind
* no bouncer queries for N intervals — decisions are not being enforced

The reason is in the `reasons` attribute:

```yaml
automation:
  - alias: CrowdSec reports a problem
    trigger:
      - platform: state
        entity_id: binary_sensor.crowdsec_edge_status
        to: "on"
        for: "00:05:00"
    action:
      - service: notify.persistent_notification
        data:
          message: >-
            CrowdSec: {{ state_attr('binary_sensor.crowdsec_edge_status', 'reasons') | join(', ') }}
```

## Troubleshooting the setup

The config flow names the rejected access path individually — metrics endpoint,
LAPI login and bouncer key are reported separately. To reproduce it on the
command line:

```bash
curl -si http://<host>:6060/metrics | head -1
curl -si -X POST http://<host>:8080/v1/watchers/login \
  -H 'Content-Type: application/json' \
  -d '{"machine_id":"<id>","password":"<password>"}'
```

If `/v1/decisions` answers with a **404**, that is not an error: not every
CrowdSec version returns an empty array there. The integration then tries the
bouncer key and finally falls back to `cs_active_decisions`. Only in that last
case does the card's table stay empty — the metric knows the count, not the
decisions.

If the LAPI reports `incorrect Username or Password` on login although the same
credentials work via curl, it is worth looking at the user agent: CrowdSec
reads it, stores it as the version of the machine (`cscli machines list`) and
expects the format `name/version`. The integration therefore sends its own
(`hass-crowdsec/…`) instead of the composite one from Home Assistant. You can
reproduce that with `curl -A`.

Detailed logging:

```yaml
logger:
  logs:
    custom_components.crowdsec: debug
```

## Behaviour during an outage

If a scrape fails, the measured values go `unavailable` — they are deliberately
**not** carried on with stale numbers. `Reachable`, `Status`, `Last update` and
`Last restart` stay available and provide the context.

After a restart of the instance the rate sensors are suspended for one interval
instead of reporting a negative jump from reset counters. `Last restart` then
shows the new point in time.

## Diagnostics

*Download diagnostics* on the device gives you the redacted configuration, the
latest data and the raw `cs_*` metrics of the instance. Credentials and
attacker IPs are replaced while the counts are preserved — so the report can be
attached to an issue.

## Building the card

The card is written in TypeScript and is **not** committed in built form. HACS
installs get it from the release zip; for a checkout it has to be built once:

```bash
npm --prefix card ci
npm --prefix card run build   # writes custom_components/crowdsec/www/
```

Without that file the integration starts normally and only logs a warning —
everything except the card works.

## Tests

```bash
pip install -r requirements_test.txt
python -m pytest

npm --prefix card test
```

`tests/` covers the parts without a Home Assistant dependency, which are at
the same time the most error-prone ones: the Prometheus parser, the rate and
restart logic, the alert evaluation including ban detection and the rolling
alert window, the normalisation and enrichment of the decisions, the splitting
of the time windows, the input validation as well as the consistency of
manifest, `strings.json` and the translations. It installs with nothing but
pytest, which is what keeps those modules framework-free.

Everything that does import Home Assistant is covered separately, because it
needs the real thing:

```bash
pip install -r requirements_test_ha.txt
python -m pytest -c pytest_ha.ini
```

That suite exercises the config, reauth, reconfigure and options flows, the
update cycle including the error routing and the ban events, the WebSocket
commands, the services, the repair flow and the diagnostics redaction.

On the card side the search, filter and sort logic is tested with vitest,
together with the paging of the WebSocket answers and the card's own
translations — German and English have to carry the same keys and the same
placeholders. CI additionally runs `ruff`, `mypy`, `hassfest` and the HACS
validation (see
[.github/workflows/validate.yml](.github/workflows/validate.yml)).

## License

[MIT](LICENSE).
