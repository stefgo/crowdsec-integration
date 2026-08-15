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

   They are needed for `/v1/alerts` (New bans 24h, Top scenario).

3. **Optional: a bouncer API key** for an exact decision count:

   ```bash
   sudo cscli bouncers add homeassistant
   ```

   Without a key the `cs_active_decisions` metric is used — it counts decisions
   including the lists pulled from the CAPI and therefore deviates slightly.

## Installation

**HACS:** add the repository as a custom repository of type *Integration*,
install it, restart Home Assistant.

**Manually:** copy `custom_components/crowdsec/` to
`<config>/custom_components/` and restart Home Assistant.

Then go to *Settings → Devices & services → Add integration → CrowdSec*.

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
number of intervals without bouncer queries before a problem is raised (5) and
the number of alerts per query (1000). The timeout applies per request and has
to be lower than the polling interval — for an instance behind a VPN or a slow
proxy a higher value helps. The three queries of a cycle run in parallel, so
the timeouts do not add up.

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
CrowdSec version returns an empty array there. In that case the integration
automatically falls back to `cs_active_decisions`.

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

## Tests

```bash
pip install -r requirements_test.txt
python -m pytest
```

Covered are the parts without a Home Assistant dependency, which are at the
same time the most error-prone ones: the Prometheus parser, the rate and
restart logic, the alert evaluation including ban detection, the splitting of
the time windows as well as the consistency of manifest, `strings.json` and the
translations. CI additionally runs `hassfest` and the HACS validation (see
[.github/workflows/validate.yml](.github/workflows/validate.yml)).

## License

[MIT](LICENSE).
