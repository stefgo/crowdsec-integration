# CrowdSec für Home Assistant

Custom-Integration, die eine oder mehrere CrowdSec-Instanzen in Home Assistant
abbildet — Erreichbarkeit, Angriffsvolumen, Durchsatz und Durchsetzung.

Jede Instanz wird als eigenes Gerät angelegt; die Integration lässt sich beliebig
oft hinzufügen.

## Entitäten je Instanz

| Entität | Typ | Quelle |
| --- | --- | --- |
| Erreichbar | `binary_sensor` (connectivity) | Erfolg des Scrapes |
| Störung | `binary_sensor` (problem) | Sammelflag, s. u. |
| Scrape-Dauer | Sensor, s (diagnostisch) | gemessene Dauer beider Abfragen |
| Letzter Neustart | Sensor, Timestamp | `process_start_time_seconds` |
| Letzte Aktualisierung | Sensor, Timestamp | letzter **erfolgreicher** Scrape |
| Aktive Decisions | Sensor | `/v1/decisions` bzw. `cs_active_decisions` |
| Neue Bans 24h | Sensor | `/v1/alerts?since=24h` |
| Top-Szenario 24h | Sensor, Text | häufigstes Szenario derselben Alerts |
| Aktive Buckets | Sensor | `cs_buckets` |
| Zeilen/min | Sensor | Rate aus `cs_parser_hits_total` |
| Parse-Fehlerquote | Sensor, % | `cs_parser_hits_ko_total` / (ok + ko) |
| Bouncer-Abfragen/min | Sensor | Rate aus `cs_lapi_route_requests_total` |

Nützliche Attribute: `Aktive Decisions` führt `by_reason`/`by_action`,
`Top-Szenario 24h` die Top 5 als `top_scenarios`, `Aktive Buckets` die offenen
Buckets je Szenario, `Störung` die auslösenden `reasons`.

## Voraussetzungen auf der CrowdSec-Seite

1. **Prometheus-Endpunkt aktivieren** in `/etc/crowdsec/config.yaml`:

   ```yaml
   prometheus:
     enabled: true
     level: full          # "full" wird für Zeilen/min und Parse-Fehler gebraucht
     listen_addr: 0.0.0.0 # bzw. die Adresse, die Home Assistant erreicht
     listen_port: 6060
   ```

   Mit `level: aggregated` fehlen die Parser-Metriken; `Zeilen/min` und
   `Parse-Fehlerquote` bleiben dann leer.

2. **Machine-Zugangsdaten** für die LAPI anlegen:

   ```bash
   sudo cscli machines add homeassistant --password '<passwort>'
   ```

   Diese werden für `/v1/alerts` (Neue Bans 24h, Top-Szenario) benötigt.

3. **Optional: Bouncer-API-Key** für eine exakte Decision-Zahl:

   ```bash
   sudo cscli bouncers add homeassistant
   ```

   Ohne Key wird die Metrik `cs_active_decisions` verwendet — die zählt
   Decisions inklusive der aus der CAPI bezogenen Listen und weicht daher
   leicht ab.

## Installation

**HACS:** Repository als benutzerdefiniertes Repository vom Typ *Integration*
hinzufügen, installieren, Home Assistant neu starten.

**Manuell:** `custom_components/crowdsec/` nach `<config>/custom_components/`
kopieren und Home Assistant neu starten.

Danach *Einstellungen → Geräte & Dienste → Integration hinzufügen → CrowdSec*.

## Konfiguration

| Feld | Beispiel |
| --- | --- |
| Name | `CrowdSec Edge` |
| Metrics-URL | `http://10.0.0.5:6060/metrics` |
| LAPI-URL | `http://10.0.0.5:8080` |
| Machine-ID / Passwort | aus `cscli machines add` |
| Bouncer-API-Key | optional, aus `cscli bouncers add` |
| SSL prüfen | bei selbstsignierten Zertifikaten abschalten |

Unter *Konfigurieren* lassen sich Abfrageintervall (Standard 60 s), Zeitlimit
je Anfrage (15 s), Schwellwert der Parse-Fehlerquote (5 %) und die Zahl der
Intervalle ohne Bouncer-Abfragen bis zur Störung (5) sowie die maximal
abgerufene Alert-Zahl (1000) anpassen. Das Zeitlimit
gilt pro Anfrage und muss kleiner als das Abfrageintervall sein — bei einer
Instanz hinter VPN oder langsamem Proxy hilft ein höherer Wert.

## Wann „Störung" auslöst

* Instanz nicht erreichbar
* Parse-Fehlerquote über dem Schwellwert — das Logformat passt nicht mehr zum Parser
* keine Logzeilen mehr verarbeitet, obwohl vorher welche kamen — CrowdSec ist blind
* keine Bouncer-Abfragen über N Intervalle — Decisions werden nicht durchgesetzt

Der Grund steht im Attribut `reasons`:

```yaml
automation:
  - alias: CrowdSec meldet Störung
    trigger:
      - platform: state
        entity_id: binary_sensor.crowdsec_edge_storung
        to: "on"
        for: "00:05:00"
    action:
      - service: notify.persistent_notification
        data:
          message: >-
            CrowdSec: {{ state_attr('binary_sensor.crowdsec_edge_storung', 'reasons') | join(', ') }}
```

## Fehlersuche bei der Einrichtung

Der Config-Flow benennt den abgelehnten Zugang einzeln — Metrics-Endpunkt,
LAPI-Login und Bouncer-Key werden getrennt gemeldet. Zum Nachstellen auf der
Kommandozeile:

```bash
curl -si http://<host>:6060/metrics | head -1
curl -si -X POST http://<host>:8080/v1/watchers/login \
  -H 'Content-Type: application/json' \
  -d '{"machine_id":"<id>","password":"<passwort>"}'
```

Antwortet `/v1/decisions` mit **404**, ist das kein Fehler: Nicht jede
CrowdSec-Version liefert dort ein leeres Array. Die Integration weicht in dem
Fall automatisch auf `cs_active_decisions` aus.

Meldet die LAPI beim Login `incorrect Username or Password`, obwohl dieselben
Zugangsdaten per curl funktionieren, lohnt ein Blick auf den User-Agent:
CrowdSec liest ihn aus, legt ihn als Version der Machine ab (`cscli machines
list`) und erwartet das Format `name/version`. Die Integration sendet deshalb
einen eigenen (`hass-crowdsec/…`) statt des zusammengesetzten von Home
Assistant. Nachstellen lässt sich das mit `curl -A`.

Detailliertes Protokoll:

```yaml
logger:
  logs:
    custom_components.crowdsec: debug
```

## Verhalten bei Ausfall

Schlägt ein Scrape fehl, gehen die Messwerte auf `unavailable` — sie werden
bewusst **nicht** mit veralteten Zahlen weitergeführt. `Erreichbar`, `Störung`,
`Letzte Aktualisierung` und `Letzter Neustart` bleiben verfügbar und liefern den
Kontext dazu.

Nach einem Neustart der Instanz werden die Ratensensoren für ein Intervall
ausgesetzt, statt einen negativen Sprung aus zurückgesetzten Countern zu melden.
`Letzter Neustart` zeigt dann den neuen Zeitpunkt.

## Tests

```bash
python -m pytest tests
```

Abgedeckt sind der Prometheus-Parser und die Raten-/Neustart-Logik — die beiden
Teile ohne Home-Assistant-Abhängigkeit und zugleich die fehleranfälligsten.

## Hinweis

Vor der Veröffentlichung in `custom_components/crowdsec/manifest.json` die
Platzhalter `CHANGEME` in `documentation`/`issue_tracker` sowie `codeowners`
ersetzen.
