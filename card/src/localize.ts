/**
 * Translations of the card.
 *
 * A custom card does not get the integration's translations — those only reach
 * the config flow, the entities and the services. Everything the card itself
 * writes on screen therefore lives here.
 *
 * English is the fallback: a key missing in another language falls back to the
 * English text rather than showing the raw key.
 */

import type { HomeAssistant } from "./types";

export const EN = {
  "card.title": "CrowdSec bans",
  "card.counts": "{active} active · {expired} expired · {local} local",
  "card.refresh": "Refresh",
  "card.refreshing": "Refreshing …",
  "card.last_poll": "Last successful poll",
  "card.dismiss": "Dismiss",
  "card.search": "Search IP, scenario, AS, country …",

  "status.active": "active",
  "status.expired": "expired",
  "status.all": "all",

  "origin.local": "Local",
  "origin.capi": "CAPI",
  "origin.lists": "Blocklists",

  "origin_label.manual": "manual",
  "origin_label.blocklist": "blocklist",
  "origin_label.unknown": "unknown",

  "filter.unbannable": "unbannable",
  "filter.unbannable_hint": "Only rows this card can unban",

  "column.address": "Address",
  "column.type": "Type",
  "column.scenario": "Scenario",
  "column.country": "Country",
  "column.as": "AS",
  "column.origin": "Origin",
  "column.remaining": "Remaining",
  "column.action": "Action",

  "action.unban": "Unban",
  "action.unban_hint": "Remove this decision",
  "action.unban_all": "Remove all decisions for {ip}",
  "action.confirm": "Remove {target}?",
  "action.target_all": "all decisions for {ip}",
  "action.target_one": "the {type} for {ip}",
  "action.blocked_expired": "Already expired — nothing left to remove.",
  "action.blocked_remote":
    "Managed by the central API; a local delete would be undone on the next pull.",

  "detail.address": "Address",
  "detail.scope": "Scope",
  "detail.type": "Type",
  "detail.scenario": "Scenario",
  "detail.origin": "Origin",
  "detail.id": "Decision ID",
  "detail.duration": "Duration",
  "detail.expires": "Expires",
  "detail.first_seen": "First seen",
  "detail.country": "Country",
  "detail.as": "AS",
  "detail.as_number": "AS number",
  "detail.alerts": "Alerts 24 h",
  "detail.status": "Status",
  "detail.simulated": "{status} (simulated)",

  "empty.not_admin": "Only administrators can manage bans.",
  "empty.no_instance": "No CrowdSec instance configured.",
  "empty.no_match": "No decisions match the filter.",
  "empty.loading": "Loading …",

  "notice.unreachable":
    "The instance is currently unreachable — showing the last known state.",
  "notice.unavailable":
    "The decision list could not be read; only the 24 h history is shown.",
  "notice.truncated":
    "More alerts than one query returns — the history is incomplete.",
  "notice.rows_truncated":
    "More decisions than the card keeps — showing the ones expiring last.",
  "filter.origin_excluded":
    "Not fetched: the integration option \"Decisions in the card\" is set to \"local only\".",
  "notice.removed": "Removed {count} decision(s).",
  "notice.removed_none":
    "CrowdSec removed nothing — the decision was already gone.",

  "error.entry_not_found": "This CrowdSec instance no longer exists.",
  "error.entry_not_loaded": "The CrowdSec instance is not loaded.",
  "error.not_ready": "The instance is still starting up.",
  "error.not_deletable":
    "This decision is managed centrally and cannot be removed locally.",
  "error.invalid_target": "No decision was selected.",

  "unit.day": "d",
  "unit.hour": "h",
  "unit.minute": "m",
  "unit.second": "s",
  "value.expired": "expired",
  "value.none": "—",
  "scenario.manual": "manual: {reason}",

  "pager.previous": "‹ Previous",
  "pager.next": "Next ›",
  "pager.info": "{page} / {pages} · {total} rows",

  "editor.title": "Title",
  "editor.instance": "Instance",
  "editor.status": "Show",
  "editor.origins": "Origins",
  "editor.sort": "Sort by",
  "editor.page_size": "Rows per page",
  "editor.hide_filters": "Hide search and filters",
  "editor.status.active": "Active decisions",
  "editor.status.expired": "Expired bans (24 h)",
  "editor.status.all": "Everything",
  "editor.sort.seconds_left": "Remaining time",
  "editor.sort.value": "Address",
  "editor.sort.scenario": "Scenario",
  "editor.sort.country": "Country",
  "editor.sort.as_name": "AS",
  "editor.sort.origin": "Origin",
  "editor.sort.type": "Type",
} as const;

export type TranslationKey = keyof typeof EN;

const DE: Partial<Record<TranslationKey, string>> = {
  "card.title": "CrowdSec-Sperren",
  "card.counts": "{active} aktiv · {expired} abgelaufen · {local} lokal",
  "card.refresh": "Aktualisieren",
  "card.refreshing": "Wird aktualisiert …",
  "card.last_poll": "Letzte erfolgreiche Abfrage",
  "card.dismiss": "Ausblenden",
  "card.search": "IP, Szenario, AS, Land suchen …",

  "status.active": "aktiv",
  "status.expired": "abgelaufen",
  "status.all": "alle",

  "origin.local": "Lokal",
  "origin.capi": "CAPI",
  "origin.lists": "Blocklisten",

  "origin_label.manual": "manuell",
  "origin_label.blocklist": "Blockliste",
  "origin_label.unknown": "unbekannt",

  "filter.unbannable": "entsperrbar",
  "filter.unbannable_hint": "Nur Einträge, die diese Karte entsperren kann",

  "column.address": "Adresse",
  "column.type": "Typ",
  "column.scenario": "Szenario",
  "column.country": "Land",
  "column.as": "AS",
  "column.origin": "Herkunft",
  "column.remaining": "Restlaufzeit",
  "column.action": "Aktion",

  "action.unban": "Entsperren",
  "action.unban_hint": "Diese Entscheidung entfernen",
  "action.unban_all": "Alle Entscheidungen für {ip} entfernen",
  "action.confirm": "{target} entfernen?",
  "action.target_all": "Alle Entscheidungen für {ip}",
  "action.target_one": "Die Entscheidung „{type}“ für {ip}",
  "action.blocked_expired": "Bereits abgelaufen — es ist nichts mehr zu entfernen.",
  "action.blocked_remote":
    "Wird zentral verwaltet; ein lokales Löschen wäre beim nächsten Abgleich wieder rückgängig.",

  "detail.address": "Adresse",
  "detail.scope": "Geltungsbereich",
  "detail.type": "Typ",
  "detail.scenario": "Szenario",
  "detail.origin": "Herkunft",
  "detail.id": "Entscheidungs-ID",
  "detail.duration": "Dauer",
  "detail.expires": "Läuft ab",
  "detail.first_seen": "Zuerst gesehen",
  "detail.country": "Land",
  "detail.as": "AS",
  "detail.as_number": "AS-Nummer",
  "detail.alerts": "Alarme 24 h",
  "detail.status": "Status",
  "detail.simulated": "{status} (simuliert)",

  "empty.not_admin": "Nur Administratoren können Sperren verwalten.",
  "empty.no_instance": "Keine CrowdSec-Instanz eingerichtet.",
  "empty.no_match": "Keine Entscheidung passt zum Filter.",
  "empty.loading": "Wird geladen …",

  "notice.unreachable":
    "Die Instanz ist derzeit nicht erreichbar — angezeigt wird der letzte bekannte Stand.",
  "notice.unavailable":
    "Die Entscheidungsliste konnte nicht gelesen werden; gezeigt wird nur die 24-h-Historie.",
  "notice.truncated":
    "Mehr Alarme, als eine Abfrage liefert — die Historie ist unvollständig.",
  "notice.rows_truncated":
    "Mehr Entscheidungen, als die Card vorhält — gezeigt werden die zuletzt ablaufenden.",
  "filter.origin_excluded":
    "Wird nicht geladen: Die Integrations-Option „Decisions in der Card\" steht auf „Nur lokale\".",
  "notice.removed": "{count} Entscheidung(en) entfernt.",
  "notice.removed_none":
    "CrowdSec hat nichts entfernt — die Entscheidung war bereits weg.",

  "error.entry_not_found": "Diese CrowdSec-Instanz existiert nicht mehr.",
  "error.entry_not_loaded": "Die CrowdSec-Instanz ist nicht geladen.",
  "error.not_ready": "Die Instanz startet noch.",
  "error.not_deletable":
    "Diese Entscheidung wird zentral verwaltet und kann lokal nicht entfernt werden.",
  "error.invalid_target": "Es wurde keine Entscheidung ausgewählt.",

  "unit.day": "T",
  "unit.hour": "Std",
  "unit.minute": "Min",
  "unit.second": "Sek",
  "value.expired": "abgelaufen",
  "value.none": "—",
  "scenario.manual": "manuell: {reason}",

  "pager.previous": "‹ Zurück",
  "pager.next": "Weiter ›",
  "pager.info": "{page} / {pages} · {total} Einträge",

  "editor.title": "Titel",
  "editor.instance": "Instanz",
  "editor.status": "Anzeigen",
  "editor.origins": "Herkunft",
  "editor.sort": "Sortieren nach",
  "editor.page_size": "Zeilen pro Seite",
  "editor.hide_filters": "Suche und Filter ausblenden",
  "editor.status.active": "Aktive Entscheidungen",
  "editor.status.expired": "Abgelaufene Sperren (24 h)",
  "editor.status.all": "Alles",
  "editor.sort.seconds_left": "Restlaufzeit",
  "editor.sort.value": "Adresse",
  "editor.sort.scenario": "Szenario",
  "editor.sort.country": "Land",
  "editor.sort.as_name": "AS",
  "editor.sort.origin": "Herkunft",
  "editor.sort.type": "Typ",
};

export const TRANSLATIONS: Record<string, Partial<Record<TranslationKey, string>>> = {
  en: EN,
  de: DE,
};

/** The language Home Assistant is set to, reduced to what the card knows. */
export function cardLanguage(hass?: HomeAssistant): string {
  // "de-DE" and "de" have to end up at the same table.
  const raw = hass?.locale?.language ?? hass?.language ?? "en";
  const base = raw.toLowerCase().split("-")[0];
  return base in TRANSLATIONS ? base : "en";
}

export type Localizer = (
  key: TranslationKey,
  params?: Record<string, string | number>,
) => string;

/** Build the lookup for one language, with English underneath. */
export function createLocalizer(hass?: HomeAssistant): Localizer {
  const table = TRANSLATIONS[cardLanguage(hass)] ?? EN;
  return (key, params) => {
    const template = table[key] ?? EN[key] ?? key;
    if (!params) return template;
    return template.replace(/\{(\w+)\}/g, (match, name: string) =>
      name in params ? String(params[name]) : match,
    );
  };
}
