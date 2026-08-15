/**
 * Turning the raw decision fields into something readable.
 *
 * The functions take their words from the outside instead of hard-coding
 * English: the card passes its localizer, the tests rely on the defaults.
 */

import { EN, Localizer } from "./localize";

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** English wording, used wherever no localizer is handed in. */
const fallback: Localizer = (key, params) => {
  const template: string = EN[key];
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? String(params[name]) : match,
  );
};

/**
 * Remaining time as a short, coarse label.
 *
 * Only the two largest units are shown: for a ban running for six days the
 * seconds are noise, and for one running for two minutes the days are.
 */
export function formatRemaining(
  seconds: number | null,
  t: Localizer = fallback,
): string {
  if (seconds === null) return t("value.none");
  if (seconds <= 0) return t("value.expired");

  const days = Math.floor(seconds / DAY);
  const hours = Math.floor((seconds % DAY) / HOUR);
  const minutes = Math.floor((seconds % HOUR) / MINUTE);

  const day = t("unit.day");
  const hour = t("unit.hour");
  const minute = t("unit.minute");

  if (days > 0) {
    return hours > 0 ? `${days} ${day} ${hours} ${hour}` : `${days} ${day}`;
  }
  if (hours > 0) {
    return minutes > 0
      ? `${hours} ${hour} ${minutes} ${minute}`
      : `${hours} ${hour}`;
  }
  if (minutes > 0) return `${minutes} ${minute}`;
  return `${Math.floor(seconds)} ${t("unit.second")}`;
}

/** Absolute timestamp in the user's locale, without the year clutter. */
export function formatMoment(
  iso: string | null,
  locale: string | undefined,
  t: Localizer = fallback,
): string {
  if (!iso) return t("value.none");
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return t("value.none");
  return date.toLocaleString(locale, {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * Country code as a flag emoji.
 *
 * The regional indicator letters sit at a fixed offset from A–Z, so the flag
 * comes out of the code itself — no image, no lookup table that would go stale.
 */
export function countryFlag(code: string | null): string {
  if (!code || code.length !== 2 || !/^[a-zA-Z]{2}$/.test(code)) return "";
  const base = 0x1f1e6 - "A".charCodeAt(0);
  return String.fromCodePoint(
    ...[...code.toUpperCase()].map((char) => char.charCodeAt(0) + base),
  );
}

/** Full country name where the browser knows one, else the bare code. */
export function countryName(
  code: string | null,
  locale: string | undefined,
  t: Localizer = fallback,
): string {
  if (!code) return t("value.none");
  try {
    const names = new Intl.DisplayNames([locale ?? "en"], { type: "region" });
    return names.of(code.toUpperCase()) ?? code;
  } catch {
    // Not every browser knows DisplayNames for every locale.
    return code;
  }
}

/**
 * Shorten a scenario for the table.
 *
 * CrowdSec scenarios are namespaced ("crowdsecurity/ssh-bf"); the namespace is
 * the same for almost every row and only eats width. The full value stays in
 * the detail panel and in the row's tooltip.
 */
export function shortScenario(
  scenario: string | null,
  t: Localizer = fallback,
): string {
  if (!scenario) return t("value.none");
  const manual = scenario.match(/^manual '(.+)' from '(.+)'$/);
  if (manual) return t("scenario.manual", { reason: manual[1] });
  const slash = scenario.lastIndexOf("/");
  return slash >= 0 ? scenario.slice(slash + 1) : scenario;
}

/** Label for the origin tag. */
export function originLabel(
  origin: string | null,
  t: Localizer = fallback,
): string {
  if (!origin) return t("origin_label.unknown");
  const normalized = origin.toLowerCase();
  if (normalized === "capi") return "CAPI";
  if (normalized === "lists" || normalized === "list") {
    return t("origin_label.blocklist");
  }
  if (normalized === "cscli") return t("origin_label.manual");
  return origin;
}
