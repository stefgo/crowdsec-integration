/**
 * The decision table, shared by both cards.
 *
 * They show the same thing — a decision — so they show it the same way: same
 * columns in the same order, same cells, same action. What differs is the
 * frame around it: the ban card sorts, pages and expands, the lookup card has
 * a handful of rows and needs none of that. So this module renders the parts
 * and each card composes them.
 */

import { TemplateResult, html, nothing } from "lit";

import {
  countryFlag,
  countryName,
  formatMoment,
  formatRemaining,
  originLabel,
  shortScenario,
} from "./format";
import { Localizer, TranslationKey } from "./localize";
import type { Decision, SortColumn } from "./types";

/** The columns, in order. `null` marks the action column, which never sorts. */
export const COLUMNS: { column: SortColumn | null; key: TranslationKey }[] = [
  { column: "value", key: "column.address" },
  { column: "type", key: "column.type" },
  { column: "scenario", key: "column.scenario" },
  { column: "country", key: "column.country" },
  { column: "as_name", key: "column.as" },
  { column: "origin", key: "column.origin" },
  { column: "seconds_left", key: "column.remaining" },
  { column: null, key: "column.action" },
];

/** Kept next to COLUMNS: a detail row spans the whole table. */
export const COLUMN_COUNT = COLUMNS.length;

export interface SortHeader {
  /** Called when a sortable header is clicked. */
  onSort: (column: SortColumn) => void;
  /** The arrow for the column currently sorted by, if it is this one. */
  indicator: (column: SortColumn) => TemplateResult | typeof nothing;
}

/**
 * The header row.
 *
 * Without `sort` the columns are plain labels — a table of three rows has
 * nothing to sort, and a header that looks clickable but is not would be worse
 * than one that does not.
 */
export function renderTableHeader(
  t: Localizer,
  sort?: SortHeader,
): TemplateResult {
  return html`
    <thead>
      <tr>
        ${COLUMNS.map(({ column, key }) => {
          if (column === null) {
            return html`<th class="right">${t(key)}</th>`;
          }
          if (!sort) {
            return html`<th>${t(key)}</th>`;
          }
          return html`<th class="sortable" @click=${() => sort.onSort(column)}>
            ${t(key)}${sort.indicator(column)}
          </th>`;
        })}
      </tr>
    </thead>
  `;
}

/** The cells of one row, without the action column. */
export function renderRowCells(
  row: Decision,
  t: Localizer,
  locale: string | undefined,
): TemplateResult {
  const none = t("value.none");
  return html`
    <td class="mono">${row.value ?? none}</td>
    <td>${row.type ?? none}</td>
    <td title=${row.scenario ?? ""}>${shortScenario(row.scenario, t)}</td>
    <td title=${countryName(row.country, locale, t)}>
      ${countryFlag(row.country)} ${row.country ?? none}
    </td>
    <td class="ellipsis" title=${row.as_name ?? ""}>${row.as_name ?? none}</td>
    <td>
      <span class="tag ${row.origin_kind}">${originLabel(row.origin, t)}</span>
    </td>
    <td class="mono">${formatRemaining(row.seconds_left, t)}</td>
  `;
}

/**
 * The unban button of a row, or a disabled one saying why not.
 *
 * A missing button would leave the reader guessing whether the card forgot the
 * row or is refusing it, so the refusal is spelled out in the tooltip.
 */
export function renderRowAction(
  row: Decision,
  t: Localizer,
  options: { busy: boolean; onUnban: (event: Event) => void },
): TemplateResult {
  if (!row.deletable) {
    const why =
      row.status === "expired"
        ? t("action.blocked_expired")
        : t("action.blocked_remote");
    return html`<button class="text-button" disabled title=${why}>
      ${t("value.none")}
    </button>`;
  }
  return html`<button
    class="text-button danger"
    ?disabled=${options.busy}
    title=${t("action.unban_hint")}
    @click=${options.onUnban}
  >
    ${options.busy ? "…" : t("action.unban")}
  </button>`;
}

/** Every raw field of a decision, for the expanded row. */
export function renderDetailGrid(
  row: Decision,
  t: Localizer,
  locale: string | undefined,
): TemplateResult {
  const none = t("value.none");
  const status = t(`status.${row.status}` as TranslationKey);
  const entries: [string, string][] = [
    [t("detail.address"), row.value ?? none],
    [t("detail.scope"), row.scope ?? none],
    [t("detail.type"), row.type ?? none],
    [t("detail.scenario"), row.scenario ?? none],
    [t("detail.origin"), row.origin ?? none],
    [t("detail.id"), row.id === null ? none : String(row.id)],
    [t("detail.duration"), row.duration ?? none],
    [t("detail.expires"), formatMoment(row.until, locale, t)],
    [t("detail.first_seen"), formatMoment(row.created_at, locale, t)],
    [t("detail.country"), countryName(row.country, locale, t)],
    [t("detail.as"), row.as_name ?? none],
    [t("detail.as_number"), row.as_number ?? none],
    [t("detail.alerts"), String(row.alerts_24h)],
    [
      t("detail.status"),
      row.simulated ? t("detail.simulated", { status }) : status,
    ],
  ];

  return html`
    <div class="detail-grid">
      ${entries.map(
        ([label, value]) => html`<div class="detail">
          <span class="label">${label}</span>
          <span class="value">${value}</span>
        </div>`,
      )}
    </div>
  `;
}
