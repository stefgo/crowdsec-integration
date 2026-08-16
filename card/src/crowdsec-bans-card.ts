/**
 * CrowdSec Bans Card
 *
 * A table of everything CrowdSec is currently enforcing, plus the bans of the
 * last 24 hours that have already run out. The data comes through the
 * integration's WebSocket commands rather than entity states: a ban list is
 * too large and changes too often to live in the state machine.
 */

import { LitElement, PropertyValues, css, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";

import "./editor";
// Both cards travel in the one bundle the integration serves.
import "./ip-lookup-card";
import {
  deleteDecision,
  deleteForIp,
  fetchAllDecisions,
  fetchInstances,
} from "./api";
import {
  Counts,
  FilterState,
  applyFilters,
  countDecisions,
  distinctValues,
  emptyFilter,
  sortDecisions,
} from "./filters";
import { formatMoment } from "./format";
import { EN, Localizer, TranslationKey, createLocalizer } from "./localize";
import { sharedStyles } from "./styles";
import {
  COLUMN_COUNT,
  renderDetailGrid,
  renderRowAction,
  renderRowCells,
  renderTableHeader,
} from "./table";
import type {
  CrowdSecBansCardConfig,
  Decision,
  DecisionStatus,
  HomeAssistant,
  Instance,
  SortColumn,
} from "./types";

const CARD_VERSION = "1.0.0";

const DEFAULT_PAGE_SIZE = 25;

const STATUS_OPTIONS: (DecisionStatus | "all")[] = ["active", "expired", "all"];

/** mdi:refresh — inlined, so the card needs no icon package. */
const MDI_REFRESH =
  "M17.65,6.35C16.2,4.9 14.21,4 12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20C15.73,20 " +
  "18.84,17.45 19.73,14H17.65C16.83,16.33 14.61,18 12,18A6,6 0 0,1 6,12A6,6 0 " +
  "0,1 12,6C13.66,6 15.14,6.69 16.22,7.78L13,11H20V4L17.65,6.35Z";

console.info(
  "%c CROWDSEC-BANS-CARD %c " + CARD_VERSION + " ",
  "background-color: #000000; color: #4CAF50; font-weight: bold;",
  "background-color: #666666; color: #FFFFFF; font-weight: bold;",
);

@customElement("crowdsec-bans-card")
export class CrowdSecBansCard extends LitElement {
  @property({ attribute: false }) public hass?: HomeAssistant;

  @state() private _config: CrowdSecBansCardConfig = { type: "" };
  @state() private _instances: Instance[] = [];
  @state() private _entryId: string | null = null;
  @state() private _decisions: Decision[] = [];
  @state() private _filter: FilterState = emptyFilter();
  @state() private _sort: SortColumn = "seconds_left";
  @state() private _sortDesc = true;
  @state() private _page = 0;
  @state() private _expanded: string | null = null;
  @state() private _loading = false;
  @state() private _busy: string | null = null;
  @state() private _error: string | null = null;
  @state() private _notice: string | null = null;
  @state() private _lastUpdate: string | null = null;

  private _started = false;

  public setConfig(config: CrowdSecBansCardConfig): void {
    if (config.status && !STATUS_OPTIONS.includes(config.status)) {
      throw new Error(`Unknown status: ${config.status}`);
    }
    if (config.page_size !== undefined && config.page_size < 1) {
      throw new Error(`Invalid page_size: ${config.page_size}`);
    }

    this._config = { page_size: DEFAULT_PAGE_SIZE, ...config };
    this._sort = config.sort ?? "seconds_left";
    this._sortDesc = config.sort_desc ?? true;
    const defaults = emptyFilter();
    this._filter = { ...defaults, status: config.status ?? defaults.status };
    if (config.config_entry_id) {
      this._entryId = config.config_entry_id;
    }
  }

  public getCardSize(): number {
    return 12;
  }

  public static getConfigElement(): HTMLElement {
    return document.createElement("crowdsec-bans-card-editor");
  }

  public static getStubConfig(): CrowdSecBansCardConfig {
    return { type: "custom:crowdsec-bans-card" };
  }

  protected updated(changed: PropertyValues): void {
    if (changed.has("hass") && this.hass && !this._started) {
      this._started = true;
      void this._start();
    }
  }

  private async _start(): Promise<void> {
    if (!this.hass) return;
    try {
      this._instances = await fetchInstances(this.hass);
    } catch (err) {
      this._error = this._message(err);
      return;
    }
    if (!this._entryId) {
      const loaded = this._instances.find((instance) => instance.loaded);
      this._entryId = (loaded ?? this._instances[0])?.config_entry_id ?? null;
    }
    await this._load();
  }

  private async _load(refresh = false): Promise<void> {
    if (!this.hass || !this._entryId) return;
    this._loading = true;
    this._error = null;
    try {
      const t = this._t;
      const result = await fetchAllDecisions(this.hass, this._entryId, refresh);
      this._decisions = result.decisions;
      this._lastUpdate = result.last_update;
      this._notice = !result.reachable
        ? t("notice.unreachable")
        : !result.available
          ? t("notice.unavailable")
          : result.decisions_truncated
            ? t("notice.rows_truncated")
            : result.alerts_truncated
              ? t("notice.truncated")
              : null;
    } catch (err) {
      this._error = this._message(err);
    } finally {
      this._loading = false;
    }
  }

  /**
   * Error text for the banner.
   *
   * The integration answers with a code next to its English message; where the
   * card knows the code it says it in the user's language, and otherwise falls
   * back to what the server wrote — better an English detail than none.
   */
  private _message(err: unknown): string {
    const failure = err as { code?: string; message?: unknown } | null;
    const code = failure?.code;
    if (code && `error.${code}` in EN) {
      return this._t(`error.${code}` as TranslationKey);
    }
    if (failure && failure.message !== undefined) {
      return String(failure.message);
    }
    return String(err);
  }

  private get _locale(): string | undefined {
    return this.hass?.locale?.language ?? this.hass?.language;
  }

  /** Rebuilt per render — the language follows the user, not the card. */
  private get _t(): Localizer {
    return createLocalizer(this.hass);
  }

  private get _rows(): Decision[] {
    return sortDecisions(
      applyFilters(this._decisions, this._filter),
      this._sort,
      this._sortDesc,
    );
  }

  private get _pageSize(): number {
    return this._config.page_size ?? DEFAULT_PAGE_SIZE;
  }

  private _patchFilter(patch: Partial<FilterState>): void {
    this._filter = { ...this._filter, ...patch };
    // Any change to the selection invalidates the page number — page 4 of a
    // three-row result would just be empty.
    this._page = 0;
  }

  private _toggleValue(field: "types" | "scopes", value: string): void {
    const current = this._filter[field];
    this._patchFilter({
      [field]: current.includes(value)
        ? current.filter((item) => item !== value)
        : [...current, value],
    } as Partial<FilterState>);
  }

  private _sortBy(column: SortColumn): void {
    if (this._sort === column) {
      this._sortDesc = !this._sortDesc;
    } else {
      this._sort = column;
      // Time descending means "longest ban first"; text ascending means A–Z.
      this._sortDesc = column === "seconds_left";
    }
    this._page = 0;
  }

  private async _unban(decision: Decision, allForIp: boolean): Promise<void> {
    if (!this.hass || !this._entryId) return;
    const t = this._t;
    const target = allForIp
      ? t("action.target_all", { ip: decision.value ?? "" })
      : t("action.target_one", {
          type: decision.type ?? "",
          ip: decision.value ?? "",
        });
    if (!confirm(t("action.confirm", { target }))) return;

    this._busy = decision.key;
    this._error = null;
    try {
      const result =
        allForIp || decision.id === null
          ? await deleteForIp(this.hass, this._entryId, decision.value ?? "")
          : await deleteDecision(this.hass, this._entryId, decision.id);
      this._notice =
        result.deleted > 0
          ? t("notice.removed", { count: result.deleted })
          : t("notice.removed_none");
      // The answer only carries the first page; the rest is fetched the same
      // way as on open, so a large table stays consistent after a delete.
      if (result.total > result.decisions.length) {
        await this._load();
      } else {
        this._decisions = result.decisions;
      }
    } catch (err) {
      this._error = this._message(err);
    } finally {
      this._busy = null;
    }
  }

  protected render() {
    if (!this.hass) return nothing;
    const t = this._t;
    if (this.hass.user && this.hass.user.is_admin === false) {
      return html`<ha-card
        ><div class="empty">${t("empty.not_admin")}</div></ha-card
      >`;
    }
    if (!this._instances.length && !this._error) {
      return html`<ha-card
        ><div class="empty">${t("empty.no_instance")}</div></ha-card
      >`;
    }

    const rows = this._rows;
    const counts = countDecisions(this._decisions);
    const pages = Math.max(1, Math.ceil(rows.length / this._pageSize));
    const page = Math.min(this._page, pages - 1);
    const visible = rows.slice(page * this._pageSize, (page + 1) * this._pageSize);

    return html`
      <ha-card>
        ${this._renderHeader(counts)}
        ${this._config.hide_filters ? nothing : this._renderFilters(counts)}
        ${this._error ? html`<div class="error">${this._error}</div>` : nothing}
        ${this._notice
          ? html`<div class="notice">
              <span>${this._notice}</span>
              <button
                class="text-button"
                @click=${() => (this._notice = null)}
              >
                ${t("card.dismiss")}
              </button>
            </div>`
          : nothing}
        ${rows.length
          ? this._renderTable(visible)
          : html`<div class="empty">
              ${this._loading ? t("empty.loading") : t("empty.no_match")}
            </div>`}
        ${pages > 1 ? this._renderPager(page, pages, rows.length) : nothing}
      </ha-card>
    `;
  }

  private _renderHeader(counts: Counts) {
    const t = this._t;
    return html`
      <div class="card-header">
        <div class="heading">
          <div class="title">${this._config.title ?? t("card.title")}</div>
          <div class="subtitle">
            ${t("card.counts", {
              active: counts.active,
              expired: counts.expired,
            })}
          </div>
        </div>
        <div class="spacer"></div>
        <div class="actions">
          ${this._instances.length > 1
            ? html`<select
                .value=${this._entryId ?? ""}
                @change=${(event: Event) => {
                  this._entryId = (event.target as HTMLSelectElement).value;
                  this._page = 0;
                  void this._load();
                }}
              >
                ${this._instances.map(
                  (instance) => html`<option value=${instance.config_entry_id}>
                    ${instance.title}
                  </option>`,
                )}
              </select>`
            : nothing}
          <span class="time" title=${t("card.last_poll")}
            >${formatMoment(this._lastUpdate, this._locale, t)}</span
          >
          <ha-icon-button
            class=${this._loading ? "spinning" : ""}
            .path=${MDI_REFRESH}
            .disabled=${this._loading}
            .label=${this._loading ? t("card.refreshing") : t("card.refresh")}
            @click=${() => void this._load(true)}
          ></ha-icon-button>
        </div>
      </div>
    `;
  }

  private _renderFilters(counts: Counts) {
    const t = this._t;
    const types = distinctValues(this._decisions, "type");
    const scopes = distinctValues(this._decisions, "scope");

    return html`
      <div class="filters">
        <input
          class="search"
          type="search"
          placeholder=${t("card.search")}
          .value=${this._filter.search}
          @input=${(event: Event) =>
            this._patchFilter({
              search: (event.target as HTMLInputElement).value,
            })}
        />
        <div class="chips">
          ${STATUS_OPTIONS.map(
            (status) => html`<button
              class="chip ${this._filter.status === status ? "active" : ""}"
              @click=${() => this._patchFilter({ status })}
            >
              ${t(`status.${status}` as TranslationKey)}
            </button>`,
          )}
          ${types.length > 1
            ? html`<span class="divider"></span>
                ${types.map(
                  (type) => html`<button
                    class="chip ${this._filter.types.includes(type) ? "active" : ""}"
                    @click=${() => this._toggleValue("types", type)}
                  >
                    ${type}
                  </button>`,
                )}`
            : nothing}
          ${scopes.length > 1
            ? html`${scopes.map(
                (scope) => html`<button
                  class="chip ${this._filter.scopes.includes(scope) ? "active" : ""}"
                  @click=${() => this._toggleValue("scopes", scope)}
                >
                  ${scope}
                </button>`,
              )}`
            : nothing}
          <span class="divider"></span>
          <button
            class="chip ${this._filter.deletableOnly ? "active" : ""}"
            title=${t("filter.unbannable_hint")}
            @click=${() =>
              this._patchFilter({ deletableOnly: !this._filter.deletableOnly })}
          >
            ${t("filter.unbannable")}
          </button>
        </div>
      </div>
    `;
  }

  private _sortIndicator(column: SortColumn) {
    if (this._sort !== column) return nothing;
    return html`<span class="arrow">${this._sortDesc ? "▾" : "▴"}</span>`;
  }

  private _renderTable(rows: Decision[]) {
    return html`
      <div class="table-wrap">
        <table>
          ${renderTableHeader(this._t, {
            onSort: (column) => this._sortBy(column),
            indicator: (column) => this._sortIndicator(column),
          })}
          <tbody>
            ${rows.map((row) => this._renderRow(row))}
          </tbody>
        </table>
      </div>
    `;
  }

  private _renderRow(row: Decision) {
    const expanded = this._expanded === row.key;
    return html`
      <tr
        class="row ${row.status} ${expanded ? "expanded" : ""}"
        @click=${() => (this._expanded = expanded ? null : row.key)}
      >
        ${renderRowCells(row, this._t, this._locale)}
        <td class="right">
          ${renderRowAction(row, this._t, {
            busy: this._busy === row.key,
            onUnban: (event: Event) => {
              // Without this the click would also toggle the detail panel.
              event.stopPropagation();
              void this._unban(row, false);
            },
          })}
        </td>
      </tr>
      ${expanded ? this._renderDetails(row) : nothing}
    `;
  }

  private _renderDetails(row: Decision) {
    const t = this._t;
    return html`
      <tr class="details">
        <td colspan=${COLUMN_COUNT}>
          ${renderDetailGrid(row, t, this._locale)}
          ${row.status === "active" && row.value
            ? html`<div class="detail-actions">
                <button
                  class="text-button danger"
                  ?disabled=${this._busy === row.key}
                  @click=${(event: Event) => {
                    event.stopPropagation();
                    void this._unban(row, true);
                  }}
                >
                  ${t("action.unban_all", { ip: row.value })}
                </button>
              </div>`
            : nothing}
        </td>
      </tr>
    `;
  }

  private _renderPager(page: number, pages: number, total: number) {
    const t = this._t;
    return html`
      <div class="pager">
        <button
          class="text-button"
          ?disabled=${page === 0}
          @click=${() => (this._page = page - 1)}
        >
          ${t("pager.previous")}
        </button>
        <span class="time"
          >${t("pager.info", { page: page + 1, pages, total })}</span
        >
        <button
          class="text-button"
          ?disabled=${page >= pages - 1}
          @click=${() => (this._page = page + 1)}
        >
          ${t("pager.next")}
        </button>
      </div>
    `;
  }

  static styles = [
    sharedStyles,
    css`
      ha-card {
        overflow: hidden;
      }

      /* The icon button brings its own padding; without compensation the row
         would end short of the right edge the table keeps. */
      .actions ha-icon-button {
        margin-right: -8px;
        color: var(--secondary-text-color);
      }
      /* Turning while the poll runs — the icon is the only feedback there is. */
      .actions ha-icon-button.spinning {
        animation: spin 1s linear infinite;
      }
      @keyframes spin {
        to {
          transform: rotate(360deg);
        }
      }
      @media (prefers-reduced-motion: reduce) {
        .actions ha-icon-button.spinning {
          animation: none;
          opacity: 0.5;
        }
      }
      .time {
        font-size: 12px;
        color: var(--secondary-text-color);
        white-space: nowrap;
      }

      input.search {
        width: 100%;
        box-sizing: border-box;
      }

      .filters {
        display: flex;
        flex-direction: column;
        gap: 8px;
        padding: 0 12px 8px;
      }
      .chips {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 6px;
      }
      .chip {
        border: 1px solid var(--divider-color);
        background: none;
        color: var(--primary-text-color);
        border-radius: 14px;
        padding: 3px 10px;
        font-size: 12px;
        font-family: inherit;
        cursor: pointer;
        text-transform: capitalize;
      }
      /* Active chips carry the fill, inactive ones step back — the state stays
         legible from the contrast even without color vision. */
      .chip.active {
        background: var(--primary-color);
        border-color: var(--primary-color);
        color: #fff;
        font-weight: 600;
      }
      .chip:not(.active) {
        opacity: 0.7;
      }
      .divider {
        width: 1px;
        height: 18px;
        background: var(--divider-color);
        margin: 0 2px;
      }

      /* The header stays put while a long table scrolls under it. */
      th {
        position: sticky;
        top: 0;
        z-index: 1;
        background: var(--card-background-color);
      }


      .pager {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        padding: 4px 12px 8px;
      }
    `,
  ];
}

declare global {
  interface HTMLElementTagNameMap {
    "crowdsec-bans-card": CrowdSecBansCard;
  }
  interface Window {
    customCards?: unknown[];
  }
}

window.customCards = window.customCards || [];
window.customCards.push({
  type: "crowdsec-bans-card",
  name: "CrowdSec Bans",
  description:
    "Active CrowdSec decisions with search, filters and one-click unban",
  preview: false,
  documentationURL: "https://github.com/stefgo/ha-crowdsec-integration",
});
window.customCards.push({
  type: "crowdsec-ip-lookup-card",
  name: "CrowdSec IP Lookup",
  description:
    "Check one address against every source — local, CAPI and blocklists, " +
    "including a range containing it — and ban or unban it",
  preview: false,
  documentationURL: "https://github.com/stefgo/ha-crowdsec-integration",
});
