/**
 * CrowdSec IP Lookup Card
 *
 * The question the ban table cannot answer: "is *this* address blocked?" The
 * table lists what is enforced, and an address blocked through a /24 from a
 * blocklist appears nowhere in it — that row is about the range. This card
 * asks the LAPI directly, across every origin and regardless of the scope the
 * integration is configured for, and can put a ban there itself.
 */

import { LitElement, PropertyValues, css, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";

import "./ip-lookup-editor";
import {
  banIp,
  deleteDecision,
  deleteForIp,
  fetchInstances,
  lookupIp,
} from "./api";
import {
  countryFlag,
  countryName,
  formatMoment,
  formatRemaining,
} from "./format";
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
  CrowdSecIpLookupCardConfig,
  Decision,
  HomeAssistant,
  Instance,
  IpReport,
} from "./types";

const DEFAULT_DURATION = "4h";
const DEFAULT_REASON = "Home Assistant";

@customElement("crowdsec-ip-lookup-card")
export class CrowdSecIpLookupCard extends LitElement {
  @property({ attribute: false }) public hass?: HomeAssistant;

  @state() private _config: CrowdSecIpLookupCardConfig = { type: "" };
  @state() private _instances: Instance[] = [];
  @state() private _entryId: string | null = null;
  @state() private _query = "";
  @state() private _report: IpReport | null = null;
  @state() private _loading = false;
  @state() private _busy = false;
  @state() private _error: string | null = null;
  @state() private _notice: string | null = null;
  @state() private _expanded: string | null = null;
  @state() private _duration = DEFAULT_DURATION;
  @state() private _reason = DEFAULT_REASON;

  private _started = false;

  public setConfig(config: CrowdSecIpLookupCardConfig): void {
    this._config = config;
    this._duration = config.ban_duration ?? DEFAULT_DURATION;
    this._reason = config.ban_reason ?? DEFAULT_REASON;
    if (config.config_entry_id) {
      this._entryId = config.config_entry_id;
    }
  }

  public getCardSize(): number {
    return this._report ? 8 : 3;
  }

  public static getConfigElement(): HTMLElement {
    return document.createElement("crowdsec-ip-lookup-card-editor");
  }

  public static getStubConfig(): CrowdSecIpLookupCardConfig {
    return { type: "custom:crowdsec-ip-lookup-card" };
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
  }

  private get _t(): Localizer {
    return createLocalizer(this.hass);
  }

  private get _locale(): string | undefined {
    return this.hass?.locale?.language ?? this.hass?.language;
  }

  /**
   * Error text for the banner.
   *
   * The integration answers with a code next to its English message; where the
   * card knows the code it says it in the user's language, and otherwise falls
   * back to what the server wrote.
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

  private async _lookup(): Promise<void> {
    const query = this._query.trim();
    if (!this.hass || !this._entryId || !query) return;
    this._loading = true;
    this._error = null;
    this._notice = null;
    try {
      this._report = await lookupIp(this.hass, this._entryId, query);
    } catch (err) {
      this._error = this._message(err);
      // A failed lookup must not leave the previous answer standing — it would
      // read as the result for the address now in the box.
      this._report = null;
    } finally {
      this._loading = false;
    }
  }

  private async _ban(): Promise<void> {
    const t = this._t;
    const target = this._report?.target ?? this._query.trim();
    if (!this.hass || !this._entryId || !target) return;
    if (!confirm(t("lookup.ban_confirm", { ip: target, duration: this._duration }))) {
      return;
    }

    this._busy = true;
    this._error = null;
    try {
      this._report = await banIp(
        this.hass,
        this._entryId,
        target,
        this._duration,
        this._reason,
      );
      this._notice = t("lookup.banned", {
        ip: target,
        duration: this._duration,
      });
    } catch (err) {
      this._error = this._message(err);
    } finally {
      this._busy = false;
    }
  }

  /** Remove one decision — the same action the ban table offers per row. */
  private async _unbanRow(row: Decision): Promise<void> {
    const t = this._t;
    if (!this.hass || !this._entryId || row.id === null) return;
    if (!confirm(t("action.confirm", { target: `${row.type} ${row.value}` }))) {
      return;
    }

    this._busy = true;
    this._error = null;
    try {
      const result = await deleteDecision(this.hass, this._entryId, row.id);
      this._notice = t("lookup.unbanned", { count: result.deleted });
      // Ask again instead of dropping the row: another decision may still
      // cover the address, and then it is not free at all.
      this._report = await lookupIp(this.hass, this._entryId, row.value ?? "");
    } catch (err) {
      this._error = this._message(err);
    } finally {
      this._busy = false;
    }
  }

  private async _unban(): Promise<void> {
    const t = this._t;
    const target = this._report?.target;
    if (!this.hass || !this._entryId || !target) return;
    if (!confirm(t("action.confirm", { target: t("lookup.unban_all") }))) return;

    this._busy = true;
    this._error = null;
    try {
      const result = await deleteForIp(this.hass, this._entryId, target);
      this._notice = t("lookup.unbanned", { count: result.deleted });
      // Ask again rather than trusting the delete count: a covering range may
      // still be in force even after the address's own decision is gone.
      this._report = await lookupIp(this.hass, this._entryId, target);
    } catch (err) {
      this._error = this._message(err);
    } finally {
      this._busy = false;
    }
  }

  protected render() {
    const t = this._t;
    if (!this.hass) return nothing;
    if (!this._instances.length && !this._error) {
      return html`<ha-card
        ><div class="empty">${t("empty.no_instance")}</div></ha-card
      >`;
    }

    return html`
      <ha-card>
        <div class="card-header">
          <div class="title">${this._config.title ?? t("lookup.title")}</div>
          <div class="spacer"></div>
          ${this._instances.length > 1
            ? html`<div class="actions">
                <select
                  @change=${(event: Event) => {
                    this._entryId = (event.target as HTMLSelectElement).value;
                    this._report = null;
                  }}
                >
                  ${this._instances.map(
                    (instance) => html`<option
                      value=${instance.config_entry_id}
                      ?selected=${instance.config_entry_id === this._entryId}
                    >
                      ${instance.title}
                    </option>`,
                  )}
                </select>
              </div>`
            : nothing}
        </div>

        <div class="query">
          <input
            class="search"
            type="search"
            placeholder=${t("lookup.placeholder")}
            .value=${this._query}
            @input=${(event: Event) => {
              this._query = (event.target as HTMLInputElement).value;
            }}
            @keydown=${(event: KeyboardEvent) => {
              if (event.key === "Enter") void this._lookup();
            }}
          />
          <button
            class="text-button"
            ?disabled=${this._loading || !this._query.trim()}
            @click=${() => void this._lookup()}
          >
            ${this._loading ? t("lookup.checking") : t("lookup.check")}
          </button>
        </div>

        ${this._error ? html`<div class="error">${this._error}</div>` : nothing}
        ${this._notice
          ? html`<div class="notice">
              <span>${this._notice}</span>
              <button class="text-button" @click=${() => (this._notice = null)}>
                ${t("card.dismiss")}
              </button>
            </div>`
          : nothing}
        ${this._report ? this._renderReport(this._report) : nothing}
      </ha-card>
    `;
  }

  private _renderReport(report: IpReport) {
    const t = this._t;
    // The route being closed is not the same as "nothing found" — saying
    // "not blocked" there would be a guess dressed up as an answer.
    if (report.decisions_available === false) {
      return html`<div class="verdict">
        <span class="mono address">${report.target}</span>
        <span class="state unknown">${t("lookup.unknown")}</span>
      </div>`;
    }

    return html`
      <div class="verdict">
        <span class="mono address">${report.target}</span>
        <span class="state ${report.blocked ? "blocked" : "clear"}">
          ${report.blocked ? t("lookup.blocked") : t("lookup.not_blocked")}
        </span>
        ${report.blocked
          ? html`<span class="sub">
              ${formatRemaining(report.seconds_left, t)}${report.expires_at
                ? html` · ${t("lookup.expires")}
                    ${formatMoment(report.expires_at, this._locale, t)}`
                : nothing}
            </span>`
          : nothing}
      </div>

      ${report.covering_ranges.length
        ? html`<div class="notice">
            <span>
              ${t("lookup.covered_by", {
                ranges: report.covering_ranges.join(", "),
              })}
              — ${t("lookup.covered_hint")}
            </span>
          </div>`
        : nothing}
      ${report.decisions.length ? this._renderDecisions(report) : nothing}
      ${this._renderHistory(report)} ${this._renderActions(report)}
    `;
  }

  private _renderDecisions(report: IpReport) {
    const t = this._t;
    return html`
      <div class="section-title">${t("lookup.decisions")}</div>
      <div class="table-wrap">
        <table>
          ${renderTableHeader(t)}
          <tbody>
            ${report.decisions.map((row) => this._renderRow(row))}
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
            busy: this._busy,
            onUnban: (event: Event) => {
              // Without this the click would also toggle the detail panel.
              event.stopPropagation();
              void this._unbanRow(row);
            },
          })}
        </td>
      </tr>
      ${expanded
        ? html`<tr class="details">
            <td colspan=${COLUMN_COUNT}>
              ${renderDetailGrid(row, this._t, this._locale)}
            </td>
          </tr>`
        : nothing}
    `;
  }

  private _renderHistory(report: IpReport) {
    const t = this._t;
    if (!report.alerts_available) {
      return html`<div class="section-title">${t("lookup.history")}</div>
        <div class="empty">${t("lookup.alerts_unavailable")}</div>`;
    }
    if (!report.alerts) {
      return html`<div class="section-title">${t("lookup.history")}</div>
        <div class="empty">${t("lookup.no_alerts")}</div>`;
    }

    const entries: [string, unknown][] = [
      [t("lookup.alerts"), report.alerts],
      ...(report.first_seen
        ? ([
            [
              t("lookup.first_seen"),
              formatMoment(report.first_seen, this._locale, t),
            ],
          ] as [string, unknown][])
        : []),
      ...(report.last_seen
        ? ([
            [
              t("lookup.last_seen"),
              formatMoment(report.last_seen, this._locale, t),
            ],
          ] as [string, unknown][])
        : []),
      ...(report.country
        ? ([
            [
              t("column.country"),
              `${countryFlag(report.country)} ${countryName(
                report.country,
                this._locale,
              )}`,
            ],
          ] as [string, unknown][])
        : []),
      ...(report.as_name
        ? ([[t("column.as"), report.as_name]] as [string, unknown][])
        : []),
      ...(report.scenarios.length
        ? ([
            [t("lookup.scenarios"), report.scenarios.join(", ")],
          ] as [string, unknown][])
        : []),
    ];

    return html`
      <div class="section-title">${t("lookup.history")}</div>
      <div class="history">
        <div class="detail-grid">
          ${entries.map(
            ([label, value]) => html`<div class="detail">
              <span class="label">${label}</span>
              <span class="value">${value}</span>
            </div>`,
          )}
        </div>
      </div>
    `;
  }

  private _renderActions(report: IpReport) {
    const t = this._t;
    const canUnban = report.blocked && report.deletable;
    return html`
      <div class="footer">
        ${canUnban
          ? html`<button
              class="text-button danger"
              ?disabled=${this._busy}
              @click=${() => void this._unban()}
            >
              ${t("lookup.unban_all")}
            </button>`
          : nothing}
        ${report.blocked && !report.deletable
          ? html`<span class="hint">${t("lookup.not_deletable")}</span>`
          : nothing}
        <div class="spacer"></div>
        ${this._config.hide_ban
          ? nothing
          : html`
              <input
                class="short"
                aria-label=${t("lookup.ban_duration")}
                .value=${this._duration}
                @input=${(event: Event) => {
                  this._duration = (event.target as HTMLInputElement).value;
                }}
              />
              <input
                class="reason"
                aria-label=${t("lookup.ban_reason")}
                .value=${this._reason}
                @input=${(event: Event) => {
                  this._reason = (event.target as HTMLInputElement).value;
                }}
              />
              <button
                class="text-button"
                ?disabled=${this._busy}
                @click=${() => void this._ban()}
              >
                ${this._busy ? t("lookup.banning") : t("lookup.ban")}
              </button>
            `}
      </div>
    `;
  }

  static styles = [
    sharedStyles,
    css`
      ha-card {
        overflow: hidden;
      }

      /* Same 12px left edge as the header and the table cells. */
      .query {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 0 12px 8px;
      }
      input.search {
        flex: 1;
        min-width: 0;
      }

      /* The answer to the question, so it gets a line of its own — but in the
         card's own type scale, not a banner. */
      .verdict {
        display: flex;
        align-items: baseline;
        flex-wrap: wrap;
        gap: 8px;
        padding: 8px 12px 12px;
        border-top: 1px solid var(--divider-color);
      }
      .address {
        font-size: 15px;
      }
      .state {
        font-size: 13px;
        font-weight: 500;
      }
      .state.blocked {
        color: var(--error-color);
      }
      .state.clear {
        color: var(--success-color, var(--state-icon-active-color));
      }
      .state.unknown {
        color: var(--warning-color);
      }
      .sub {
        font-size: 12px;
        color: var(--secondary-text-color);
      }

      .section-title {
        font-size: 12px;
        font-weight: 500;
        color: var(--secondary-text-color);
        padding: 8px 12px 4px;
      }
      .history {
        padding: 4px 12px 8px;
      }

      .footer {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 8px;
        padding: 8px 12px 12px;
        border-top: 1px solid var(--divider-color);
      }
      .hint {
        font-size: 12px;
        color: var(--secondary-text-color);
      }
      input.short {
        width: 4.5em;
      }
      input.reason {
        flex: 1;
        min-width: 8em;
      }
      /* The text buttons bring their own padding; without compensation the row
         would end short of the edge the rest of the card keeps. */
      .footer .text-button:last-child {
        margin-right: -8px;
      }
    `,
  ];
}

declare global {
  interface HTMLElementTagNameMap {
    "crowdsec-ip-lookup-card": CrowdSecIpLookupCard;
  }
}
