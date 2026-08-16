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
import { banIp, deleteForIp, fetchInstances, lookupIp } from "./api";
import { countryFlag, countryName, formatMoment, formatRemaining } from "./format";
import { EN, Localizer, TranslationKey, createLocalizer } from "./localize";
import type {
  CrowdSecIpLookupCardConfig,
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
          ${this._instances.length > 1
            ? html`<select
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
              </select>`
            : nothing}
        </div>

        <div class="query">
          <input
            type="text"
            inputmode="numeric"
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
            class="primary"
            ?disabled=${this._loading || !this._query.trim()}
            @click=${() => void this._lookup()}
          >
            ${this._loading ? t("lookup.checking") : t("lookup.check")}
          </button>
        </div>
        <div class="intro">${t("lookup.intro")}</div>

        ${this._error ? html`<div class="error">${this._error}</div>` : nothing}
        ${this._notice
          ? html`<div class="notice">
              <span>${this._notice}</span>
              <button class="text-button" @click=${() => (this._notice = null)}>
                ${t("card.dismiss")}
              </button>
            </div>`
          : nothing}
        ${this._report ? this._renderReport(this._report) : this._renderEmpty()}
      </ha-card>
    `;
  }

  private _renderEmpty() {
    return html`<div class="empty">${this._t("lookup.empty")}</div>`;
  }

  private _renderReport(report: IpReport) {
    const t = this._t;
    // The route being closed is not the same as "nothing found" — saying
    // "not blocked" there would be a guess dressed up as an answer.
    if (report.decisions_available === false) {
      return html`<div class="verdict unknown">
        <div class="target">${report.target}</div>
        <div class="state">${t("lookup.unknown")}</div>
      </div>`;
    }

    return html`
      <div class="verdict ${report.blocked ? "blocked" : "clear"}">
        <div class="target">${report.target}</div>
        <div class="state">
          ${report.blocked ? t("lookup.blocked") : t("lookup.not_blocked")}
        </div>
        ${report.blocked
          ? html`<div class="sub">
              ${t("lookup.remaining")}:
              ${formatRemaining(report.seconds_left, t)}${report.expires_at
                ? html` · ${t("lookup.expires")}
                    ${formatMoment(report.expires_at, this._locale, t)}`
                : nothing}
            </div>`
          : nothing}
      </div>

      ${report.covering_ranges.length
        ? html`<div class="covered">
            <div class="covered-title">
              ${t("lookup.covered_by", {
                ranges: report.covering_ranges.join(", "),
              })}
            </div>
            <div class="covered-hint">${t("lookup.covered_hint")}</div>
          </div>`
        : nothing}
      ${report.decisions.length ? this._renderDecisions(report) : nothing}
      ${this._renderHistory(report)} ${this._renderActions(report)}
    `;
  }

  private _renderDecisions(report: IpReport) {
    const t = this._t;
    return html`
      <div class="section">
        <div class="section-title">${t("lookup.decisions")}</div>
        <table>
          <tbody>
            ${report.decisions.map(
              (decision) => html`<tr>
                <td class="mono">${decision.value}</td>
                <td>${decision.type}</td>
                <td>${decision.scenario ?? "—"}</td>
                <td>
                  <span class="tag ${decision.origin_kind}"
                    >${decision.origin ?? decision.origin_kind}</span
                  >
                </td>
                <td class="right">
                  ${formatRemaining(decision.seconds_left, t)}
                </td>
              </tr>`,
            )}
          </tbody>
        </table>
      </div>
    `;
  }

  private _renderHistory(report: IpReport) {
    const t = this._t;
    if (!report.alerts_available) {
      return html`<div class="section">
        <div class="section-title">${t("lookup.history")}</div>
        <div class="muted">${t("lookup.alerts_unavailable")}</div>
      </div>`;
    }
    if (!report.alerts) {
      return html`<div class="section">
        <div class="section-title">${t("lookup.history")}</div>
        <div class="muted">${t("lookup.no_alerts")}</div>
      </div>`;
    }

    return html`
      <div class="section">
        <div class="section-title">${t("lookup.history")}</div>
        <dl>
          <dt>${t("lookup.alerts")}</dt>
          <dd>${report.alerts}</dd>
          ${report.first_seen
            ? html`<dt>${t("lookup.first_seen")}</dt>
                <dd>${formatMoment(report.first_seen, this._locale, t)}</dd>`
            : nothing}
          ${report.last_seen
            ? html`<dt>${t("lookup.last_seen")}</dt>
                <dd>${formatMoment(report.last_seen, this._locale, t)}</dd>`
            : nothing}
          ${report.country
            ? html`<dt>${t("column.country")}</dt>
                <dd>
                  ${countryFlag(report.country)}
                  ${countryName(report.country, this._locale)}
                </dd>`
            : nothing}
          ${report.as_name
            ? html`<dt>${t("column.as")}</dt>
                <dd>${report.as_name}</dd>`
            : nothing}
          ${report.scenarios.length
            ? html`<dt>${t("lookup.scenarios")}</dt>
                <dd>${report.scenarios.join(", ")}</dd>`
            : nothing}
        </dl>
      </div>
    `;
  }

  private _renderActions(report: IpReport) {
    const t = this._t;
    const canUnban = report.blocked && report.deletable;
    return html`
      <div class="actions">
        ${canUnban
          ? html`<button
              class="danger"
              ?disabled=${this._busy}
              @click=${() => void this._unban()}
            >
              ${t("lookup.unban_all")}
            </button>`
          : nothing}
        ${report.blocked && !report.deletable
          ? html`<div class="muted">${t("lookup.not_deletable")}</div>`
          : nothing}
        ${this._config.hide_ban
          ? nothing
          : html`
              <div class="ban-row">
                <input
                  class="short"
                  aria-label=${t("lookup.ban_duration")}
                  .value=${this._duration}
                  @input=${(event: Event) => {
                    this._duration = (event.target as HTMLInputElement).value;
                  }}
                />
                <input
                  aria-label=${t("lookup.ban_reason")}
                  .value=${this._reason}
                  @input=${(event: Event) => {
                    this._reason = (event.target as HTMLInputElement).value;
                  }}
                />
                <button
                  class="primary"
                  ?disabled=${this._busy}
                  @click=${() => void this._ban()}
                >
                  ${this._busy ? t("lookup.banning") : t("lookup.ban")}
                </button>
              </div>
            `}
      </div>
    `;
  }

  static styles = css`
    ha-card {
      padding: 12px 16px 16px;
    }

    .card-header {
      display: flex;
      align-items: center;
      gap: 12px;
      padding-bottom: 8px;
    }
    .title {
      font-size: 1.3rem;
      font-weight: 500;
      flex: 1;
    }

    .query {
      display: flex;
      gap: 8px;
    }
    input {
      flex: 1;
      min-width: 0;
      padding: 8px 10px;
      border: 1px solid var(--divider-color, #ccc);
      border-radius: 8px;
      background: var(--card-background-color, #fff);
      color: var(--primary-text-color);
      font: inherit;
    }
    input.short {
      flex: 0 0 5.5rem;
    }
    select {
      padding: 6px 8px;
      border-radius: 8px;
      border: 1px solid var(--divider-color, #ccc);
      background: var(--card-background-color, #fff);
      color: var(--primary-text-color);
      font: inherit;
    }

    button {
      padding: 8px 14px;
      border: none;
      border-radius: 8px;
      font: inherit;
      cursor: pointer;
      background: var(--secondary-background-color, #eee);
      color: var(--primary-text-color);
    }
    button[disabled] {
      opacity: 0.5;
      cursor: default;
    }
    button.primary {
      background: var(--primary-color);
      color: var(--text-primary-color, #fff);
    }
    button.danger {
      background: var(--error-color, #db4437);
      color: var(--text-primary-color, #fff);
    }
    .text-button {
      background: none;
      padding: 0 4px;
      color: var(--primary-color);
    }

    .intro,
    .muted {
      color: var(--secondary-text-color);
      font-size: 0.85rem;
      padding-top: 6px;
    }

    .error,
    .notice {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 10px;
      padding: 8px 10px;
      border-radius: 8px;
      font-size: 0.9rem;
    }
    .error {
      background: var(--error-color, #db4437);
      color: var(--text-primary-color, #fff);
    }
    .notice {
      background: var(--secondary-background-color, #eee);
    }
    .notice span {
      flex: 1;
    }

    .empty {
      padding: 24px 0;
      text-align: center;
      color: var(--secondary-text-color);
    }

    /* The verdict is the answer to the question — it gets the space and the
       colour, everything below it is supporting detail. */
    .verdict {
      margin-top: 14px;
      padding: 12px 14px;
      border-radius: 10px;
      border-left: 4px solid var(--divider-color, #ccc);
      background: var(--secondary-background-color, #f4f4f4);
    }
    .verdict.blocked {
      border-left-color: var(--error-color, #db4437);
    }
    .verdict.clear {
      border-left-color: var(--success-color, #43a047);
    }
    .verdict.unknown {
      border-left-color: var(--warning-color, #ffa600);
    }
    .target {
      font-family: var(--code-font-family, monospace);
      font-size: 1.05rem;
    }
    .state {
      font-size: 1.2rem;
      font-weight: 500;
      padding-top: 2px;
    }
    .sub {
      color: var(--secondary-text-color);
      font-size: 0.9rem;
      padding-top: 4px;
    }

    /* Being caught by a range is the finding people do not expect, so it gets
       its own block rather than a footnote in the table. */
    .covered {
      margin-top: 10px;
      padding: 10px 12px;
      border-radius: 8px;
      background: var(--secondary-background-color, #f4f4f4);
    }
    .covered-title {
      font-family: var(--code-font-family, monospace);
    }
    .covered-hint {
      color: var(--secondary-text-color);
      font-size: 0.85rem;
      padding-top: 4px;
    }

    .section {
      margin-top: 16px;
    }
    .section-title {
      font-weight: 500;
      padding-bottom: 6px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }
    td {
      padding: 6px 8px;
      border-top: 1px solid var(--divider-color, #eee);
    }
    td.right {
      text-align: right;
      white-space: nowrap;
    }
    .mono {
      font-family: var(--code-font-family, monospace);
    }

    dl {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 4px 16px;
      margin: 0;
      font-size: 0.9rem;
    }
    dt {
      color: var(--secondary-text-color);
    }
    dd {
      margin: 0;
    }

    /* Only the origins that limit what can be done get a colour; local is the
       normal case and stays quiet. */
    .tag {
      padding: 1px 6px;
      border-radius: 6px;
      font-size: 0.8rem;
      background: var(--secondary-background-color, #eee);
    }
    .tag.capi,
    .tag.lists {
      background: var(--warning-color, #ffa600);
      color: var(--text-primary-color, #fff);
    }

    .actions {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      margin-top: 16px;
    }
    .ban-row {
      display: flex;
      gap: 8px;
      flex: 1;
      min-width: 260px;
    }
  `;
}

declare global {
  interface HTMLElementTagNameMap {
    "crowdsec-ip-lookup-card": CrowdSecIpLookupCard;
  }
}
