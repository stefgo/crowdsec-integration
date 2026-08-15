/** Visual editor of the card (ha-form). */

import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";

import { fetchInstances } from "./api";
import { ORIGIN_KINDS } from "./filters";
import { Localizer, TranslationKey, createLocalizer } from "./localize";
import type { CrowdSecBansCardConfig, HomeAssistant, Instance } from "./types";

@customElement("crowdsec-bans-card-editor")
export class CrowdSecBansCardEditor extends LitElement {
  @property({ attribute: false }) public hass?: HomeAssistant;

  @state() private _config: CrowdSecBansCardConfig = { type: "" };
  @state() private _instances: Instance[] = [];

  public setConfig(config: CrowdSecBansCardConfig): void {
    this._config = config;
  }

  protected firstUpdated(): void {
    if (this.hass) {
      void fetchInstances(this.hass).then((instances) => {
        this._instances = instances;
      });
    }
  }

  private get _t(): Localizer {
    return createLocalizer(this.hass);
  }

  private get _schema() {
    const t = this._t;
    return [
      { name: "title", selector: { text: {} } },
      {
        name: "config_entry_id",
        selector: {
          select: {
            mode: "dropdown",
            options: this._instances.map((instance) => ({
              value: instance.config_entry_id,
              label: instance.title,
            })),
          },
        },
      },
      {
        name: "status",
        selector: {
          select: {
            mode: "dropdown",
            options: [
              { value: "active", label: t("editor.status.active") },
              { value: "expired", label: t("editor.status.expired") },
              { value: "all", label: t("editor.status.all") },
            ],
          },
        },
      },
      {
        name: "origins",
        selector: {
          select: {
            multiple: true,
            mode: "list",
            options: ORIGIN_KINDS.map((kind) => ({
              value: kind,
              label: t(`origin.${kind}` as TranslationKey),
            })),
          },
        },
      },
      {
        name: "sort",
        selector: {
          select: {
            mode: "dropdown",
            options: [
              "seconds_left",
              "value",
              "scenario",
              "country",
              "as_name",
              "origin",
              "type",
            ].map((column) => ({
              value: column,
              label: t(`editor.sort.${column}` as TranslationKey),
            })),
          },
        },
      },
      {
        name: "page_size",
        selector: { number: { min: 5, max: 200, step: 5, mode: "box" } },
      },
      { name: "hide_filters", selector: { boolean: {} } },
    ];
  }

  private _label = (schema: { name: string }): string => {
    const key = `editor.${schema.name === "config_entry_id" ? "instance" : schema.name}`;
    const label = this._t(key as TranslationKey);
    // An unknown field would render its key; the bare name reads better.
    return label === key ? schema.name : label;
  };

  private _changed(event: CustomEvent): void {
    const config = (event.detail as { value: CrowdSecBansCardConfig }).value;
    this.dispatchEvent(
      new CustomEvent("config-changed", {
        detail: { config },
        bubbles: true,
        composed: true,
      }),
    );
  }

  protected render() {
    if (!this.hass) return nothing;
    return html`
      <ha-form
        .hass=${this.hass}
        .data=${this._config}
        .schema=${this._schema}
        .computeLabel=${this._label}
        @value-changed=${this._changed}
      ></ha-form>
    `;
  }
}
