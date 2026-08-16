/** Visual editor of the lookup card (ha-form). */

import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";

import { fetchInstances } from "./api";
import { Localizer, TranslationKey, createLocalizer } from "./localize";
import type {
  CrowdSecIpLookupCardConfig,
  HomeAssistant,
  Instance,
} from "./types";

@customElement("crowdsec-ip-lookup-card-editor")
export class CrowdSecIpLookupCardEditor extends LitElement {
  @property({ attribute: false }) public hass?: HomeAssistant;

  @state() private _config: CrowdSecIpLookupCardConfig = { type: "" };
  @state() private _instances: Instance[] = [];

  public setConfig(config: CrowdSecIpLookupCardConfig): void {
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
      { name: "ban_duration", selector: { text: {} } },
      { name: "ban_reason", selector: { text: {} } },
      { name: "hide_ban", selector: { boolean: {} } },
    ];
  }

  private _label = (schema: { name: string }): string => {
    const key = `editor.${
      schema.name === "config_entry_id" ? "instance" : schema.name
    }`;
    return this._t(key as TranslationKey);
  };

  private _changed(event: CustomEvent): void {
    this.dispatchEvent(
      new CustomEvent("config-changed", {
        detail: { config: event.detail.value },
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

declare global {
  interface HTMLElementTagNameMap {
    "crowdsec-ip-lookup-card-editor": CrowdSecIpLookupCardEditor;
  }
}
