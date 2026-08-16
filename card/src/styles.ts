/**
 * The visual vocabulary both cards share.
 *
 * They sit on the same dashboard and have to read as one thing: same header,
 * same type scale, same controls. Keeping the rules here rather than copying
 * them is what stops the two from drifting apart — which is exactly what
 * happened when the lookup card was first written with its own set.
 *
 * Sizes are px on purpose, matching Home Assistant's own cards: a rem scale
 * would follow the browser font size and stop lining up with the cards next to
 * it. Padding lives on the sections, never on `ha-card`, so a table can run
 * edge to edge while text keeps its 12px inset.
 */

import { css } from "lit";

export const sharedStyles = css`
  :host {
    display: block;
  }

  /* Header */
  .card-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 16px 12px 8px;
    flex-wrap: wrap;
  }
  .title {
    font-size: 24px;
    font-weight: 400;
    line-height: 1.2;
  }
  .subtitle {
    font-size: 12px;
    color: var(--secondary-text-color);
  }
  .spacer {
    flex: 1;
  }
  .actions {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  /* Messages */
  .empty {
    padding: 16px 12px;
    color: var(--secondary-text-color);
  }
  .error {
    padding: 12px;
    color: var(--error-color);
  }
  .notice {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 12px 12px;
    font-size: 13px;
    color: var(--warning-color);
  }

  /* Controls — the cards use text buttons throughout; a filled button would
     shout next to Home Assistant's own cards. */
  .text-button {
    background: none;
    border: none;
    color: var(--primary-color);
    font-size: 13px;
    font-family: inherit;
    cursor: pointer;
    padding: 6px 8px;
    border-radius: 4px;
  }
  .text-button:hover:not(:disabled) {
    background: var(--secondary-background-color);
  }
  .text-button:disabled {
    color: var(--secondary-text-color);
    cursor: default;
  }
  .text-button.danger {
    color: var(--error-color);
  }

  select,
  input {
    background: none;
    color: var(--primary-text-color);
    border: 1px solid var(--divider-color);
    border-radius: 4px;
    padding: 6px 8px;
    font-size: 13px;
    font-family: inherit;
  }

  /* Table */
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th,
  td {
    padding: 8px 12px;
    text-align: left;
    border-top: 1px solid var(--divider-color);
    white-space: nowrap;
  }
  th {
    font-size: 12px;
    font-weight: 500;
    color: var(--secondary-text-color);
  }
  .right {
    text-align: right;
  }
  .mono {
    font-family: var(--code-font-family, monospace);
  }

  .tag {
    font-size: 11px;
    padding: 1px 6px;
    border-radius: 8px;
    background: var(--divider-color);
    color: var(--secondary-text-color);
  }
  /* Only the origins that limit what can be done get a colour; local is the
     normal case and stays quiet. */
  .tag.capi {
    color: var(--info-color);
  }
  .tag.lists {
    color: var(--warning-color);
  }

  /* Label/value pairs — the detail panel of one card, the history of the
     other. */
  .detail-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 8px 16px;
  }
  .detail {
    display: flex;
    flex-direction: column;
  }
  .detail .label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--secondary-text-color);
  }
  .detail .value {
    font-size: 13px;
    overflow-wrap: anywhere;
  }
`;
