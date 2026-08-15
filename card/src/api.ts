/** Typed wrapper around the integration's WebSocket commands. */

import type {
  Decision,
  DecisionsResponse,
  HomeAssistant,
  Instance,
} from "./types";

export const DOMAIN = "crowdsec";

export const fetchInstances = async (
  hass: HomeAssistant,
): Promise<Instance[]> => {
  const result = await hass.connection.sendMessagePromise<{
    instances: Instance[];
  }>({ type: `${DOMAIN}/instances` });
  return result.instances;
};

/** One page of the table. `total` says how many rows there are in all. */
export const fetchDecisions = (
  hass: HomeAssistant,
  configEntryId: string,
  refresh = false,
  offset = 0,
  limit = PAGE_SIZE,
): Promise<DecisionsResponse> =>
  hass.connection.sendMessagePromise<DecisionsResponse>({
    type: `${DOMAIN}/decisions/list`,
    config_entry_id: configEntryId,
    refresh,
    offset,
    limit,
  });

/** Rows per WebSocket message — the integration uses the same default. */
export const PAGE_SIZE = 500;

/**
 * Every row, fetched page by page.
 *
 * The card filters and sorts in the browser, so it does need the whole table —
 * but it no longer arrives as one oversized message. Only the first response
 * may carry `refresh`: the following pages have to read the same snapshot,
 * and refreshing again in between would shift the rows underneath them.
 */
export const fetchAllDecisions = async (
  hass: HomeAssistant,
  configEntryId: string,
  refresh = false,
): Promise<DecisionsResponse> => {
  const first = await fetchDecisions(hass, configEntryId, refresh);
  const decisions = [...first.decisions];

  while (decisions.length < first.total && first.decisions.length > 0) {
    const next = await fetchDecisions(
      hass,
      configEntryId,
      false,
      decisions.length,
    );
    if (!next.decisions.length) break;
    decisions.push(...next.decisions);
  }

  return { ...first, decisions };
};

export interface DeleteResult {
  deleted: number;
  decisions: Decision[];
  total: number;
}

/** Remove a single decision — everything else for that address stays. */
export const deleteDecision = (
  hass: HomeAssistant,
  configEntryId: string,
  decisionId: number,
): Promise<DeleteResult> =>
  hass.connection.sendMessagePromise<DeleteResult>({
    type: `${DOMAIN}/decisions/delete`,
    config_entry_id: configEntryId,
    decision_id: decisionId,
  });

/** Remove every decision of an address at once. */
export const deleteForIp = (
  hass: HomeAssistant,
  configEntryId: string,
  ip: string,
): Promise<DeleteResult> =>
  hass.connection.sendMessagePromise<DeleteResult>({
    type: `${DOMAIN}/decisions/delete`,
    config_entry_id: configEntryId,
    ip,
  });
