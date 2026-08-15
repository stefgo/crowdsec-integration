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

export const fetchDecisions = (
  hass: HomeAssistant,
  configEntryId: string,
  refresh = false,
): Promise<DecisionsResponse> =>
  hass.connection.sendMessagePromise<DecisionsResponse>({
    type: `${DOMAIN}/decisions/list`,
    config_entry_id: configEntryId,
    refresh,
  });

export interface DeleteResult {
  deleted: number;
  decisions: Decision[];
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
