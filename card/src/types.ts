/** Types shared by the card, the API layer, the filters and the editor. */

export type OriginKind = "local" | "capi" | "lists";
export type DecisionStatus = "active" | "expired";

/** One row of the table, as the WebSocket command delivers it. */
export interface Decision {
  key: string;
  /** Only decisions the LAPI knows by ID can be removed one by one. */
  id: number | null;
  origin: string | null;
  origin_kind: OriginKind;
  type: string | null;
  scope: string | null;
  value: string | null;
  scenario: string | null;
  duration: string | null;
  until: string | null;
  created_at: string | null;
  country: string | null;
  as_name: string | null;
  as_number: string | null;
  seconds_left: number | null;
  status: DecisionStatus;
  simulated: boolean;
  deletable: boolean;
  alerts_24h: number;
}

export interface DecisionsResponse {
  decisions: Decision[];
  /** Rows in the whole table, not just in this page. */
  total: number;
  offset: number;
  /** False when the decision route itself could not be read. */
  available: boolean;
  reachable: boolean;
  alerts_truncated: boolean;
  /** The table hit the integration's row cap — there are more decisions. */
  decisions_truncated: boolean;
  last_update: string | null;
}

/** The answer of the lookup command — one address, every source. */
export interface IpReport {
  target: string;
  /** Everything currently in force for the address, whatever its origin. */
  decisions: Decision[];
  blocked: boolean;
  expires_at: string | null;
  seconds_left: number | null;
  /**
   * Set when a decision covers the address through a range rather than naming
   * it — the case the ban table structurally cannot show.
   */
  covering_ranges: string[];
  /** Whether anything found here can be lifted from Home Assistant. */
  deletable: boolean;
  alerts: number;
  first_seen: string | null;
  last_seen: string | null;
  scenarios: string[];
  country: string | null;
  as_name: string | null;
  /** False when the alert history could not be read; the decisions still can. */
  alerts_available: boolean;
  /** False when the decision route itself is closed — then "not blocked"
   *  would be a lie, and the card says so instead. */
  decisions_available?: boolean;
}

export interface CrowdSecIpLookupCardConfig {
  type: string;
  title?: string;
  /** Which instance to query. Omitted means the first configured one. */
  config_entry_id?: string;
  /** Prefilled ban duration in the ban row. */
  ban_duration?: string;
  /** Prefilled ban reason. */
  ban_reason?: string;
  /** Hide the ban controls — lookup only. */
  hide_ban?: boolean;
}

export interface Instance {
  config_entry_id: string;
  title: string;
  loaded: boolean;
}

export type SortColumn =
  | "value"
  | "type"
  | "scenario"
  | "country"
  | "as_name"
  | "origin"
  | "seconds_left";

export interface CrowdSecBansCardConfig {
  type: string;
  title?: string;
  /** Which instance to show. Omitted means the first configured one. */
  config_entry_id?: string;
  /** Status filter the card opens with. */
  status?: DecisionStatus | "all";
  /** Rows per page. */
  page_size?: number;
  /** Hide the search field and the filter chips — for a compact dashboard. */
  hide_filters?: boolean;
  /** Column the table is sorted by initially. */
  sort?: SortColumn;
  sort_desc?: boolean;
}

/** The slice of the hass object that the card uses. */
export interface HomeAssistant {
  locale?: { language?: string };
  language?: string;
  user?: { is_admin?: boolean };
  connection: {
    sendMessagePromise<T>(message: Record<string, unknown>): Promise<T>;
  };
}
