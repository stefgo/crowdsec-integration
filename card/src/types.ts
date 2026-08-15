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
  /** Only locally created decisions are fetched; CAPI and blocklists are out. */
  local_only: boolean;
  last_update: string | null;
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
  /** Origins active initially; all three if omitted. */
  origins?: OriginKind[];
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
