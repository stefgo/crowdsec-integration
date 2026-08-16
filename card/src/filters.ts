/**
 * Search, filter and sort — the part of the card that has no DOM in it.
 *
 * Everything happens on the client: the whole table already arrives with one
 * WebSocket call, so a keystroke must not cost a round trip.
 */

import type { Decision, DecisionStatus, SortColumn } from "./types";

export interface FilterState {
  search: string;
  status: DecisionStatus | "all";
  types: string[];
  scopes: string[];
  /** Only rows the card could actually unban. */
  deletableOnly: boolean;
}

/**
 * What the card opens with: what is being enforced right now, and only the
 * decisions this Home Assistant owns. The CAPI and the blocklists contribute
 * thousands of rows that can neither be acted on nor read usefully — they are
 * one chip away when someone wants them.
 */
export const emptyFilter = (): FilterState => ({
  search: "",
  status: "active",
  types: [],
  scopes: [],
  deletableOnly: false,
});

/**
 * Free text over everything that identifies a row.
 *
 * Several words all have to match, but may sit in different fields — that is
 * how "de ssh" finds the German SSH bruteforcers.
 */
export function matchesSearch(decision: Decision, query: string): boolean {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return true;

  const haystack = [
    decision.value,
    decision.scenario,
    decision.country,
    decision.as_name,
    decision.as_number,
    decision.origin,
    decision.type,
    decision.scope,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return terms.every((term) => haystack.includes(term));
}

export function applyFilters(
  decisions: Decision[],
  state: FilterState,
): Decision[] {
  return decisions.filter((decision) => {
    if (state.status !== "all" && decision.status !== state.status) return false;
    if (state.deletableOnly && !decision.deletable) return false;
    if (state.types.length && !state.types.includes(decision.type ?? "")) {
      return false;
    }
    if (state.scopes.length && !state.scopes.includes(decision.scope ?? "")) {
      return false;
    }
    return matchesSearch(decision, state.search);
  });
}

/** The distinct values of a field, for the filter chips. */
export function distinctValues(
  decisions: Decision[],
  field: "type" | "scope",
): string[] {
  const values = new Set<string>();
  for (const decision of decisions) {
    const value = decision[field];
    if (value) values.add(value);
  }
  return [...values].sort();
}

/** Numeric sort for IPv4 so that .10 lands after .9, not between .1 and .2. */
function ipKey(value: string | null): string {
  if (!value) return "";
  const [address] = value.split("/");
  const parts = address.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) {
    return value;
  }
  return parts.map((part) => part.padStart(3, "0")).join(".");
}

export function sortDecisions(
  decisions: Decision[],
  column: SortColumn,
  descending: boolean,
): Decision[] {
  const direction = descending ? -1 : 1;

  const compare = (a: Decision, b: Decision): number => {
    if (column === "seconds_left") {
      // Rows without a remaining time go last in either direction — they say
      // nothing about the ordering and should not push the real values around.
      const left = a.seconds_left;
      const right = b.seconds_left;
      if (left === null && right === null) return 0;
      if (left === null) return 1;
      if (right === null) return -1;
      return (left - right) * direction;
    }

    const left = column === "value" ? ipKey(a.value) : (a[column] ?? "");
    const right = column === "value" ? ipKey(b.value) : (b[column] ?? "");
    return String(left).localeCompare(String(right)) * direction;
  };

  // A copy: the caller keeps the unsorted list to filter against.
  return [...decisions].sort(compare);
}

export interface Counts {
  total: number;
  active: number;
  expired: number;
}

/** The numbers for the header line — always over the unfiltered list. */
export function countDecisions(decisions: Decision[]): Counts {
  const counts: Counts = {
    total: decisions.length,
    active: 0,
    expired: 0,
  };
  for (const decision of decisions) {
    counts[decision.status] += 1;
  }
  return counts;
}
