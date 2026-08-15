import { describe, expect, it } from "vitest";

import {
  applyFilters,
  countDecisions,
  distinctValues,
  emptyFilter,
  matchesSearch,
  sortDecisions,
} from "../src/filters";
import { formatRemaining, shortScenario } from "../src/format";
import type { Decision } from "../src/types";

const decision = (overrides: Partial<Decision> = {}): Decision => ({
  key: "id:1",
  id: 1,
  origin: "crowdsec",
  origin_kind: "local",
  type: "ban",
  scope: "Ip",
  value: "192.0.2.1",
  scenario: "crowdsecurity/ssh-bf",
  duration: "3h",
  until: "2026-08-15T15:00:00Z",
  created_at: "2026-08-15T12:00:00Z",
  country: "DE",
  as_name: "Example AS",
  as_number: "AS64500",
  seconds_left: 10800,
  status: "active",
  simulated: false,
  deletable: true,
  alerts_24h: 3,
  ...overrides,
});

describe("search", () => {
  it("looks through every field that identifies a row", () => {
    const row = decision();
    expect(matchesSearch(row, "192.0.2")).toBe(true);
    expect(matchesSearch(row, "ssh")).toBe(true);
    expect(matchesSearch(row, "example")).toBe(true);
    expect(matchesSearch(row, "AS64500")).toBe(true);
    expect(matchesSearch(row, "198.51")).toBe(false);
  });

  it("lets several words match in different fields", () => {
    // "de ssh" should find the German SSH bruteforcers.
    expect(matchesSearch(decision(), "de ssh")).toBe(true);
    expect(matchesSearch(decision(), "fr ssh")).toBe(false);
  });

  it("treats an empty query as no filter at all", () => {
    expect(matchesSearch(decision(), "   ")).toBe(true);
  });
});

describe("filters", () => {
  const rows = [
    decision({ key: "a" }),
    decision({ key: "b", status: "expired", seconds_left: -60, deletable: false }),
    decision({ key: "c", origin: "CAPI", origin_kind: "capi", deletable: false }),
    decision({ key: "d", type: "captcha" }),
  ];

  it("opens on the active, local decisions", () => {
    // The CAPI and the blocklists contribute thousands of rows nobody can act
    // on — they are one chip away, not the first thing on screen.
    const result = applyFilters(rows, emptyFilter());
    expect(result.map((row) => row.key)).toEqual(["a", "d"]);
  });

  it("filters by origin", () => {
    const result = applyFilters(rows, {
      ...emptyFilter(),
      status: "all",
      origins: ["capi"],
    });
    expect(result.map((row) => row.key)).toEqual(["c"]);
  });

  it("filters by type", () => {
    const result = applyFilters(rows, { ...emptyFilter(), types: ["captcha"] });
    expect(result.map((row) => row.key)).toEqual(["d"]);
  });

  it("shows everything once all chips are on", () => {
    const result = applyFilters(rows, {
      ...emptyFilter(),
      status: "all",
      origins: ["local", "capi", "lists"],
    });
    expect(result.map((row) => row.key)).toEqual(["a", "b", "c", "d"]);
  });

  it("can narrow down to what the card may actually unban", () => {
    const result = applyFilters(rows, {
      ...emptyFilter(),
      status: "all",
      deletableOnly: true,
    });
    expect(result.map((row) => row.key)).toEqual(["a", "d"]);
  });

  it("collects the distinct values for the chips", () => {
    expect(distinctValues(rows, "type")).toEqual(["ban", "captcha"]);
  });
});

describe("sorting", () => {
  it("orders IPv4 numerically, not as text", () => {
    const rows = [
      decision({ key: "a", value: "192.0.2.10" }),
      decision({ key: "b", value: "192.0.2.9" }),
      decision({ key: "c", value: "192.0.2.100" }),
    ];
    const sorted = sortDecisions(rows, "value", false);
    expect(sorted.map((row) => row.value)).toEqual([
      "192.0.2.9",
      "192.0.2.10",
      "192.0.2.100",
    ]);
  });

  it("puts rows without a remaining time last in either direction", () => {
    const rows = [
      decision({ key: "a", seconds_left: null }),
      decision({ key: "b", seconds_left: 100 }),
      decision({ key: "c", seconds_left: 500 }),
    ];
    expect(sortDecisions(rows, "seconds_left", false).map((r) => r.key)).toEqual([
      "b",
      "c",
      "a",
    ]);
    expect(sortDecisions(rows, "seconds_left", true).map((r) => r.key)).toEqual([
      "c",
      "b",
      "a",
    ]);
  });

  it("leaves the input list alone", () => {
    const rows = [decision({ key: "a" }), decision({ key: "b", value: "1.1.1.1" })];
    sortDecisions(rows, "value", false);
    expect(rows.map((row) => row.key)).toEqual(["a", "b"]);
  });
});

describe("counts", () => {
  it("counts over the unfiltered list", () => {
    const counts = countDecisions([
      decision(),
      decision({ status: "expired" }),
      decision({ origin_kind: "capi" }),
    ]);
    expect(counts).toEqual({
      total: 3,
      active: 2,
      expired: 1,
      local: 2,
      capi: 1,
      lists: 0,
    });
  });
});

describe("formatting", () => {
  it("shows at most the two largest units", () => {
    expect(formatRemaining(6 * 86400 + 3 * 3600)).toBe("6 d 3 h");
    expect(formatRemaining(3 * 3600 + 12 * 60)).toBe("3 h 12 m");
    expect(formatRemaining(90)).toBe("1 m");
    expect(formatRemaining(-5)).toBe("expired");
    expect(formatRemaining(null)).toBe("—");
  });

  it("drops the namespace of a scenario but keeps manual bans readable", () => {
    expect(shortScenario("crowdsecurity/ssh-bf")).toBe("ssh-bf");
    expect(shortScenario("manual 'Home Assistant' from 'hass'")).toBe(
      "manual: Home Assistant",
    );
  });
});
