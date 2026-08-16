import { describe, expect, it } from "vitest";

import { PAGE_SIZE, banIp, fetchAllDecisions, lookupIp } from "../src/api";
import type { Decision, DecisionsResponse, HomeAssistant } from "../src/types";

const decision = (index: number): Decision =>
  ({
    key: `id:${index}`,
    id: index,
    value: `192.0.2.${index % 255}`,
    status: "active",
    origin_kind: "local",
    deletable: true,
  }) as Decision;

/** A hass stub that answers the list command out of a fixed set of rows. */
const fakeHass = (total: number, sent: Record<string, unknown>[] = []) =>
  ({
    connection: {
      sendMessagePromise: async <T,>(message: Record<string, unknown>) => {
        sent.push(message);
        const offset = (message.offset as number) ?? 0;
        const limit = (message.limit as number) ?? PAGE_SIZE;
        const rows = Array.from({ length: total }, (_, i) => decision(i));
        return {
          decisions: rows.slice(offset, offset + limit),
          total,
          offset,
          available: true,
          reachable: true,
          alerts_truncated: false,
          decisions_truncated: false,
          local_only: true,
          last_update: null,
        } as DecisionsResponse as T;
      },
    },
  }) as HomeAssistant;

describe("fetchAllDecisions", () => {
  it("returns everything in one go when it fits into a page", async () => {
    const sent: Record<string, unknown>[] = [];
    const result = await fetchAllDecisions(fakeHass(10, sent), "entry");

    expect(result.decisions).toHaveLength(10);
    expect(sent).toHaveLength(1);
  });

  it("fetches further pages until the table is complete", async () => {
    const sent: Record<string, unknown>[] = [];
    const result = await fetchAllDecisions(fakeHass(1200, sent), "entry");

    expect(result.decisions).toHaveLength(1200);
    expect(result.decisions[1199].id).toBe(1199);
    expect(sent.map((message) => message.offset)).toEqual([0, 500, 1000]);
  });

  it("only asks for a refresh once", async () => {
    // The following pages have to read the same snapshot — refreshing again
    // in between would shift the rows underneath them.
    const sent: Record<string, unknown>[] = [];
    await fetchAllDecisions(fakeHass(1200, sent), "entry", true);

    expect(sent.map((message) => message.refresh)).toEqual([true, false, false]);
  });

  it("stops instead of looping when a page comes back empty", async () => {
    // A total that never gets reached — a lying server must not hang the card.
    const hass = {
      connection: {
        sendMessagePromise: async <T,>() =>
          ({
            decisions: [],
            total: 999,
            offset: 0,
            available: true,
            reachable: true,
            alerts_truncated: false,
            decisions_truncated: false,
            local_only: false,
            last_update: null,
          }) as DecisionsResponse as T,
      },
    } as HomeAssistant;

    const result = await fetchAllDecisions(hass, "entry");
    expect(result.decisions).toHaveLength(0);
  });
});

describe("lookup and ban", () => {
  const capture = () => {
    const sent: Record<string, unknown>[] = [];
    const hass = {
      connection: {
        sendMessagePromise: async <T,>(message: Record<string, unknown>) => {
          sent.push(message);
          return { target: message.ip, blocked: false } as unknown as T;
        },
      },
    } as HomeAssistant;
    return { hass, sent };
  };

  it("asks the lookup command for one address", async () => {
    const { hass, sent } = capture();
    await lookupIp(hass, "entry", "192.0.2.10");

    expect(sent[0]).toEqual({
      type: "crowdsec/ip/lookup",
      config_entry_id: "entry",
      ip: "192.0.2.10",
    });
  });

  it("sends duration and reason with a ban", async () => {
    const { hass, sent } = capture();
    await banIp(hass, "entry", "192.0.2.10", "2h", "Because");

    expect(sent[0]).toEqual({
      type: "crowdsec/ip/ban",
      config_entry_id: "entry",
      ip: "192.0.2.10",
      duration: "2h",
      reason: "Because",
    });
  });
});
