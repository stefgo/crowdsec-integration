import { describe, expect, it } from "vitest";

import { EN, TRANSLATIONS, cardLanguage, createLocalizer } from "../src/localize";
import { formatRemaining, originLabel, shortScenario } from "../src/format";
import type { HomeAssistant } from "../src/types";

const hass = (language?: string): HomeAssistant =>
  ({ locale: { language } }) as HomeAssistant;

describe("languages", () => {
  it("keeps every language on the same set of keys", () => {
    // The counterpart of the integrity test on the Python side: a key that
    // exists only in one language is a gap nobody notices in the UI.
    const expected = Object.keys(EN).sort();
    for (const [language, table] of Object.entries(TRANSLATIONS)) {
      expect(Object.keys(table).sort(), `${language} differs`).toEqual(expected);
    }
  });

  it("keeps the placeholders of a text intact", () => {
    const placeholders = (text: string) =>
      (text.match(/\{\w+\}/g) ?? []).sort();
    for (const [language, table] of Object.entries(TRANSLATIONS)) {
      for (const [key, text] of Object.entries(table)) {
        expect(
          placeholders(text as string),
          `${language}.${key} has different placeholders`,
        ).toEqual(placeholders(EN[key as keyof typeof EN]));
      }
    }
  });

  it("maps a regional language onto its base table", () => {
    expect(cardLanguage(hass("de-DE"))).toBe("de");
    expect(cardLanguage(hass("de"))).toBe("de");
  });

  it("falls back to English for anything it does not have", () => {
    expect(cardLanguage(hass("fr"))).toBe("en");
    expect(cardLanguage(undefined)).toBe("en");
  });
});

describe("localizer", () => {
  it("translates into the language of the user", () => {
    expect(createLocalizer(hass("de"))("action.unban")).toBe("Entsperren");
    expect(createLocalizer(hass("en"))("action.unban")).toBe("Unban");
  });

  it("substitutes placeholders", () => {
    const t = createLocalizer(hass("de"));
    expect(t("card.counts", { active: 3, expired: 1, local: 2 })).toBe(
      "3 aktiv · 1 abgelaufen · 2 lokal",
    );
  });

  it("leaves an unknown placeholder alone instead of blanking it", () => {
    const t = createLocalizer(hass("en"));
    expect(t("action.unban_all", {})).toContain("{ip}");
  });
});

describe("formatting follows the language", () => {
  const de = createLocalizer(hass("de"));

  it("uses the localized units and words", () => {
    expect(formatRemaining(3 * 3600 + 12 * 60, de)).toBe("3 Std 12 Min");
    expect(formatRemaining(-5, de)).toBe("abgelaufen");
    expect(shortScenario("manual 'Test' from 'hass'", de)).toBe("manuell: Test");
    expect(originLabel("cscli", de)).toBe("manuell");
    // CAPI is a proper name and stays as it is in every language.
    expect(originLabel("CAPI", de)).toBe("CAPI");
  });

  it("still speaks English without a localizer", () => {
    expect(formatRemaining(90)).toBe("1 m");
    expect(originLabel("lists")).toBe("blocklist");
  });
});
