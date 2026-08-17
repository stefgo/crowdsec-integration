/**
 * Values the build injects into the bundle.
 *
 * `CARD_VERSION` is defined by rollup's `output.intro` from the version in
 * package.json, so the number the card reports is the released one rather than
 * a constant somebody has to remember to bump.
 */
declare const CARD_VERSION: string;
