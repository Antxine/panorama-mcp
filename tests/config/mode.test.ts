import { describe, it, expect } from "vitest";
import { isReadOnlyMode, selectedModules, PANORAMA_DEBUG_PRESET } from "../../src/config/mode.js";

describe("isReadOnlyMode", () => {
  it("defaults to read-only", () => {
    expect(isReadOnlyMode({})).toBe(true);
  });
  it.each(["false", "0", "no", "OFF"])("%s disables read-only", (v) => {
    expect(isReadOnlyMode({ PANOS_READ_ONLY: v })).toBe(false);
  });
});

describe("selectedModules", () => {
  const all = ["firewalls", "panorama", "utility", "debug", "urlcategories", "diagnose", "directory", "nat"];
  it("defaults to the panorama-debug preset", () => {
    expect(selectedModules(all, {})).toEqual(PANORAMA_DEBUG_PRESET);
  });
  it("loads everything with 'all'", () => {
    expect(selectedModules(all, { PANOS_MODULES: "all" })).toEqual(all);
  });
  it("expands the panorama-debug preset", () => {
    expect(selectedModules(all, { PANOS_MODULES: "panorama-debug" })).toEqual(PANORAMA_DEBUG_PRESET);
  });
  it("rejects unknown modules", () => {
    expect(() => selectedModules(all, { PANOS_MODULES: "debug,foo" })).toThrow(/foo/);
  });
});
