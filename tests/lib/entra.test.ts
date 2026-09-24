import { describe, it, expect } from "vitest";
import { assertEntraId, parseMemberGroups } from "../../src/api/entra.js";

describe("assertEntraId", () => {
  it.each(["jdoe-external@corp.com", "Jane.Doe@corp.co.uk", "0f8fad5b-d9cb-469f-a165-70867728950e"])("accepts %s", (id) => {
    expect(assertEntraId(id)).toBe(id);
  });
  it.each(["jdoe", "a@b.com & calc", "a@b.com\" --x", "x@y.com'", "$(whoami)@corp.com", "a@b.com;ls"])("rejects %s", (id) => {
    expect(() => assertEntraId(id)).toThrow();
  });
});

describe("parseMemberGroups", () => {
  it("reads displayName whatever its case", () => {
    expect(parseMemberGroups('[{"displayName":"APP-Marketing-Team","id":"1"},{"DisplayName":"GRP-B","id":"2"}]')).toEqual([
      "APP-Marketing-Team",
      "GRP-B",
    ]);
  });
  it("handles empty output", () => {
    expect(parseMemberGroups("")).toEqual([]);
  });
});
