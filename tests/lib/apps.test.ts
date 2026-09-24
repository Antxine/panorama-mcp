import { describe, it, expect } from "vitest";
import { containersOf, filterMatchesApp, type AppContainer } from "../../src/api/apps.js";
import { prismaDeviceGroup } from "../../src/api/device.js";
import { explainApiError } from "../../src/api/ops.js";
import { jsonResponse } from "../../src/api/panorama.js";

const podcast = { name: "adobe-podcast", category: "business-systems", subcategory: "generative-ai", technology: "browser-based", risk: "2", tags: ["Generative AI"] };

describe("filterMatchesApp", () => {
  it("ANDs dimensions and ORs values", () => {
    expect(filterMatchesApp({ subcategory: ["generative-ai"], risk: ["2", "3"] }, podcast)).toBe(true);
    expect(filterMatchesApp({ subcategory: ["generative-ai"], risk: ["5"] }, podcast)).toBe(false);
  });
  it("supports tags and exclusions", () => {
    expect(filterMatchesApp({ tags: ["Generative AI"] }, podcast)).toBe(true);
    expect(filterMatchesApp({ tags: ["Generative AI"], exclude: ["adobe-podcast"] }, podcast)).toBe(false);
  });
  it("an empty filter matches nothing", () => {
    expect(filterMatchesApp({}, podcast)).toBe(false);
  });
});

describe("containersOf", () => {
  it("follows groups containing filters containing the app", () => {
    const containers: AppContainer[] = [
      { kind: "application-filter", name: "AI-Filter", location: "shared", definition: { subcategory: ["generative-ai"] } },
      { kind: "application-group", name: "ORG_GenAI_Apps", location: "shared", definition: { members: ["AI-Filter", "chatgpt"] } },
      { kind: "application-group", name: "Unrelated", location: "shared", definition: { members: ["box"] } },
    ];
    expect(containersOf(podcast, containers).map((c) => c.name)).toEqual(["AI-Filter", "ORG_GenAI_Apps"]);
  });
});

describe("prismaDeviceGroup", () => {
  const groups = ["DG-Internet-Rules", "Mobile_User_Device_Group", "Remote_Network_Device_Group"];
  it.each([
    ["GP cloud service", "Mobile_User_Device_Group"],
    ["RN-Prisma-FRLKE", "Remote_Network_Device_Group"],
    ["fw-branch-01", undefined],
  ])("%s -> %s", (name, expected) => {
    expect(prismaDeviceGroup(name, groups)).toBe(expected);
  });
});

describe("explainApiError", () => {
  it("names the missing XML API permission", () => {
    expect(explainApiError("HTTP 403 API Error: Type [op] not authorized for user role.")).toContain("'Operational Requests'");
    expect(explainApiError("other")).toBe("other");
  });
});

describe("jsonResponse", () => {
  it("shrinks oversized arrays and says so", () => {
    const big = { entries: Array.from({ length: 2000 }, (_, i) => ({ i, pad: "x".repeat(50) })) };
    const text = jsonResponse(big).content[0].text;
    expect(text.length).toBeLessThan(42_000);
    expect(text).toContain("more omitted");
    expect(text).toContain("Output reduced");
  });
  it("leaves small payloads untouched", () => {
    expect(jsonResponse({ a: [1, 2] }).content[0].text).toBe('{"a":[1,2]}');
  });
});
