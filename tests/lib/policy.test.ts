import { describe, it, expect } from "vitest";
import { exceptionPattern, findExceptionRules, type RuleSummary } from "../../src/api/policy.js";

function rule(partial: Partial<RuleSummary>): RuleSummary {
  return {
    location: "DG-URL",
    rulebase: "pre",
    policy: "security",
    position: 1,
    name: "r",
    disabled: false,
    action: "allow",
    from: [],
    to: [],
    source: [],
    destination: [],
    sourceUser: [],
    application: [],
    service: [],
    category: [],
    negateSource: false,
    negateDestination: false,
    targetDevices: [],
    targetNegate: false,
    profiles: {},
    logEnd: true,
    sourceHip: [],
    destinationHip: [],
    tags: [],
    ...partial,
  };
}

describe("findExceptionRules", () => {
  const blocking = rule({ name: "GenAI - Block", action: "deny", position: 1059, application: ["ORG_GenAI_Apps"] });
  const rules = [
    rule({ name: "EXC - User1 - AI", position: 830, sourceUser: ["bpo@corp.com"], application: ["adobe-firefly"], profileGroup: "PG-Upload-Allowed", schedule: "END-31-10-2026" }),
    rule({ name: "EXC - User2 - Adobe", position: 835, sourceUser: ["mpa@corp.com"], application: ["adobe-express"], profileGroup: "PG-Upload-Allowed" }),
    rule({ name: "After block", position: 1100, sourceUser: ["x@corp.com"], application: ["adobe-express"] }),
    rule({ name: "Any user", position: 10, sourceUser: ["any"], application: ["adobe-express"] }),
    rule({ name: "Other location", location: "DG-OTHER", position: 5, sourceUser: ["y@corp.com"], application: ["adobe-cloud"] }),
    rule({ name: "Unrelated", position: 20, sourceUser: ["z@corp.com"], application: ["box"] }),
  ];

  it("returns per-user allow rules of the same app family, before the blocking rule first", () => {
    const found = findExceptionRules(rules, { apps: ["adobe-podcast"] }, blocking).map((r) => r.name);
    expect(found).toEqual(["EXC - User1 - AI", "EXC - User2 - Adobe", "Other location", "After block"]);
  });

  it("matches on categories too", () => {
    const withCat = [rule({ name: "Yumpu for A", sourceUser: ["a@corp.com"], category: ["SOC - yumpu"] })];
    expect(findExceptionRules(withCat, { categories: ["SOC - yumpu"] })).toHaveLength(1);
  });

  it("describes the shared pattern", () => {
    const pattern = exceptionPattern(findExceptionRules(rules, { apps: ["adobe-podcast"] }, blocking).slice(0, 2));
    expect(pattern).toContain("DG-URL/pre");
    expect(pattern).toContain("'PG-Upload-Allowed'");
    expect(pattern).toContain("1/2 have an expiry schedule");
  });
});
