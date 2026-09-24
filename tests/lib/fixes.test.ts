import { describe, it, expect } from "vitest";
import { suggestAppFixes, suggestUrlFixes } from "../../src/lib/fixes.js";
import type { RuleSummary } from "../../src/api/policy.js";

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
    sourceUser: ["any"],
    application: [],
    service: ["application-default"],
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

const membership = { identities: ["jane@corp.com"], groups: ["CN=GRP-Comms,OU=G,DC=corp"] };
const blocking = rule({ name: "GenAI - Block", action: "deny", position: 1059, application: ["ORG_GenAI_Apps"] });

describe("suggestAppFixes", () => {
  const rules = [
    rule({ name: "Comms apps", position: 950, sourceUser: ["CN=GRP-Comms,DC=tenant,DC=onmicrosoft,DC=com"], application: ["adobe-express", "canva"] }),
    rule({ name: "Comms misc", position: 951, sourceUser: ["corp\\grp-comms"], application: ["box"] }),
    rule({ name: "Podcast for Bob", position: 960, sourceUser: ["bob@corp.com"], application: ["adobe-podcast"] }),
    rule({ name: "After block", position: 1100, sourceUser: ["corp\\grp-comms"], application: ["adobe-express"] }),
    blocking,
  ];

  it("suggests extending the rule the user's group already has, for the same app family first", () => {
    const options = suggestAppFixes("adobe-podcast", { rules, locations: ["shared", "DG-URL"], blocking, membership, userLabel: "Jane" });
    expect(options[0]).toMatchObject({ confidence: "high", change: "Add App-ID 'adobe-podcast' to rule 'Comms apps'" });
    expect(options[0].impact).toContain("Every identity matched by");
    expect(options.map((o) => o.rule)).toContain("Podcast for Bob");
    expect(options.map((o) => o.rule)).not.toContain("After block");
    expect(options.find((o) => o.rule === "Comms misc")?.confidence).toBe("low");
    expect(options.at(-1)?.change).toContain("Create a dedicated exception");
  });

  it("without AD membership only proposes a new exception", () => {
    const options = suggestAppFixes("adobe-podcast", { rules, locations: ["DG-URL"], blocking, userLabel: "Jane" });
    expect(options).toHaveLength(1);
  });
});

describe("suggestUrlFixes", () => {
  it("proposes joining the rule that already allows a covering category", () => {
    const rules = [
      rule({ name: "Yumpu for team X", position: 40, sourceUser: ["corp\\grp-x"], category: ["SOC - yumpu"] }),
      rule({ name: "Comms sites", position: 41, sourceUser: ["corp\\grp-comms"], category: ["CC - Communication dept"] }),
    ];
    const options = suggestUrlFixes("www.yumpu.com", ["SOC - yumpu"], { rules, locations: ["DG-URL"], membership, userLabel: "Jane" });
    expect(options[0]).toMatchObject({ confidence: "high", rule: "Yumpu for team X" });
    expect(options[1]).toMatchObject({ confidence: "medium", change: "Add 'www.yumpu.com' to custom category 'CC - Communication dept' used by rule 'Comms sites'" });
  });
});
