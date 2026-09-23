import { describe, it, expect } from "vitest";
import { classifyLogEntry, isBlockingAction } from "../../src/lib/classify.js";

describe("classifyLogEntry traffic", () => {
  it("detects the default deny", () => {
    const c = classifyLogEntry("traffic", { action: "deny", rule: "interzone-default", session_end_reason: "policy-deny" });
    expect(c).toMatchObject({ blocked: true, layer: "default-rule" });
  });

  it("detects an explicit deny rule", () => {
    const c = classifyLogEntry("traffic", { action: "reset-both", rule: "block-social", app: "facebook-base" });
    expect(c).toMatchObject({ blocked: true, layer: "security-policy" });
    expect(c.summary).toContain("block-social");
  });

  it("points to threat logs when a profile ended the session", () => {
    const c = classifyLogEntry("traffic", { action: "allow", rule: "web", session_end_reason: "threat" });
    expect(c.blocked).toBe(true);
    expect(c.next_steps[0]).toContain("threat");
  });

  it("recognizes network issues, not policy", () => {
    expect(classifyLogEntry("traffic", { action: "allow", app: "incomplete" }).layer).toBe("network");
    expect(
      classifyLogEntry("traffic", { action: "allow", app: "ssl", proto: "tcp", session_end_reason: "aged-out", bytes_received: "0" }).layer
    ).toBe("network");
  });

  it("recognizes decryption failures", () => {
    expect(classifyLogEntry("traffic", { action: "allow", session_end_reason: "decrypt-cert-validation" }).layer).toBe("decryption");
  });
});

describe("classifyLogEntry threat", () => {
  it.each([
    [{ subtype: "file", action: "deny", direction: "client-to-server" }, "file-blocking"],
    [{ subtype: "virus", action: "reset-both" }, "antivirus"],
    [{ subtype: "wildfire-virus", action: "reset-both" }, "wildfire"],
    [{ subtype: "vulnerability", action: "reset-server" }, "vulnerability"],
    [{ subtype: "spyware", action: "sinkhole", threatid: "generic:evil.example(109001001)" }, "dns-security"],
    [{ subtype: "spyware", action: "drop", threatid: "Cobalt Strike(86246)" }, "anti-spyware"],
    [{ subtype: "url", action: "block-url" }, "url-filtering"],
    [{ subtype: "packet", action: "drop" }, "zone-protection"],
  ])("%j -> %s", (entry, layer) => {
    const c = classifyLogEntry("threat", entry);
    expect(c.layer).toBe(layer);
    expect(c.blocked).toBe(true);
  });

  it("alerts are not blocks", () => {
    expect(classifyLogEntry("threat", { subtype: "vulnerability", action: "alert" }).blocked).toBe(false);
  });

  it("wildfire submission logs are not blocks", () => {
    expect(classifyLogEntry("wildfire", { category: "malware", action: "allow" })).toMatchObject({ blocked: false, layer: "wildfire" });
  });
});

describe("isBlockingAction", () => {
  it.each([
    ["traffic", "deny", true],
    ["traffic", "allow", false],
    ["url", "block-continue", true],
    ["url", "alert", false],
    ["threat", "sinkhole", true],
    ["threat", "alert", false],
  ] as const)("%s %s -> %s", (type, action, expected) => {
    expect(isBlockingAction(type, action)).toBe(expected);
  });
});
