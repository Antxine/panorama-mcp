import { describe, it, expect } from "vitest";
import { buildUserFilter, cnOf, domainFromDn, escapeLdap, logIdentities } from "../../src/lib/ldap.js";

describe("escapeLdap", () => {
  it("escapes filter metacharacters", () => {
    expect(escapeLdap("a*b(c)d\\e")).toBe("a\\2ab\\28c\\29d\\5ce");
  });
});

describe("buildUserFilter", () => {
  it("searches mail, UPN and proxy addresses for emails", () => {
    expect(buildUserFilter("jdoe-external@corp.com")).toBe(
      "(&(objectCategory=person)(objectClass=user)(|(mail=jdoe-external@corp.com)(userPrincipalName=jdoe-external@corp.com)(proxyAddresses=smtp:jdoe-external@corp.com)))"
    );
  });
  it("uses the account part of DOMAIN\\id", () => {
    expect(buildUserFilter("corp\\u123456")).toContain("(sAMAccountName=u123456)");
  });
  it("matches display names in both orders", () => {
    const f = buildUserFilter("Jane DOE");
    expect(f).toContain("(displayName=*Jane DOE*)");
    expect(f).toContain("(&(givenName=Jane*)(sn=DOE*))");
    expect(f).toContain("(&(givenName=DOE*)(sn=Jane*))");
  });
  it("cannot be broken out of with filter syntax", () => {
    const f = buildUserFilter("x)(|(objectClass=*)");
    expect(f).not.toContain("x)(|");
    expect(f).toContain("x\\29\\28|\\28objectClass=\\2a\\29");
  });
});

describe("identities", () => {
  const user = {
    sam: "U123456",
    upn: "Jane.Doe@corp.com",
    mail: "jane.doe@corp.com",
    displayName: "Jane Doe",
    dn: "CN=Jane Doe,OU=Users,DC=emea,DC=corp,DC=local",
    disabled: false,
    groups: [],
    groupDns: [],
  };
  it("derives the identities seen in PAN-OS logs", () => {
    expect(logIdentities(user)).toEqual(["emea\\u123456", "jane.doe@corp.com"]);
  });
  it("parses DNs", () => {
    expect(domainFromDn(user.dn)).toBe("emea");
    expect(cnOf("CN=ACC\\, Comms,OU=G,DC=corp")).toBe("ACC, Comms");
  });
});

describe("AD PowerShell script", async () => {
  const { AD_SCRIPT } = await import("../../src/api/ad.js");
  it("escapes the user DN for the nested-group filter with single backslashes", () => {
    expect(AD_SCRIPT).toContain("-replace '\\\\', '\\5c' -replace '\\*', '\\2a' -replace '\\(', '\\28' -replace '\\)', '\\29'");
  });
  it("reads the filter from the environment, never from interpolated input", () => {
    expect(AD_SCRIPT).toContain("$s.Filter = $env:PANOS_MCP_LDAP_FILTER");
  });
});
