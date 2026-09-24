import { describe, it, expect } from "vitest";
import { matchSourceUser, principalKey } from "../../src/lib/groups.js";

describe("principalKey", () => {
  it.each([
    ["CN=APP-Marketing-Team,DC=contoso,DC=onmicrosoft,DC=com", "app-marketing-team"],
    ["cn=app-marketing-team,ou=groups,dc=emea,dc=corp", "app-marketing-team"],
    ["emea\\APP-Marketing-Team", "app-marketing-team"],
    ["APP-Marketing-Team", "app-marketing-team"],
  ])("%s -> %s", (input, key) => {
    expect(principalKey(input)).toBe(key);
  });
});

describe("matchSourceUser", () => {
  const membership = {
    identities: ["corp\\u123456", "jane.doe@corp.com"],
    groups: ["CN=GRP-Upload-Allowed,OU=G,DC=emea,DC=corp", "APP-Marketing-Team"],
  };

  it("treats any as unrestricted", () => {
    expect(matchSourceUser(["any"], membership)).toEqual({ unrestricted: true, matchedBy: [] });
  });

  it("matches the user identity whatever the case", () => {
    expect(matchSourceUser(["JANE.DOE@corp.com"], membership).matchedBy).toEqual(["JANE.DOE@corp.com"]);
    expect(matchSourceUser(["CORP\\U123456"], membership).matchedBy).toEqual(["CORP\\U123456"]);
  });

  it("matches groups across DN formats", () => {
    const r = matchSourceUser(
      ["CN=APP-Marketing-Team,DC=contoso,DC=onmicrosoft,DC=com", "emea\\grp-upload-allowed", "other@corp.com"],
      membership
    );
    expect(r.matchedBy).toEqual(["CN=APP-Marketing-Team,DC=contoso,DC=onmicrosoft,DC=com", "emea\\grp-upload-allowed"]);
  });

  it("reports no match for other users and groups", () => {
    expect(matchSourceUser(["bob@corp.com", "CN=GRP-Finance,DC=corp"], membership)).toEqual({ unrestricted: false, matchedBy: [] });
  });
});
