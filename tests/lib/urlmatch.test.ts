import { describe, it, expect } from "vitest";
import { baseDomain, matchEntries, matchEntry, normalizeUrl } from "../../src/lib/urlmatch.js";

describe("normalizeUrl", () => {
  it.each([
    ["https://WWW.Example.com/Path?q=1#x", "www.example.com/Path"],
    ["http://user@host.example.com:8443/a", "host.example.com/a"],
    ["example.com.", "example.com"],
    ["example.com", "example.com"],
  ])("%s -> %s", (input, expected) => {
    expect(normalizeUrl(input)).toBe(expected);
  });
});

describe("matchEntry", () => {
  it.each([
    ["https://www.example.com/login", "www.example.com"],
    ["https://www.example.com/login", "www.example.com/"],
    ["https://www.example.com/login", "*.example.com"],
    ["https://www.example.com/login", "*.example.com/"],
    ["https://www.example.com/login", "www.example.com/login"],
    ["https://a.b.example.com", "*.*.example.com"],
    ["https://www.example.com", "^.example.com"],
    // Without a trailing slash PAN-OS also matches longer hostnames.
    ["https://example.com.evil.net", "example.com"],
  ])("%s matches %s", (url, entry) => {
    expect(matchEntry(url, entry)?.kind).toBe("match");
  });

  it.each([
    ["https://www.example.com", "example.com/"],
    ["https://example.com", "*.example.com"],
    ["https://www.example.com/other", "www.example.com/login"],
    ["https://a.b.example.com", "*.example.com/"],
  ])("%s is only related to %s", (url, entry) => {
    expect(matchEntry(url, entry)?.kind).toBe("related");
  });

  it("does not match unrelated domains or partial tokens", () => {
    expect(matchEntry("https://www.example.com", "other.com")).toBeNull();
    expect(matchEntry("https://www.examples.com", "www.example")).toBeNull();
  });
});

describe("matchEntries", () => {
  it("returns matches before related entries", () => {
    const result = matchEntries("https://files.xyz.com/upload", ["xyz.com/", "*.xyz.com/", "abc.com"]);
    expect(result).toEqual([
      { entry: "*.xyz.com/", kind: "match" },
      { entry: "xyz.com/", kind: "related" },
    ]);
  });
});

describe("baseDomain", () => {
  it.each([
    ["a.b.example.com", "example.com"],
    ["www.example.co.uk", "example.co.uk"],
    ["example.com", "example.com"],
    ["x.service.gouv.fr", "service.gouv.fr"],
  ])("%s -> %s", (host, expected) => {
    expect(baseDomain(host)).toBe(expected);
  });
});
