import { describe, it, expect } from "vitest";
import { ipInEntry } from "../../src/lib/ip.js";

describe("ipInEntry", () => {
  it.each([
    ["10.1.2.3", "10.1.2.3", true],
    ["10.1.2.3", "10.0.0.0/8", true],
    ["11.1.2.3", "10.0.0.0/8", false],
    ["10.1.2.3", "10.1.2.0-10.1.2.10", true],
    ["10.1.2.11", "10.1.2.0-10.1.2.10", false],
    ["10.1.2.3", "10.1.2.3/32", true],
    ["2001:db8::1", "2001:DB8::1", true],
    ["10.1.2.3", "garbage", false],
  ])("%s in %s -> %s", (ip, entry, expected) => {
    expect(ipInEntry(ip, entry)).toBe(expected);
  });
});
