import { describe, it, expect } from "vitest";
import { buildLogQuery, entryMatches, trimLogEntry } from "../../src/lib/logquery.js";

describe("buildLogQuery", () => {
  it("builds server-side filters for traffic logs", () => {
    const { query, clientSide } = buildLogQuery("traffic", {
      src_ip: "10.1.2.3",
      user: "jdoe@corp.com",
      dst_port: 443,
      only_blocked: true,
      period: "last-hour",
    });
    expect(query).toBe(
      "( receive_time in last-hour ) and ( addr.src in 10.1.2.3 ) and ( user.src eq 'jdoe@corp.com' ) and ( port.dst eq 443 ) and ( action neq allow )"
    );
    expect(clientSide).toEqual({});
  });

  it("excludes alerts when only_blocked on threat/url logs", () => {
    expect(buildLogQuery("url", { only_blocked: true }).query).toBe("( action neq allow ) and ( action neq alert )");
  });

  it("uses absolute times and raw query", () => {
    const { query } = buildLogQuery("threat", {
      start_time: "2026/09/23 10:00:00",
      end_time: "2026/09/23 11:00:00",
      query: "severity geq high",
    });
    expect(query).toBe("( receive_time geq '2026/09/23 10:00:00' ) and ( receive_time leq '2026/09/23 11:00:00' ) and ( severity geq high )");
  });

  it("moves user/ip filtering client-side for globalprotect logs", () => {
    const { query, clientSide } = buildLogQuery("globalprotect", { user: "jdoe", src_ip: "10.0.0.1", period: "last-24-hrs" });
    expect(query).toBe("( receive_time in last-24-hrs )");
    expect(clientSide).toEqual({ user: "jdoe", ip: "10.0.0.1" });
  });

  it("rejects unsupported filters for non-session logs", () => {
    expect(() => buildLogQuery("userid", { dst_port: 443 })).toThrow(/not supported/);
  });

  it.each([
    [{ src_ip: "not-an-ip" }, /src_ip/],
    [{ src_ip: "10.0.0.0/33" }, /src_ip/],
    [{ user: "x' ) or ( 1" }, /quotes/],
    [{ start_time: "2026-09-23 10:00" }, /format/],
  ])("rejects invalid input %j", (filters, error) => {
    expect(() => buildLogQuery("traffic", filters)).toThrow(error);
  });

  it("requires a complete identity for session logs", () => {
    expect(() => buildLogQuery("traffic", { user: "jdoe" })).toThrow(/exactly as logged/);
    expect(buildLogQuery("traffic", { user: "corp\\u123456" }).query).toBe("( user.src eq 'corp\\u123456' )");
  });

  it("only allows url_contains on url logs", () => {
    expect(buildLogQuery("url", { url_contains: "yumpu.com" }).query).toBe("( url contains 'yumpu.com' )");
    expect(() => buildLogQuery("traffic", { url_contains: "yumpu.com" })).toThrow(/only works on url logs/);
  });

  it("accepts CIDR sources", () => {
    expect(buildLogQuery("traffic", { src_ip: "10.0.0.0/8" }).query).toBe("( addr.src in 10.0.0.0/8 )");
  });
});

describe("trimLogEntry", () => {
  it("keeps useful fields and drops empty ones", () => {
    const out = trimLogEntry("traffic", { src: "1.1.1.1", dst: "", rule: "r1", seqno: "42", "@_logid": "1" });
    expect(out).toEqual({ src: "1.1.1.1", rule: "r1" });
  });

  it("keeps everything with allFields", () => {
    expect(trimLogEntry("traffic", { seqno: "42" }, true)).toEqual({ seqno: "42" });
  });
});

describe("entryMatches", () => {
  const entry = { srcuser: "CORP\\JDoe", public_ip: "10.0.0.1", private_ip: "10.0.0.12" };
  it("matches user substring case-insensitively", () => {
    expect(entryMatches(entry, { user: "jdoe" })).toBe(true);
    expect(entryMatches(entry, { user: "other" })).toBe(false);
  });
  it("matches IP exactly", () => {
    expect(entryMatches(entry, { ip: "10.0.0.1" })).toBe(true);
    expect(entryMatches(entry, { ip: "10.0.0.2" })).toBe(false);
  });
});
