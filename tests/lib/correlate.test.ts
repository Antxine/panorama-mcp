import { describe, it, expect } from "vitest";
import { groupEvents, reportedSiteFindings, type LogEvent } from "../../src/lib/correlate.js";

const t = (hhmm: string) => new Date(2026, 8, 23, Number(hhmm.slice(0, 2)), Number(hhmm.slice(3, 5))).getTime();
const identity = (_: unknown, e: Record<string, any>) => e;

describe("groupEvents / reportedSiteFindings", () => {
  it("flags a block on a third-party domain used by the reported site", () => {
    const anchor: LogEvent[] = [
      { logType: "url", time: t("10:00"), entry: { misc: "app.abc.com/upload", action: "alert", receive_time: "2026/09/23 10:00:00" } },
    ];
    const events: LogEvent[] = [
      {
        logType: "url",
        time: t("10:01"),
        entry: { misc: "storage.xyz.com/put", action: "block-url", rule: "web", category: "online-storage", receive_time: "2026/09/23 10:01:00" },
      },
      {
        logType: "url",
        time: t("10:01"),
        entry: { misc: "storage.xyz.com/put2", action: "block-url", rule: "web", category: "online-storage", receive_time: "2026/09/23 10:01:30" },
      },
      {
        logType: "url",
        time: t("16:00"),
        entry: { misc: "unrelated.net/", action: "block-url", rule: "web", receive_time: "2026/09/23 16:00:00" },
      },
    ];
    const groups = groupEvents(events, identity, { url: "https://app.abc.com" }, anchor);

    const xyz = groups.find((g) => g.destination === "storage.xyz.com")!;
    expect(xyz.count).toBe(2);
    expect(xyz.relation).toBe("same-time-as-reported-site");
    expect(groups.find((g) => g.destination === "unrelated.net")!.relation).toBeUndefined();

    const findings = reportedSiteFindings(groups, "https://app.abc.com");
    expect(findings[0]).toContain("app.abc.com is NOT blocked");
    expect(findings[0]).toContain("storage.xyz.com");
  });

  it("uses the incident time as anchor", () => {
    const events: LogEvent[] = [
      { logType: "threat", time: t("09:59"), entry: { subtype: "file", action: "deny", dst: "52.1.2.3", rule: "web", receive_time: "2026/09/23 09:59:00" } },
    ];
    const groups = groupEvents(events, identity, { url: "abc.com", incidentTime: t("10:00") });
    expect(groups[0].relation).toBe("same-time-as-reported-site");
    expect(groups[0].layer).toBe("file-blocking");
  });

  it("reports blocks on the reported site itself", () => {
    const events: LogEvent[] = [
      { logType: "url", time: t("10:00"), entry: { misc: "www.abc.com/", action: "block-url", receive_time: "2026/09/23 10:00:00" } },
    ];
    const groups = groupEvents(events, identity, { url: "https://abc.com/" });
    expect(groups[0].relation).toBe("reported-site");
    expect(reportedSiteFindings(groups, "https://abc.com/")[0]).toContain("is blocked by: url-filtering");
  });

  it("asks for browser evidence when nothing is found", () => {
    expect(reportedSiteFindings([], "abc.com")[0]).toContain("DevTools");
  });
});
