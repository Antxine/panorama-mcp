import { describe, it, expect } from "vitest";
import { lookbackFinding, lookbackWindows, searchBackwards, windowFilters } from "../../src/lib/lookback.js";

const NOW = new Date(2026, 8, 25, 12, 0, 0).getTime();

describe("lookbackWindows", () => {
  it("covers the last 7 days by default, newest first, without gaps", () => {
    const w = lookbackWindows(NOW);
    expect(w.map((x) => x.label)).toEqual(["last 24h", "1-2 days ago", "2-3 days ago", "3-5 days ago", "5-7 days ago"]);
    expect(w[0].end_time).toBe("2026/09/25 12:00:00");
    expect(w[w.length - 1].start_time).toBe("2026/09/18 12:00:00");
    for (let i = 1; i < w.length; i++) expect(w[i].end_time).toBe(w[i - 1].start_time);
  });

  it("stops at the requested number of days and caps at 14", () => {
    expect(lookbackWindows(NOW, 4).map((x) => x.label)).toEqual(["last 24h", "1-2 days ago", "2-3 days ago", "3-4 days ago"]);
    expect(lookbackWindows(NOW, 1)).toHaveLength(1);
    const max = lookbackWindows(NOW, 30);
    expect(max[max.length - 1].label).toBe("10-14 days ago");
  });
});

describe("searchBackwards", () => {
  it("stops at the first window with evidence", async () => {
    const windows = lookbackWindows(NOW);
    const calls: string[] = [];
    const lb = await searchBackwards(
      windows,
      async (w) => {
        calls.push(w.label);
        return w.label === "2-3 days ago" ? ["block"] : [];
      },
      (r) => r.length > 0
    );
    expect(calls).toEqual(["last 24h", "1-2 days ago", "2-3 days ago"]);
    expect(lb.found?.label).toBe("2-3 days ago");
    expect(lb.result).toEqual(["block"]);
    expect(lookbackFinding(lb, "a block")).toContain("found 2-3 days ago");
  });

  it("returns the newest result when nothing is found", async () => {
    const windows = lookbackWindows(NOW, 3);
    const lb = await searchBackwards(windows, async (w) => w.label, () => false);
    expect(lb.found).toBeUndefined();
    expect(lb.result).toBe("last 24h");
    expect(lb.searched).toHaveLength(3);
    expect(lookbackFinding(lb, "a block")).toContain("to 2026/09/22 12:00:00: a block was not found");
  });
});

describe("windowFilters", () => {
  it("uses the period when set, else start/end", () => {
    expect(windowFilters({ period: "last-7-days", label: "x" })).toEqual({ period: "last-7-days" });
    expect(windowFilters({ start_time: "a", end_time: "b", label: "x" })).toEqual({ start_time: "a", end_time: "b" });
  });
});
