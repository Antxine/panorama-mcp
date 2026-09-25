import { describe, it, expect } from "vitest";
import { cancelled, remainingMs, runWithBudget, toolBudgetMs } from "../../src/lib/budget.js";
import { lookbackFinding, lookbackWindows, searchBackwards } from "../../src/lib/lookback.js";

describe("tool budget", () => {
  it("is unlimited outside a tool call", () => {
    expect(remainingMs()).toBe(Infinity);
  });

  it("defaults to 50 seconds and reads PANOS_TOOL_BUDGET_SECONDS", () => {
    expect(toolBudgetMs({})).toBe(50_000);
    expect(toolBudgetMs({ PANOS_TOOL_BUDGET_SECONDS: "200" })).toBe(200_000);
  });

  it("tracks the deadline across awaits", async () => {
    const left = await runWithBudget(async () => {
      await new Promise((r) => setTimeout(r, 5));
      return remainingMs();
    }, undefined, 1000);
    expect(left).toBeLessThanOrEqual(1000);
    expect(left).toBeGreaterThan(900);
  });

  it("drops to zero when the client cancels", async () => {
    const ctrl = new AbortController();
    await runWithBudget(async () => {
      ctrl.abort();
      expect(cancelled()).toBe(true);
      expect(remainingMs()).toBe(0);
    }, ctrl.signal);
  });
});

describe("searchBackwards under a budget", () => {
  const NOW = new Date(2026, 8, 25, 12, 0, 0).getTime();

  it("stops before a new window when time is short and says how to resume", async () => {
    const windows = lookbackWindows(NOW);
    const calls: string[] = [];
    const lb = await runWithBudget(
      () =>
        searchBackwards(
          windows,
          async (w) => {
            calls.push(w.label);
            return [];
          },
          () => false
        ),
      undefined,
      15_000
    );
    expect(calls).toEqual(["last 24h"]);
    expect(lb.remaining[0].label).toBe("1-2 days ago");
    expect(lookbackFinding(lb, "a block")).toContain("lookback_start_days: 1");
  });

  it("resumes from lookback_start_days", () => {
    const w = lookbackWindows(NOW, 14, 5);
    expect(w.map((x) => x.label)).toEqual(["5-7 days ago", "7-10 days ago", "10-14 days ago"]);
    expect(lookbackWindows(NOW, 14, 4)[0].label).toBe("4-5 days ago");
  });
});
