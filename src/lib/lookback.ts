/**
 * Backward log search: tickets are often opened days after the block happened, so when the incident
 * time is unknown, logs are searched window by window going back in time (newest first) until
 * relevant evidence is found. Short windows keep each query below the Panorama timeout.
 */

import type { LogFilters, LogPeriod } from "./logquery.js";
import { remainingMs } from "./budget.js";

const DAY_MS = 24 * 60 * 60 * 1000;

/** Window boundaries in days before now: [0-1], [1-2], [2-3], [3-5], [5-7], [7-10], [10-14], [14-21], [21-30]. */
const BOUNDARIES = [0, 1, 2, 3, 5, 7, 10, 14, 21, 30];

export const DEFAULT_LOOKBACK_DAYS = 14;
export const MAX_LOOKBACK_DAYS = 30;

export interface TimeWindow {
  start_time?: string;
  end_time?: string;
  /** Relative period instead of start/end (explicit 'period' parameter). */
  period?: LogPeriod;
  /** Human label, e.g. "last 24h" or "2-3 days ago". */
  label: string;
  /** Backward windows: days before now covered by the window. */
  fromDays?: number;
  toDays?: number;
}

/** Time a window needs to be worth starting: less than that, answer now and let the model resume. */
const MIN_WINDOW_MS = 20_000;

/** Log filter fields of a window. */
export function windowFilters(w: TimeWindow): Pick<LogFilters, "period" | "start_time" | "end_time"> {
  return w.period ? { period: w.period } : { start_time: w.start_time, end_time: w.end_time };
}

export function formatLogTime(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}/${p(d.getMonth() + 1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** Consecutive windows from `startDays` to `days` days ago, newest first. */
export function lookbackWindows(nowMs: number, days = DEFAULT_LOOKBACK_DAYS, startDays = 0): TimeWindow[] {
  const limit = Math.min(Math.max(1, Math.round(days)), MAX_LOOKBACK_DAYS);
  const start = Math.min(Math.max(0, Math.round(startDays)), limit - 1);
  const bounds = [start, ...BOUNDARIES.filter((b) => b > start && b < limit), limit];
  const windows: TimeWindow[] = [];
  for (let i = 0; i + 1 < bounds.length; i++) {
    const [from, to] = [bounds[i], bounds[i + 1]];
    windows.push({
      start_time: formatLogTime(nowMs - to * DAY_MS),
      end_time: formatLogTime(nowMs - from * DAY_MS),
      label: from === 0 ? `last ${to * 24}h` : `${from}-${to} days ago`,
      fromDays: from,
      toDays: to,
    });
  }
  return windows;
}

export interface LookbackResult<T> {
  result: T;
  /** Window where relevant evidence was found, undefined when none had any. */
  found?: TimeWindow;
  /** Windows searched, newest first. */
  searched: TimeWindow[];
  /** Older windows left unsearched to answer before the client timeout. */
  remaining: TimeWindow[];
}

/**
 * Runs `run` on each window, newest first, and stops at the first one where `found` is true.
 * Without any hit, returns the newest window's result (the most useful default).
 */
export async function searchBackwards<T>(
  windows: TimeWindow[],
  run: (w: TimeWindow) => Promise<T>,
  found: (result: T) => boolean
): Promise<LookbackResult<T>> {
  const searched: TimeWindow[] = [];
  let first: T | undefined;
  for (const [i, w] of windows.entries()) {
    if (searched.length && remainingMs() < MIN_WINDOW_MS) return { result: first as T, searched, remaining: windows.slice(i) };
    const result = await run(w);
    searched.push(w);
    if (first === undefined) first = result;
    if (found(result)) return { result, found: w, searched, remaining: [] };
  }
  return { result: first as T, searched, remaining: [] };
}

/** One-line finding describing how far back the search went. */
export function lookbackFinding(lb: LookbackResult<unknown>, what: string): string {
  const oldest = lb.searched[lb.searched.length - 1];
  if (!lb.found && lb.remaining.length) {
    const next = lb.remaining[0];
    return `Searched ${lb.searched.map((w) => w.label).join(", ")}: ${what} was not found yet. Stopped to answer before the client timeout: call again with lookback_start_days: ${next.fromDays} to continue with older logs (${lb.remaining.map((w) => w.label).join(", ")}).`;
  }
  if (!lb.found) {
    return `Searched back window by window from now to ${oldest?.start_time}: ${what} was not found. Ask the user for the date and time of the block, or widen lookback_days.`;
  }
  if (lb.searched.length === 1) return `${what[0].toUpperCase()}${what.slice(1)} found in the last 24h.`;
  return `Nothing relevant in the most recent windows: ${what} found ${lb.found.label} (${lb.found.start_time} to ${lb.found.end_time}). The ticket was likely opened after the block happened.`;
}
