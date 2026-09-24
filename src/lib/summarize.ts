import type { LogType } from "./logquery.js";
import { hostOf, normalizeUrl } from "./urlmatch.js";

export interface LogGroup {
  count: number;
  first_seen: string;
  last_seen: string;
  key: Record<string, string>;
  users: string[];
  sources: string[];
  devices: string[];
}

function text(v: unknown): string {
  return typeof v === "object" && v !== null ? String((v as any)["#text"] ?? "") : String(v ?? "");
}

/** Fields that identify "the same thing happening" for each log type. */
function groupKey(logType: LogType, e: Record<string, any>): Record<string, string> {
  switch (logType) {
    case "url":
      return {
        host: hostOf(normalizeUrl(text(e.misc))),
        action: text(e.action),
        categories: text(e.url_category_list) || text(e.category),
        rule: text(e.rule),
      };
    case "traffic":
      return {
        dst: text(e.dst),
        dport: text(e.dport),
        app: text(e.app),
        action: text(e.action),
        rule: text(e.rule),
        end_reason: text(e.session_end_reason),
      };
    case "threat":
    case "wildfire":
    case "data":
      return {
        threat: text(e.threatid),
        subtype: text(e.subtype),
        action: text(e.action),
        rule: text(e.rule),
        file: text(e.misc),
        ...(logType === "wildfire" ? { verdict: text(e.category) } : {}),
      };
    case "decryption":
      return { dst: text(e.dst), error: text(e.error) || text(e.error_index), rule: text(e.rule) };
    case "globalprotect":
      return { event: text(e.eventid), stage: text(e.stage), status: text(e.status), error: text(e.error) };
    default:
      return { event: text(e.eventid) || text(e.subtype), description: text(e.description).slice(0, 120) };
  }
}

const MAX_LISTED = 5;

function addCapped(list: string[], value: string, overflow: Map<string[], number>): void {
  if (!value || list.includes(value)) return;
  if (list.length < MAX_LISTED) list.push(value);
  else overflow.set(list, (overflow.get(list) ?? 0) + 1);
}

/** Groups log entries by what happened, most frequent first: far smaller and more telling than raw entries. */
export function summarizeLogs(logType: LogType, entries: Array<Record<string, any>>, limit = 30): LogGroup[] {
  const groups = new Map<string, LogGroup>();
  const overflow = new Map<string[], number>();
  for (const e of entries) {
    const key = groupKey(logType, e);
    for (const k of Object.keys(key)) if (!key[k]) delete key[k];
    const id = JSON.stringify(key);
    const time = text(e.receive_time);
    let g = groups.get(id);
    if (!g) {
      g = { count: 0, first_seen: time, last_seen: time, key, users: [], sources: [], devices: [] };
      groups.set(id, g);
    }
    g.count++;
    if (time && time < g.first_seen) g.first_seen = time;
    if (time > g.last_seen) g.last_seen = time;
    addCapped(g.users, text(e.srcuser) || text(e.user), overflow);
    addCapped(g.sources, text(e.src) || text(e.ip) || text(e.public_ip), overflow);
    addCapped(g.devices, text(e.device_name), overflow);
  }
  for (const [list, extra] of overflow) list.push(`+${extra} more`);
  return [...groups.values()].sort((a, b) => b.count - a.count).slice(0, limit);
}
