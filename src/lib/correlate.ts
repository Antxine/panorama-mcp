import { classifyLogEntry, type BlockLayer } from "./classify.js";
import type { LogType } from "./logquery.js";
import { baseDomain, hostOf, normalizeUrl } from "./urlmatch.js";

export interface LogEvent {
  logType: LogType;
  /** Epoch ms, NaN when unknown. */
  time: number;
  entry: Record<string, any>;
}

export type Relation = "reported-site" | "same-time-as-reported-site";

export interface EventGroup {
  layer: BlockLayer;
  blocked: boolean;
  log_type: LogType;
  destination: string;
  rule: string;
  threat?: string;
  count: number;
  first_seen: string;
  last_seen: string;
  summary: string;
  next_steps: string[];
  relation?: Relation;
  sample: Record<string, any>;
}

const WINDOW_MS = 3 * 60 * 1000;

function text(v: unknown): string {
  return typeof v === "object" && v !== null ? String((v as any)["#text"] ?? "") : String(v ?? "");
}

/** Hostname of the destination when the log carries a URL (URL logs, some threat logs). */
export function eventHost(logType: LogType, entry: Record<string, any>): string | undefined {
  const url = logType === "url" ? text(entry.misc) : text(entry.url ?? "");
  if (!url) return undefined;
  const host = hostOf(normalizeUrl(url));
  return host || undefined;
}

/** Groups similar events (same layer, destination, rule and threat) and flags their relation to the reported site. */
export function groupEvents(
  events: LogEvent[],
  trim: (logType: LogType, entry: Record<string, any>) => Record<string, any>,
  reported?: { url?: string; incidentTime?: number },
  anchorEvents: LogEvent[] = []
): EventGroup[] {
  const reportedBase = reported?.url ? baseDomain(hostOf(normalizeUrl(reported.url))) : undefined;

  // Moments where the user was on the reported site: incident time + any log towards it.
  const anchors: number[] = [];
  if (reported?.incidentTime !== undefined && !Number.isNaN(reported.incidentTime)) anchors.push(reported.incidentTime);
  if (reportedBase) {
    for (const ev of [...anchorEvents, ...events]) {
      const host = eventHost(ev.logType, ev.entry);
      if (host && baseDomain(host) === reportedBase && !Number.isNaN(ev.time)) anchors.push(ev.time);
    }
  }

  const groups = new Map<string, EventGroup & { times: number[] }>();
  for (const ev of events) {
    const c = classifyLogEntry(ev.logType, ev.entry);
    const host = eventHost(ev.logType, ev.entry);
    const destination = host ?? text(ev.entry.dst);
    const rule = text(ev.entry.rule);
    const threat = text(ev.entry.threatid) || undefined;
    const key = [c.layer, destination, rule, threat ?? "", c.blocked].join("|");

    let relation: Relation | undefined;
    if (reportedBase && host && baseDomain(host) === reportedBase) relation = "reported-site";
    else if (anchors.some((a) => Math.abs(a - ev.time) <= WINDOW_MS)) relation = "same-time-as-reported-site";

    const existing = groups.get(key);
    const receive = text(ev.entry.receive_time);
    if (existing) {
      existing.count++;
      existing.times.push(ev.time);
      if (receive < existing.first_seen) existing.first_seen = receive;
      if (receive > existing.last_seen) existing.last_seen = receive;
      if (relation === "reported-site" || (relation && !existing.relation)) existing.relation = relation;
      continue;
    }
    groups.set(key, {
      layer: c.layer,
      blocked: c.blocked,
      log_type: ev.logType,
      destination,
      rule,
      threat,
      count: 1,
      first_seen: receive,
      last_seen: receive,
      summary: c.summary,
      next_steps: c.next_steps,
      relation,
      sample: trim(ev.logType, ev.entry),
      times: [ev.time],
    });
  }

  return [...groups.values()]
    .map(({ times: _times, ...g }) => g)
    .sort((a, b) => Number(b.blocked) - Number(a.blocked) || b.last_seen.localeCompare(a.last_seen));
}

/** Plain-language conclusions about blocks around the reported site. */
export function reportedSiteFindings(groups: EventGroup[], reportedUrl?: string): string[] {
  const findings: string[] = [];
  const blocked = groups.filter((g) => g.blocked || g.layer !== "none");
  if (!reportedUrl) return findings;

  const onSite = blocked.filter((g) => g.relation === "reported-site" && g.blocked);
  const sameTime = blocked.filter((g) => g.relation === "same-time-as-reported-site");
  const reportedHost = hostOf(normalizeUrl(reportedUrl));

  if (!onSite.length && sameTime.length) {
    findings.push(
      `The reported site ${reportedHost} is NOT blocked in the logs, but ${sameTime.length} block(s) happened on other destinations at the same time: ` +
        `${[...new Set(sameTime.map((g) => g.destination))].join(", ")}. The site most likely depends on these services ` +
        "(upload/storage, CDN, API, SSO): the fix must target these destinations, not the reported site."
    );
  } else if (onSite.length && sameTime.length) {
    findings.push(
      `The reported site ${reportedHost} is blocked (${onSite.map((g) => g.layer).join(", ")}), and other destinations were blocked at the same time ` +
        `(${[...new Set(sameTime.map((g) => g.destination))].join(", ")}): fixing only the reported site may not be enough.`
    );
  } else if (onSite.length) {
    findings.push(`The reported site ${reportedHost} is blocked by: ${[...new Set(onSite.map((g) => g.layer))].join(", ")}.`);
  } else {
    findings.push(
      `No block found for ${reportedHost} nor at the same time on other destinations. PAN-OS does not log URL categories set to 'allow', ` +
        "so third-party domains used by the site may be missing: ask the user for the browser DevTools Network tab (failed requests) or a HAR file, then re-run with those domains."
    );
  }
  return findings;
}

/** Why a search may legitimately return nothing: points the model to visibility issues, not to "no problem". */
export const NO_LOG_HINTS = [
  "Rules without a log forwarding profile do not send logs to Panorama: check the rule's log_forwarding (find_security_rules) or look on the firewall itself.",
  "The predefined interzone-default/intrazone-default rules do not log by default: a silent deny often means no rule matched.",
  "URL categories with action 'allow' are not logged in URL logs.",
  "Check the user identity: log user names may be 'domain\\\\user' or UPN; try the source IP instead (User-ID mapping may be missing).",
  "Widen the period: log times are in Panorama's timezone and forwarding can lag a few minutes.",
];
