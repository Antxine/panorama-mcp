import { executeLogQuery, executeOpCommand, isApiError, resolveTarget, type FirewallTarget } from "./client.js";
import { asArray, nodeText } from "./panorama.js";
import { xmlEscape } from "../schemas/panos.js";
import { buildLogQuery, entryMatches, type LogFilters, type LogType } from "../lib/logquery.js";

/** Resolves the Panorama entry from firewalls.json / env, throwing instead of returning an error object. */
export function panoramaTarget(firewall?: string): FirewallTarget {
  const target = resolveTarget(firewall);
  if (isApiError(target)) throw new Error(target.error);
  return target;
}

/** Runs an op command (optionally proxied to a managed firewall) and returns its `result` or throws. */
export async function op(target: FirewallTarget, cmd: string, serial?: string): Promise<any> {
  const result = await executeOpCommand(cmd, target, serial);
  if (!result.success) throw new Error(explainApiError(result.error));
  return result.data;
}

/** Turns PAN-OS permission errors into an actionable message. */
export function explainApiError(error = "Unknown PanOS error"): string {
  const denied = /Type \[(\w+)\] not authorized/i.exec(error);
  if (!denied) return error;
  const permission: Record<string, string> = { op: "Operational Requests", log: "Log", config: "Configuration" };
  return `${error} -> the Panorama admin role of the API key lacks the XML API permission '${permission[denied[1]] ?? denied[1]}'. Tools relying on it are unavailable until the role is updated.`;
}

/** `<a><b>value</b></a>`-style helper for building op commands with escaped leaf values. */
export function xmlLeaf(tag: string, value: string | number | undefined): string {
  return value === undefined || value === "" ? "" : `<${tag}>${xmlEscape(String(value))}</${tag}>`;
}

export interface LogSearchResult {
  query: string;
  entries: Array<Record<string, any>>;
  /** Number of entries matching before truncation to max results. */
  matched: number;
  /** The query did not finish in time: entries are only the logs received so far. */
  partial?: boolean;
}

/**
 * Queries logs stored on Panorama / its log collectors. When some filters cannot be
 * expressed in the PAN-OS filter language for this log type, a larger batch is fetched
 * and filtered locally.
 */
export async function searchLogs(
  target: FirewallTarget,
  logType: LogType,
  filters: LogFilters,
  maxResults = 50,
  extraFilter?: (entry: Record<string, any>) => boolean
): Promise<LogSearchResult> {
  const built = buildLogQuery(logType, filters);
  const localFiltering = Boolean(built.clientSide.user || built.clientSide.ip || extraFilter);
  const nlogs = localFiltering ? 2000 : Math.min(maxResults, 5000);

  const result = await executeLogQuery(logType, nlogs, built.query || undefined, target);
  if (!result.success) throw new Error(explainApiError(result.error));

  let entries = asArray<Record<string, any>>(result.data?.entry);
  if (built.clientSide.user || built.clientSide.ip) entries = entries.filter((e) => entryMatches(e, built.clientSide));
  if (extraFilter) entries = entries.filter(extraFilter);
  return { query: built.query, entries: entries.slice(0, maxResults), matched: entries.length, ...(result.partial ? { partial: true } : {}) };
}

/** Parses `test url` output lines like "www.x.com search-engines,low-risk (Cloud db)". */
export function parseTestUrl(raw: unknown): { categories: string[]; lines: string[] } {
  const text = typeof raw === "string" ? raw : nodeText(raw) || JSON.stringify(raw ?? "");
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const categories = new Set<string>();
  for (const line of lines) {
    const m = /^\S+\s+(\S+)\s+\(([^)]*)\)/.exec(line);
    if (m) m[1].split(",").filter(Boolean).forEach((c) => categories.add(c));
  }
  return { categories: [...categories], lines };
}

export async function testUrl(target: FirewallTarget, serial: string, url: string) {
  const data = await op(target, `<test>${xmlLeaf("url", url)}</test>`, serial);
  return parseTestUrl(data);
}

export interface IpUserMapping {
  ip: string;
  user: string;
  type?: string;
  vsys?: string;
  idleTimeout?: string;
  maxTimeout?: string;
}

export async function ipUserMapping(target: FirewallTarget, serial: string, ip: string): Promise<IpUserMapping[]> {
  const data = await op(target, `<show><user><ip-user-mapping>${xmlLeaf("ip", ip)}</ip-user-mapping></user></show>`, serial);
  return asArray(data?.entry).map((e: any) => ({
    ip: nodeText(e.ip),
    user: nodeText(e.user),
    type: nodeText(e.type) || undefined,
    vsys: nodeText(e.vsys) || undefined,
    idleTimeout: nodeText(e.idle_timeout) || undefined,
    maxTimeout: nodeText(e.max_timeout) || undefined,
  }));
}

/** Groups known by User-ID for a user (`show user user-ids match-user`); PAN-OS returns plain text. */
export async function userGroups(target: FirewallTarget, serial: string, user: string): Promise<string> {
  const data = await op(target, `<show><user><user-ids>${xmlLeaf("match-user", user)}</user-ids></user></show>`, serial);
  return typeof data === "string" ? data.trim() : nodeText(data) || JSON.stringify(data);
}

export interface PolicyMatchInput {
  from?: string;
  to?: string;
  source: string;
  destination: string;
  destination_port: number;
  protocol: number;
  application?: string;
  source_user?: string;
  category?: string;
  show_all?: boolean;
}

export async function testSecurityPolicyMatch(target: FirewallTarget, serial: string, input: PolicyMatchInput) {
  const cmd =
    "<test><security-policy-match>" +
    xmlLeaf("from", input.from) +
    xmlLeaf("to", input.to) +
    xmlLeaf("source", input.source) +
    xmlLeaf("destination", input.destination) +
    xmlLeaf("destination-port", input.destination_port) +
    xmlLeaf("protocol", input.protocol) +
    xmlLeaf("application", input.application) +
    xmlLeaf("source-user", input.source_user) +
    xmlLeaf("category", input.category) +
    (input.show_all ? "<show-all>yes</show-all>" : "") +
    "</security-policy-match></test>";
  const data = await op(target, cmd, serial);
  return asArray(data?.rules?.entry).map((e: any) =>
    typeof e === "string" ? { raw: e } : { name: nodeText(e["@_name"]), action: nodeText(e.action) || undefined, details: e }
  );
}

/** Parses PAN-OS log timestamps ("2026/09/23 10:04:05") as local time; NaN when invalid. */
export function logTime(value: unknown): number {
  const m = /^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})$/.exec(nodeText(value));
  if (!m) return NaN;
  return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime();
}
