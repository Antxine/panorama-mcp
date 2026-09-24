import { isIP } from "net";

export const LOG_TYPES = [
  "traffic", "threat", "url", "wildfire", "data", "globalprotect", "userid", "auth", "decryption", "system",
] as const;
export type LogType = (typeof LOG_TYPES)[number];

/** Relative time windows understood by the PAN-OS log filter (`receive_time in <period>`). */
export const LOG_PERIODS = [
  "last-15-minutes",
  "last-hour",
  "last-6-hrs",
  "last-12-hrs",
  "last-24-hrs",
  "last-7-days",
  "last-30-days",
] as const;
export type LogPeriod = (typeof LOG_PERIODS)[number];

/** Log types whose filter fields (addr.src, user.src, ...) are applied server-side by PAN-OS. */
const SESSION_LOG_TYPES: ReadonlySet<LogType> = new Set(["traffic", "threat", "url", "wildfire", "data", "decryption"]);

export interface LogFilters {
  src_ip?: string;
  dst_ip?: string;
  user?: string;
  dst_port?: number;
  app?: string;
  rule?: string;
  action?: string;
  only_blocked?: boolean;
  url_contains?: string;
  period?: LogPeriod;
  start_time?: string;
  end_time?: string;
  query?: string;
}

export interface BuiltLogQuery {
  /** Filter sent to PAN-OS (`query=` parameter). */
  query: string;
  /** Terms PAN-OS cannot filter for this log type; applied on the returned entries instead. */
  clientSide: { user?: string; ip?: string };
}

const TIME_RE = /^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}$/;

function assertIpOrCidr(value: string, field: string): void {
  const [addr, prefix] = value.split("/");
  const version = isIP(addr);
  const prefixOk = prefix === undefined || (/^\d{1,3}$/.test(prefix) && Number(prefix) <= (version === 6 ? 128 : 32));
  if (!version || !prefixOk) throw new Error(`${field} must be an IP address or CIDR, got '${value}'`);
}

function assertSafeLiteral(value: string, field: string): void {
  // The PAN-OS filter language has no escaping for quotes inside literals.
  if (/['()]/.test(value)) throw new Error(`${field} must not contain quotes or parentheses`);
}

/**
 * PAN-OS only supports exact match on user.src, so the identity must be complete:
 * UPN for GlobalProtect/Prisma Access users, DOMAIN\\id for AD/Citrix users.
 */
export function assertFullIdentity(user: string): string {
  if (!/[@\\]/.test(user)) {
    throw new Error(
      `user '${user}' must be the identity exactly as logged: 'name@domain' (GlobalProtect/Prisma) or 'DOMAIN\\id' (AD/Citrix). ` +
        "Unknown? Search by src_ip, or by the blocked URL (log_type=url, url_contains) and read srcuser in the results."
    );
  }
  return user;
}

/** Builds a PAN-OS log filter from structured filters. Throws on invalid input. */
export function buildLogQuery(logType: LogType, f: LogFilters): BuiltLogQuery {
  const terms: string[] = [];
  const clientSide: BuiltLogQuery["clientSide"] = {};
  const sessionLog = SESSION_LOG_TYPES.has(logType);

  if (f.period) terms.push(`( receive_time in ${f.period} )`);
  for (const [value, op, name] of [
    [f.start_time, "geq", "start_time"],
    [f.end_time, "leq", "end_time"],
  ] as const) {
    if (!value) continue;
    if (!TIME_RE.test(value)) throw new Error(`${name} must use the format 'YYYY/MM/DD HH:MM:SS'`);
    terms.push(`( receive_time ${op} '${value}' )`);
  }

  if (f.src_ip) assertIpOrCidr(f.src_ip, "src_ip");
  if (f.dst_ip) assertIpOrCidr(f.dst_ip, "dst_ip");
  for (const [value, name] of [
    [f.user, "user"],
    [f.app, "app"],
    [f.rule, "rule"],
    [f.action, "action"],
    [f.url_contains, "url_contains"],
  ] as const) {
    if (value) assertSafeLiteral(value, name);
  }

  if (f.url_contains && logType !== "url") {
    throw new Error(
      "url_contains only works on url logs (other log types have no URL field): search log_type=url first, then filter other logs by dst_ip/src_ip"
    );
  }

  if (sessionLog) {
    if (f.src_ip) terms.push(`( addr.src in ${f.src_ip} )`);
    if (f.dst_ip) terms.push(`( addr.dst in ${f.dst_ip} )`);
    if (f.user) terms.push(`( user.src eq '${assertFullIdentity(f.user)}' )`);
    if (f.dst_port !== undefined) terms.push(`( port.dst eq ${f.dst_port} )`);
    if (f.app) terms.push(`( app eq ${f.app} )`);
    if (f.rule) terms.push(`( rule eq '${f.rule}' )`);
    if (f.action) terms.push(`( action eq ${f.action} )`);
    if (f.only_blocked) {
      terms.push(logType === "traffic" ? "( action neq allow )" : "( action neq allow ) and ( action neq alert )");
    }
    if (f.url_contains) terms.push(`( url contains '${f.url_contains}' )`);
  } else {
    // Field names differ for these log types; match on returned entries instead.
    if (f.user) clientSide.user = f.user;
    if (f.src_ip) clientSide.ip = f.src_ip;
    const unsupported = [
      f.dst_ip && "dst_ip",
      f.dst_port !== undefined && "dst_port",
      f.app && "app",
      f.rule && "rule",
      f.action && "action",
      f.only_blocked && "only_blocked",
      f.url_contains && "url_contains",
    ].filter(Boolean);
    if (unsupported.length) {
      throw new Error(`Filters ${unsupported.join(", ")} are not supported for ${logType} logs; use 'query' instead`);
    }
  }

  if (f.query) terms.push(`( ${f.query} )`);

  return { query: terms.join(" and "), clientSide };
}

/** Most useful fields per log type; everything else is dropped unless all_fields is requested. */
const FIELDS: Partial<Record<LogType, string[]>> = {
  traffic: [
    "receive_time", "device_name", "serial", "vsys", "from", "to", "src", "dst", "natsrc", "natdst",
    "srcuser", "sport", "dport", "proto", "app", "rule", "action", "session_end_reason",
    "category", "bytes_sent", "bytes_received", "elapsed",
  ],
  threat: [
    "receive_time", "device_name", "serial", "vsys", "from", "to", "src", "dst", "srcuser", "dport",
    "app", "rule", "action", "subtype", "threatid", "severity", "direction", "misc", "thr_category",
    "filetype", "filedigest", "reportid", "contenttype", "url_idx",
  ],
  wildfire: [
    "receive_time", "device_name", "serial", "src", "dst", "srcuser", "app", "rule", "action", "subtype",
    "threatid", "category", "direction", "misc", "filetype", "filedigest", "reportid", "cloud",
  ],
  data: [
    "receive_time", "device_name", "serial", "src", "dst", "srcuser", "app", "rule", "action", "subtype",
    "threatid", "severity", "direction", "misc", "filetype",
  ],
  url: [
    "receive_time", "device_name", "serial", "from", "to", "src", "dst", "srcuser", "app", "rule",
    "action", "misc", "category", "url_category_list", "http_method", "user_agent", "referer",
  ],
  globalprotect: [
    "receive_time", "time_generated", "device_name", "serial", "eventid", "stage", "status", "error",
    "error_code", "srcuser", "public_ip", "private_ip", "portal", "gateway", "machinename",
    "client_ver", "client_os", "client_os_ver", "auth_method", "connect_method", "login_duration",
    "selection_type", "srcregion", "description",
  ],
  userid: [
    "receive_time", "device_name", "serial", "vsys", "user", "ip", "datasource", "datasourcename",
    "datasourcetype", "factortype", "eventid", "timeout", "beginport", "endport",
  ],
};

function isEmpty(value: unknown): boolean {
  return value === undefined || value === null || value === "" || (typeof value === "object" && Object.keys(value as object).length === 0);
}

/** Keeps the useful fields of a log entry and drops empty values. */
export function trimLogEntry(logType: LogType, entry: Record<string, any>, allFields = false): Record<string, any> {
  const keys = allFields || !FIELDS[logType] ? Object.keys(entry) : FIELDS[logType]!;
  const out: Record<string, any> = {};
  for (const key of keys) {
    const value = entry[key];
    if (!isEmpty(value) && !key.startsWith("@_")) out[key] = value;
  }
  return out;
}

/** Case-insensitive match of a client-side term against every field of a log entry. */
export function entryMatches(entry: Record<string, any>, clientSide: BuiltLogQuery["clientSide"]): boolean {
  const values = Object.values(entry).map((v) => String(typeof v === "object" ? v?.["#text"] ?? "" : v).toLowerCase());
  const has = (needle: string) => values.some((v) => v.includes(needle.toLowerCase()));
  if (clientSide.user && !has(clientSide.user)) return false;
  if (clientSide.ip && !values.some((v) => v === clientSide.ip!.toLowerCase())) return false;
  return true;
}
