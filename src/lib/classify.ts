import type { LogType } from "./logquery.js";

/** Enforcement layer that produced (or explains) a log event. */
export type BlockLayer =
  | "security-policy"
  | "default-rule"
  | "url-filtering"
  | "antivirus"
  | "wildfire"
  | "anti-spyware"
  | "dns-security"
  | "vulnerability"
  | "file-blocking"
  | "data-filtering"
  | "zone-protection"
  | "decryption"
  | "app-id"
  | "network"
  | "authentication"
  | "globalprotect"
  | "none";

export interface Classification {
  blocked: boolean;
  layer: BlockLayer;
  summary: string;
  next_steps: string[];
}

const TRAFFIC_BLOCK_ACTIONS = new Set(["deny", "drop", "drop-icmp", "reset-client", "reset-server", "reset-both"]);
const PASS_ACTIONS = new Set(["allow", "alert", ""]);

function str(entry: Record<string, any>, key: string): string {
  const v = entry[key];
  return (typeof v === "object" && v !== null ? String(v["#text"] ?? "") : String(v ?? "")).trim();
}

export function isBlockingAction(logType: LogType, action: string): boolean {
  const a = action.toLowerCase();
  if (logType === "traffic") return TRAFFIC_BLOCK_ACTIONS.has(a);
  if (logType === "url") return a !== "allow" && a !== "alert";
  return !PASS_ACTIONS.has(a);
}

function classifyTraffic(e: Record<string, any>): Classification {
  const action = str(e, "action");
  const reason = str(e, "session_end_reason");
  const rule = str(e, "rule");
  const app = str(e, "app");
  const received = Number(str(e, "bytes_received") || "0");

  if (TRAFFIC_BLOCK_ACTIONS.has(action)) {
    if (/^(interzone|intrazone)-default$/.test(rule)) {
      return {
        blocked: true,
        layer: "default-rule",
        summary: `No explicit rule matched; denied by the default '${rule}' rule`,
        next_steps: [
          "diagnose_flow with the same source/destination/port to see which rules almost match (zone, user, application, service)",
          "Check User-ID mapping of the source if the expected rule uses source users/groups",
        ],
      };
    }
    return {
      blocked: true,
      layer: "security-policy",
      summary: `Denied by security rule '${rule}' (action ${action}, app ${app})`,
      next_steps: [
        `find_security_rules to inspect '${rule}' and the rules placed before it`,
        "diagnose_flow to test policy match with the user's identity",
      ],
    };
  }

  if (reason === "threat") {
    return {
      blocked: true,
      layer: "none",
      summary: `Session allowed by rule '${rule}' but terminated by a security profile (session_end_reason=threat)`,
      next_steps: ["search_logs log_type=threat for the same source/destination to find the threat ID and profile type"],
    };
  }
  if (reason.startsWith("decrypt")) {
    return {
      blocked: true,
      layer: "decryption",
      summary: `Session ended by decryption (${reason}): certificate validation, pinning or unsupported parameters`,
      next_steps: ["search_logs log_type=decryption for the destination to read the exact error", "Check decryption rules/profile applied (find_security_rules with policy decryption)"],
    };
  }
  if (app === "incomplete" || app === "insufficient-data") {
    return {
      blocked: false,
      layer: "network",
      summary: `Allowed by '${rule}' but handshake never completed (app=${app}): no reply from the server, routing, NAT or upstream filtering, not a policy block`,
      next_steps: ["Check routing/NAT towards the destination and return path (asymmetric routing)", "show_sessions on the firewall while the user retries"],
    };
  }
  if (reason === "aged-out" && received === 0 && str(e, "proto") === "tcp") {
    return {
      blocked: false,
      layer: "network",
      summary: "Session aged out with 0 bytes received: the destination never answered (network/NAT/server side)",
      next_steps: ["Check routing/NAT and the server; verify the traffic is not dropped by an upstream device"],
    };
  }
  if (reason === "tcp-rst-from-server") {
    return {
      blocked: false,
      layer: "network",
      summary: "The server reset the connection (tcp-rst-from-server): the firewall allowed it",
      next_steps: ["Issue is on the server/application side, or a decryption/SNI issue if the site rejects the firewall's certificate"],
    };
  }
  if (app.startsWith("unknown-")) {
    return {
      blocked: false,
      layer: "app-id",
      summary: `App-ID could not identify the traffic (${app}); rules listing specific applications will not match it`,
      next_steps: ["Consider a custom application or application override for this destination/port"],
    };
  }
  return { blocked: false, layer: "none", summary: `Allowed by '${rule}' (${app}, ${reason || "no end reason"})`, next_steps: [] };
}

function classifyThreat(e: Record<string, any>, logType: LogType): Classification {
  const subtype = str(e, "subtype");
  const action = str(e, "action");
  const threat = str(e, "threatid");
  const rule = str(e, "rule");
  const blocked = isBlockingAction(logType, action);
  const detail = `${threat || subtype} (action ${action}, rule '${rule}')`;
  const threatSteps = [
    "diagnose_threat_block with this threat to see the applied profile and any existing exception",
  ];

  switch (subtype) {
    case "url":
      return {
        blocked,
        layer: "url-filtering",
        summary: `URL filtering: ${str(e, "misc")} ${detail}`,
        next_steps: ["diagnose_url_access with this URL"],
      };
    case "virus":
    case "wildfire-virus":
    case "ml-virus":
      return {
        blocked,
        layer: subtype === "virus" ? "antivirus" : "wildfire",
        summary: `${subtype} signature matched on file '${str(e, "misc")}': ${detail}`,
        next_steps: [
          ...threatSteps,
          "If a false positive: check the WildFire verdict (search_logs log_type=wildfire, filedigest) and request a verdict change before adding an exception",
        ],
      };
    case "wildfire":
      return {
        blocked: false,
        layer: "wildfire",
        summary: `WildFire submission, verdict '${str(e, "category")}' for '${str(e, "misc")}'. Submission logs do not block by themselves; blocking comes from signatures/inline ML`,
        next_steps: threatSteps,
      };
    case "spyware": {
      const dns = /dns|sinkhole/i.test(`${threat} ${str(e, "thr_category")} ${action}`);
      return {
        blocked,
        layer: dns ? "dns-security" : "anti-spyware",
        summary: dns
          ? `DNS Security / DNS signature: ${detail}. The client got a sinkholed answer, so it may look like a DNS or connectivity issue`
          : `Anti-spyware signature: ${detail}`,
        next_steps: threatSteps,
      };
    }
    case "vulnerability":
      return {
        blocked,
        layer: "vulnerability",
        summary: `Vulnerability protection signature: ${detail}. Common false positives on uploads/forms (SQLi/XSS/brute-force signatures)`,
        next_steps: threatSteps,
      };
    case "file":
      return {
        blocked,
        layer: "file-blocking",
        summary: `File blocking: ${str(e, "filetype") || threat} '${str(e, "misc")}' direction ${str(e, "direction")} (action ${action}, rule '${rule}')`,
        next_steps: [
          "diagnose_threat_block to see the file-blocking profile rule (application, file type, direction) that matched",
          "Note: action 'continue' only works in a browser over HTTP(S); it breaks non-browser apps and sync clients",
        ],
      };
    case "data":
      return { blocked, layer: "data-filtering", summary: `Data filtering pattern matched: ${detail}`, next_steps: threatSteps };
    case "flood":
    case "scan":
    case "packet":
      return {
        blocked,
        layer: "zone-protection",
        summary: `Zone/DoS protection (${subtype}): ${detail}. Asymmetric routing can trigger 'reject non-SYN TCP' drops`,
        next_steps: ["Review the zone protection profile of the ingress zone"],
      };
    default:
      return { blocked, layer: "none", summary: `${subtype}: ${detail}`, next_steps: threatSteps };
  }
}

/** Explains a log entry: whether it is a block, which layer did it and what to check next. */
export function classifyLogEntry(logType: LogType, e: Record<string, any>): Classification {
  switch (logType) {
    case "traffic":
      return classifyTraffic(e);
    case "threat":
    case "wildfire":
    case "data":
      return classifyThreat({ subtype: logType === "threat" ? str(e, "subtype") : logType, ...e }, logType);
    case "url": {
      const action = str(e, "action");
      const blocked = isBlockingAction("url", action);
      const cats = str(e, "url_category_list") || str(e, "category");
      return {
        blocked,
        layer: blocked ? "url-filtering" : "none",
        summary: `URL ${str(e, "misc")} categorized '${cats}', action ${action}, rule '${str(e, "rule")}'`,
        next_steps: blocked ? ["diagnose_url_access with this URL"] : [],
      };
    }
    case "decryption": {
      const error = str(e, "error") || str(e, "error_index");
      return {
        blocked: Boolean(error),
        layer: error ? "decryption" : "none",
        summary: error ? `Decryption failure: ${error}` : "Decryption log without error",
        next_steps: error ? ["Pinned certificates/mutual TLS usually need a no-decrypt rule for that destination"] : [],
      };
    }
    case "auth":
      return { blocked: false, layer: "authentication", summary: `Authentication event: ${str(e, "event") || str(e, "description")}`, next_steps: [] };
    case "globalprotect": {
      const failed = /fail/i.test(str(e, "status"));
      return {
        blocked: failed,
        layer: failed ? "globalprotect" : "none",
        summary: `GlobalProtect ${str(e, "eventid")} ${str(e, "stage")}: ${str(e, "status")} ${str(e, "error")}`.trim(),
        next_steps: failed ? ["gp_current_users on the gateway; check auth profile, certificate and HIP"] : [],
      };
    }
    default:
      return { blocked: false, layer: "none", summary: "", next_steps: [] };
  }
}
