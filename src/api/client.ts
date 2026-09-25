import { XMLParser } from "fast-xml-parser";
import { fetch } from "undici";
import { resolveFirewall, isMultiFirewall } from "../config/firewalls.js";
import { buildDispatcher, describeProxy } from "./proxy.js";
import { cancelled, remainingMs } from "../lib/budget.js";

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  // Keep values as strings: serial numbers have leading zeros and ports/IDs
  // must not be coerced into lossy numbers.
  parseTagValue: false,
  parseAttributeValue: false,
});

export interface ApiResponse {
  success: boolean;
  data?: any;
  error?: string;
  /** Log queries only: the job did not finish in time and data holds the logs received so far. */
  partial?: boolean;
}

/** Log query timeout in seconds (PANOS_LOG_TIMEOUT, default 120): large Panorama log searches are slow. */
function logTimeoutSeconds(): number {
  const value = Number(process.env.PANOS_LOG_TIMEOUT);
  return Number.isFinite(value) && value > 0 ? value : 120;
}

export interface FirewallTarget {
  host: string;
  apiKey: string;
  verifySSL: boolean;
}

export function resolveTarget(firewallParam?: string): FirewallTarget | ApiResponse {
  if (isMultiFirewall() && !firewallParam) {
    return {
      success: false,
      error: "Multiple firewalls configured. The 'firewall' parameter is required — use list_firewalls to see available names.",
    };
  }

  const entry = resolveFirewall(firewallParam);
  if (!entry) {
    if (firewallParam) {
      return {
        success: false,
        error: `Firewall '${firewallParam}' not found. Use list_firewalls to see available names.`,
      };
    }
    return {
      success: false,
      error: "No firewall configured. Set PANOS_HOST/PANOS_API_KEY environment variables or provide a firewalls.json config file.",
    };
  }

  return { host: entry.host, apiKey: entry.api_key, verifySSL: entry.verify_ssl };
}

export function isApiError(result: FirewallTarget | ApiResponse): result is ApiResponse {
  return "success" in result && !(result as any).host;
}

function connectError(error: unknown): string {
  const msg = error instanceof Error ? error.message : String(error);
  const cause = error instanceof Error && error.cause;
  const causeStr = cause instanceof Error ? cause.message : cause ? String(cause) : null;
  const proxy = describeProxy();
  const proxyStr = proxy ? ` [via ${proxy}]` : "";
  return `Error connecting to firewall: ${msg}${causeStr ? ` (${causeStr})` : ""}${proxyStr}`;
}

async function makeRequest(url: string, apiKey = "", verifySSL = false): Promise<ApiResponse> {
  const dispatcher = buildDispatcher(url, verifySSL);

  const headers: Record<string, string> = {};
  if (apiKey) headers["X-PAN-KEY"] = apiKey;

  const response = await fetch(url, {
    method: "GET",
    headers,
    dispatcher,
  });

  if (!response.ok) {
    return {
      success: false,
      error: `HTTP ${response.status} ${response.statusText}`,
    };
  }

  const xmlText = await response.text();

  let parsed: any;
  try {
    parsed = xmlParser.parse(xmlText);
  } catch (err) {
    return {
      success: false,
      error: `Failed to parse XML response: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (parsed.response?.["@_status"] === "error") {
    return {
      success: false,
      error: `PanOS API Error: ${JSON.stringify(parsed.response.msg || parsed.response)}`,
    };
  }

  return {
    success: true,
    data: parsed.response?.result ?? parsed.response?.msg ?? "OK",
  };
}

export async function generateApiKey(host: string, username: string, password: string): Promise<ApiResponse> {
  const url = `https://${host}/api/?type=keygen&user=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`;

  try {
    const result = await makeRequest(url);
    if (result.success && result.data?.key) {
      return { success: true, data: { key: result.data.key } };
    }
    return result;
  } catch (error) {
    return {
      success: false,
      error: connectError(error),
    };
  }
}

/**
 * Run an operational command. When `deviceSerial` is set and `target` is a
 * Panorama, the command is proxied by Panorama to that managed firewall
 * (`&target=<serial>`), so a single Panorama API key is enough.
 */
export async function executeOpCommand(cmd: string, target?: FirewallTarget, deviceSerial?: string): Promise<ApiResponse> {
  if (!target) {
    const resolved = resolveTarget();
    if (isApiError(resolved)) return resolved;
    target = resolved;
  }

  let url = `https://${target.host}/api/?type=op&cmd=${encodeURIComponent(cmd)}`;
  if (deviceSerial) {
    url += `&target=${encodeURIComponent(deviceSerial)}`;
  }

  try {
    return await makeRequest(url, target.apiKey, target.verifySSL);
  } catch (error) {
    return {
      success: false,
      error: connectError(error),
    };
  }
}

/** Time kept for the tool's own work (config analysis) after its log queries. */
const LOG_RESERVE_MS = 10_000;

export async function executeLogQuery(
  logType: string,
  nlogs: number,
  query: string | undefined,
  target: FirewallTarget
): Promise<ApiResponse> {
  if (remainingMs() < LOG_RESERVE_MS) {
    return { success: false, error: "Log query skipped: no time left in this tool call (client timeout). Narrow the time window or add filters." };
  }

  // Step 1: Submit log query (type=log)
  let url = `https://${target.host}/api/?type=log&log-type=${encodeURIComponent(logType)}&nlogs=${nlogs}`;
  if (query) {
    url += `&query=${encodeURIComponent(query)}`;
  }

  let submitResult: ApiResponse;
  try {
    submitResult = await makeRequest(url, target.apiKey, target.verifySSL);
  } catch (error) {
    return {
      success: false,
      error: `Error submitting log query: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  if (!submitResult.success) return submitResult;

  const jobId = submitResult.data?.job;
  if (!jobId) {
    return { success: false, error: "No job ID returned from log query" };
  }

  // Step 2: Poll for results (type=log&action=get)
  const pollUrl = `https://${target.host}/api/?type=log&action=get&job-id=${jobId}`;
  const maxAttempts = logTimeoutSeconds();
  const pollIntervalMs = 1000;
  let lastLogs: any;
  let outOfBudget = false;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    // Stop before the client gives up on the tool call, or as soon as it cancels it.
    if (remainingMs() < LOG_RESERVE_MS) {
      outOfBudget = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));

    let pollResult: ApiResponse;
    try {
      pollResult = await makeRequest(pollUrl, target.apiKey, target.verifySSL);
    } catch (error) {
      return {
        success: false,
        error: `Error polling log results: ${error instanceof Error ? error.message : String(error)}`,
      };
    }

    if (!pollResult.success) return pollResult;

    const status = pollResult.data?.job?.status || pollResult.data?.log?.logs?.["@_progress"];
    if (status === "FIN" || pollResult.data?.log?.logs?.["@_progress"] === "100") {
      return { success: true, data: pollResult.data?.log?.logs };
    }
    lastLogs = pollResult.data?.log?.logs ?? lastLogs;
  }

  // Stop the job on Panorama so abandoned queries do not keep loading the log collectors.
  makeRequest(`https://${target.host}/api/?type=log&action=finish&job-id=${jobId}`, target.apiKey, target.verifySSL).catch(() => undefined);

  if (lastLogs?.entry) return { success: true, data: lastLogs, partial: true };
  return {
    success: false,
    error: cancelled()
      ? `Log query cancelled by the client (job ${jobId}).`
      : outOfBudget
        ? `Log query stopped to answer before the client timeout (job ${jobId}). Narrow the time window (incident_time) or add filters (src_ip, user).`
        : `Log query timed out after ${maxAttempts} seconds (job ${jobId}). Narrow the time window (incident_time or a shorter period) or add filters (src_ip, user).`,
  };
}

/** Reads config; with `deviceSerial`, Panorama proxies the request to that managed firewall. */
export async function getConfig(xpath: string, target?: FirewallTarget, deviceSerial?: string): Promise<ApiResponse> {
  if (!target) {
    const resolved = resolveTarget();
    if (isApiError(resolved)) return resolved;
    target = resolved;
  }

  let url = `https://${target.host}/api/?type=config&action=get&xpath=${encodeURIComponent(xpath)}`;
  if (deviceSerial) url += `&target=${encodeURIComponent(deviceSerial)}`;

  try {
    return await makeRequest(url, target.apiKey, target.verifySSL);
  } catch (error) {
    return {
      success: false,
      error: connectError(error),
    };
  }
}

/** Reads the running (committed) configuration, unlike getConfig which reads the candidate. */
export async function showConfig(xpath: string, target?: FirewallTarget): Promise<ApiResponse> {
  if (!target) {
    const resolved = resolveTarget();
    if (isApiError(resolved)) return resolved;
    target = resolved;
  }

  const url = `https://${target.host}/api/?type=config&action=show&xpath=${encodeURIComponent(xpath)}`;

  try {
    return await makeRequest(url, target.apiKey, target.verifySSL);
  } catch (error) {
    return {
      success: false,
      error: connectError(error),
    };
  }
}

export async function setConfig(xpath: string, element: string, target?: FirewallTarget): Promise<ApiResponse> {
  if (!target) {
    const resolved = resolveTarget();
    if (isApiError(resolved)) return resolved;
    target = resolved;
  }

  const url = `https://${target.host}/api/?type=config&action=set&xpath=${encodeURIComponent(xpath)}&element=${encodeURIComponent(element)}`;

  try {
    return await makeRequest(url, target.apiKey, target.verifySSL);
  } catch (error) {
    return {
      success: false,
      error: connectError(error),
    };
  }
}

export async function deleteConfig(xpath: string, target?: FirewallTarget): Promise<ApiResponse> {
  if (!target) {
    const resolved = resolveTarget();
    if (isApiError(resolved)) return resolved;
    target = resolved;
  }

  const url = `https://${target.host}/api/?type=config&action=delete&xpath=${encodeURIComponent(xpath)}`;

  try {
    return await makeRequest(url, target.apiKey, target.verifySSL);
  } catch (error) {
    return {
      success: false,
      error: connectError(error),
    };
  }
}

export async function moveConfig(xpath: string, where: string, dst?: string, target?: FirewallTarget): Promise<ApiResponse> {
  if (!target) {
    const resolved = resolveTarget();
    if (isApiError(resolved)) return resolved;
    target = resolved;
  }

  let url = `https://${target.host}/api/?type=config&action=move&xpath=${encodeURIComponent(xpath)}&where=${encodeURIComponent(where)}`;
  if (dst) {
    url += `&dst=${encodeURIComponent(dst)}`;
  }

  try {
    return await makeRequest(url, target.apiKey, target.verifySSL);
  } catch (error) {
    return {
      success: false,
      error: connectError(error),
    };
  }
}

export async function commitConfig(cmd: string, target?: FirewallTarget): Promise<ApiResponse> {
  if (!target) {
    const resolved = resolveTarget();
    if (isApiError(resolved)) return resolved;
    target = resolved;
  }

  const url = `https://${target.host}/api/?type=commit&cmd=${encodeURIComponent(cmd)}`;

  try {
    return await makeRequest(url, target.apiKey, target.verifySSL);
  } catch (error) {
    return {
      success: false,
      error: connectError(error),
    };
  }
}

export async function commitAll(cmd: string, target?: FirewallTarget): Promise<ApiResponse> {
  if (!target) {
    const resolved = resolveTarget();
    if (isApiError(resolved)) return resolved;
    target = resolved;
  }

  const url = `https://${target.host}/api/?type=commit&action=all&cmd=${encodeURIComponent(cmd)}`;

  try {
    return await makeRequest(url, target.apiKey, target.verifySSL);
  } catch (error) {
    return {
      success: false,
      error: connectError(error),
    };
  }
}

export function formatResponse(result: ApiResponse): { content: Array<{ type: "text"; text: string }> } {
  if (!result.success) {
    return {
      content: [{ type: "text", text: `Error: ${result.error}` }],
    };
  }

  // Raw config dumps can reach hundreds of KB, which MCP clients spill to files.
  const MAX_CHARS = 40_000;
  let text = JSON.stringify(result.data, null, 2);
  if (text.length > MAX_CHARS) {
    text = `${text.slice(0, MAX_CHARS)}\n... [TRUNCATED: ${text.length} chars total. Use a narrower XPath or the debug/diagnose tools.]`;
  }
  return {
    content: [{ type: "text", text }],
  };
}
