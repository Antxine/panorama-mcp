import { executeOpCommand, showConfig, type FirewallTarget } from "./client.js";

/** Panorama's own config root. */
export const PANORAMA_ROOT = "/config/devices/entry[@name='localhost.localdomain']";

const CACHE_TTL_MS = 5 * 60 * 1000;

/** Normalizes fast-xml-parser output (single object, array or undefined) into an array. */
export function asArray<T = any>(value: T | T[] | undefined | null): T[] {
  if (value === undefined || value === null || value === "") return [];
  return Array.isArray(value) ? value : [value];
}

/** Text of a parsed XML node, whether it is a plain string or an object with attributes. */
export function nodeText(value: any): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "object") return String(value["#text"] ?? "");
  return String(value);
}

/** Extracts `<member>` values from a parsed node like `{ member: [...] }`. */
export function memberList(node: any): string[] {
  if (!node || typeof node !== "object") return [];
  return asArray(node.member).map(nodeText).filter(Boolean);
}

/**
 * XPath for the config location of a device group, or `/config/shared` for "shared".
 * Names are validated by the tool schemas (no quotes), this is a last-resort guard.
 */
export function locationXpath(deviceGroup: string): string {
  if (deviceGroup === "shared") return "/config/shared";
  if (deviceGroup.includes("'")) throw new Error(`Invalid device group name: ${deviceGroup}`);
  return `${PANORAMA_ROOT}/device-group/entry[@name='${deviceGroup}']`;
}

export interface ManagedDevice {
  serial: string;
  hostname: string;
  ip: string;
  model: string;
  swVersion: string;
  connected: boolean;
  haState?: string;
  /** Panorama's view of pushed policy/template state ("In Sync", "Out of Sync", ...). */
  policySync?: string;
  templateSync?: string;
}

export interface DeviceGroupInfo {
  name: string;
  devices: Array<{ serial: string; hostname: string }>;
}

const deviceCache = new Map<string, { at: number; devices: ManagedDevice[] }>();
const dgCache = new Map<string, { at: number; groups: DeviceGroupInfo[] }>();

function unwrap<T>(result: { success: boolean; data?: any; error?: string }, pick: (data: any) => T): T {
  if (!result.success) throw new Error(result.error ?? "Unknown PanOS error");
  return pick(result.data);
}

/** Managed firewalls as seen by Panorama (`show devices all`), cached for 5 minutes. */
export async function listManagedDevices(target: FirewallTarget, refresh = false): Promise<ManagedDevice[]> {
  const cached = deviceCache.get(target.host);
  if (!refresh && cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.devices;

  const result = await executeOpCommand("<show><devices><all></all></devices></show>", target);
  const devices = unwrap(result, (data) =>
    asArray(data?.devices?.entry).map((e: any): ManagedDevice => ({
      serial: nodeText(e.serial ?? e["@_name"]),
      hostname: nodeText(e.hostname),
      ip: nodeText(e["ip-address"]),
      model: nodeText(e.model),
      swVersion: nodeText(e["sw-version"]),
      connected: nodeText(e.connected) === "yes",
      haState: e.ha?.state ? nodeText(e.ha.state) : undefined,
      policySync: e["shared-policy-status"] ? nodeText(e["shared-policy-status"]) : undefined,
      templateSync: e["template-status"] ? nodeText(e["template-status"]) : undefined,
    }))
  );
  deviceCache.set(target.host, { at: Date.now(), devices });
  return devices;
}

/**
 * Resolves a managed firewall given its serial or hostname (case-insensitive).
 * Throws with the list of close candidates when nothing or several devices match.
 */
export async function resolveDevice(target: FirewallTarget, device: string): Promise<ManagedDevice> {
  const devices = await listManagedDevices(target);
  const needle = device.trim().toLowerCase();

  const exact = devices.find((d) => d.serial === device.trim() || d.hostname.toLowerCase() === needle);
  if (exact) return exact;

  const partial = devices.filter((d) => d.hostname.toLowerCase().includes(needle));
  if (partial.length === 1) return partial[0];

  const hint = partial.length
    ? `Several devices match '${device}': ${partial.map((d) => `${d.hostname} (${d.serial})`).join(", ")}`
    : `No managed device matches '${device}'. Use panorama_list_firewalls to see available devices.`;
  throw new Error(hint);
}

/** Device groups and their member firewalls (`show devicegroups`), cached for 5 minutes. */
export async function listDeviceGroups(target: FirewallTarget, refresh = false): Promise<DeviceGroupInfo[]> {
  const cached = dgCache.get(target.host);
  if (!refresh && cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.groups;

  const result = await executeOpCommand("<show><devicegroups></devicegroups></show>", target);
  const groups = unwrap(result, (data) =>
    asArray(data?.devicegroups?.entry).map((g: any): DeviceGroupInfo => ({
      name: nodeText(g["@_name"]),
      devices: asArray(g.devices?.entry).map((d: any) => ({
        serial: nodeText(d.serial ?? d["@_name"]),
        hostname: nodeText(d.hostname),
      })),
    }))
  );
  dgCache.set(target.host, { at: Date.now(), groups });
  return groups;
}

/** Device group names to search: the requested one, or "shared" plus every device group. */
export async function locationsToSearch(target: FirewallTarget, deviceGroup?: string): Promise<string[]> {
  if (deviceGroup) return [deviceGroup];
  const groups = await listDeviceGroups(target);
  return ["shared", ...groups.map((g) => g.name)];
}

/** Reads `<location>/<relative>` from the running config and returns its `entry` list. */
export async function readEntries(target: FirewallTarget, deviceGroup: string, relative: string): Promise<any[]> {
  const xpath = `${locationXpath(deviceGroup)}/${relative}`;
  const result = await showConfig(xpath, target);
  if (!result.success) {
    // An empty or missing node is reported as an error by some PAN-OS versions.
    if (/No such node|not present/i.test(result.error ?? "")) return [];
    throw new Error(result.error);
  }
  const leaf = relative.split("/").pop()!;
  const node = result.data?.[leaf] ?? result.data;
  return asArray(node?.entry);
}

/** Compact JSON tool response; keeps token usage low compared to indented output. */
export function jsonResponse(data: unknown): { content: Array<{ type: "text"; text: string }> } {
  return { content: [{ type: "text", text: JSON.stringify(data) }] };
}

export function errorResponse(error: unknown): { content: Array<{ type: "text"; text: string }> } {
  return { content: [{ type: "text", text: `Error: ${error instanceof Error ? error.message : String(error)}` }] };
}
