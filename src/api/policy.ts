import { executeOpCommand, getConfig, type FirewallTarget } from "./client.js";
import { asArray, listDeviceGroups, memberList, nodeText, readEntries } from "./panorama.js";

export interface CustomUrlCategory {
  location: string;
  name: string;
  type: string;
  description?: string;
  /** URL entries for "URL List" categories, PAN-DB categories for "Category Match" ones. */
  list: string[];
}

export type Rulebase = "pre" | "post";
export type PolicyType = "security" | "decryption";

export interface RuleSummary {
  location: string;
  rulebase: Rulebase;
  policy: PolicyType;
  /** Position within its location/rulebase, 1-based. */
  position: number;
  name: string;
  disabled: boolean;
  action: string;
  from: string[];
  to: string[];
  source: string[];
  destination: string[];
  sourceUser: string[];
  application: string[];
  service: string[];
  category: string[];
  negateSource: boolean;
  negateDestination: boolean;
  /** Serials this rule is restricted to (empty = all devices of the device group). */
  targetDevices: string[];
  targetNegate: boolean;
  profileGroup?: string;
  /** Profiles set directly on the rule, by type (virus, spyware, url-filtering, file-blocking, ...). */
  profiles: Record<string, string>;
  /** Log forwarding profile; without one, the rule's logs never reach Panorama. */
  logSetting?: string;
  logEnd: boolean;
  schedule?: string;
  sourceHip: string[];
  destinationHip: string[];
  description?: string;
  tags: string[];
}

export interface UrlFilteringProfile {
  location: string;
  name: string;
  /** Site access action per category; categories not listed default to "allow". */
  actions: Record<string, string>;
  /** User credential submission action per category, when configured. */
  credentialActions: Record<string, string>;
}

/** Security profile types as named in the PAN-OS config (`profile-setting/profiles/<type>`). */
export const PROFILE_TYPES = [
  "virus", "spyware", "vulnerability", "url-filtering", "file-blocking", "wildfire-analysis", "data-filtering",
] as const;
export type ProfileType = (typeof PROFILE_TYPES)[number];

export interface ProfileGroup {
  location: string;
  name: string;
  profiles: Record<string, string>;
}

const URL_ACTIONS = ["alert", "allow", "block", "continue", "override"];

export async function fetchCustomUrlCategories(target: FirewallTarget, locations: string[]): Promise<CustomUrlCategory[]> {
  const perLocation = await Promise.all(
    locations.map(async (location) =>
      (await readEntries(target, location, "profiles/custom-url-category")).map((e: any) => ({
        location,
        name: nodeText(e["@_name"]),
        type: nodeText(e.type) || "URL List",
        description: nodeText(e.description) || undefined,
        list: memberList(e.list),
      }))
    )
  );
  return perLocation.flat();
}

function yes(value: any): boolean {
  return nodeText(value) === "yes";
}

function toRuleSummary(e: any, location: string, rulebase: Rulebase, policy: PolicyType, position: number): RuleSummary {
  const profileSetting = e["profile-setting"] ?? {};
  const profiles: Record<string, string> = {};
  for (const type of PROFILE_TYPES) {
    const name = memberList(profileSetting.profiles?.[type])[0];
    if (name) profiles[type] = name;
  }
  return {
    location,
    rulebase,
    policy,
    position,
    name: nodeText(e["@_name"]),
    disabled: yes(e.disabled),
    action: nodeText(e.action) || (policy === "decryption" ? "" : "allow"),
    from: memberList(e.from),
    to: memberList(e.to),
    source: memberList(e.source),
    destination: memberList(e.destination),
    sourceUser: memberList(e["source-user"]),
    application: memberList(e.application),
    service: memberList(e.service),
    category: memberList(e.category),
    negateSource: yes(e["negate-source"]),
    negateDestination: yes(e["negate-destination"]),
    targetDevices: asArray(e.target?.devices?.entry).map((d: any) => nodeText(d["@_name"])),
    targetNegate: yes(e.target?.negate),
    profileGroup: memberList(profileSetting.group)[0],
    profiles,
    logSetting: nodeText(e["log-setting"]) || undefined,
    // Security rules log at session end unless explicitly disabled.
    logEnd: nodeText(e["log-end"]) !== "no",
    schedule: nodeText(e.schedule) || undefined,
    sourceHip: memberList(e["source-hip"]),
    destinationHip: memberList(e["destination-hip"]),
    description: nodeText(e.description) || undefined,
    tags: memberList(e.tag),
  };
}

export async function fetchRules(
  target: FirewallTarget,
  locations: string[],
  policies: PolicyType[] = ["security"],
  rulebases: Rulebase[] = ["pre", "post"]
): Promise<RuleSummary[]> {
  const jobs: Array<Promise<RuleSummary[]>> = [];
  for (const location of locations) {
    for (const rulebase of rulebases) {
      for (const policy of policies) {
        jobs.push(
          readEntries(target, location, `${rulebase}-rulebase/${policy}/rules`).then((entries) =>
            entries.map((e, i) => toRuleSummary(e, location, rulebase, policy, i + 1))
          )
        );
      }
    }
  }
  return (await Promise.all(jobs)).flat();
}

export async function fetchUrlFilteringProfiles(target: FirewallTarget, locations: string[]): Promise<UrlFilteringProfile[]> {
  const perLocation = await Promise.all(
    locations.map(async (location) =>
      (await readEntries(target, location, "profiles/url-filtering")).map((e: any): UrlFilteringProfile => {
        const actions: Record<string, string> = {};
        const credentialActions: Record<string, string> = {};
        for (const action of URL_ACTIONS) {
          for (const cat of memberList(e[action])) actions[cat] = action;
          for (const cat of memberList(e["credential-enforcement"]?.[action])) credentialActions[cat] = action;
        }
        return { location, name: nodeText(e["@_name"]), actions, credentialActions };
      })
    )
  );
  return perLocation.flat();
}

export async function fetchProfileGroups(target: FirewallTarget, locations: string[]): Promise<ProfileGroup[]> {
  const perLocation = await Promise.all(
    locations.map(async (location) =>
      (await readEntries(target, location, "profile-group")).map((e: any) => {
        const profiles: Record<string, string> = {};
        for (const type of PROFILE_TYPES) {
          const name = memberList(e[type])[0];
          if (name) profiles[type] = name;
        }
        return { location, name: nodeText(e["@_name"]), profiles };
      })
    )
  );
  return perLocation.flat();
}

/**
 * Parent chain of every device group, from the read-only config (`parent-dg`), falling back
 * to `show dg-hierarchy` (nested `<dg name="...">`). Maps a device group to its ancestors, closest last.
 */
export async function fetchDgAncestors(target: FirewallTarget): Promise<Map<string, string[]>> {
  const ancestors = new Map<string, string[]>();

  // Preferred source: the read-only config lists each device group with its parent.
  const readonly = await getConfig(`/config/readonly/devices/entry[@name='localhost.localdomain']/device-group`, target);
  if (readonly.success) {
    const parents = new Map<string, string>();
    for (const e of asArray(readonly.data?.["device-group"]?.entry)) {
      const name = nodeText(e["@_name"]);
      const parent = nodeText(e["parent-dg"]);
      if (name) parents.set(name, parent);
    }
    for (const name of parents.keys()) {
      const chain: string[] = [];
      for (let p = parents.get(name); p && !chain.includes(p); p = parents.get(p)) chain.unshift(p);
      ancestors.set(name, chain);
    }
    if (ancestors.size) return ancestors;
  }

  const result = await executeOpCommand("<show><dg-hierarchy></dg-hierarchy></show>", target);
  if (!result.success) return ancestors;

  const walk = (nodes: any, parents: string[]) => {
    for (const dg of asArray(nodes)) {
      const name = nodeText(dg["@_name"]);
      if (!name) continue;
      ancestors.set(name, parents);
      walk(dg.dg, [...parents, name]);
    }
  };
  walk(result.data?.["dg-hierarchy"]?.dg, []);
  return ancestors;
}

export interface DeviceScope {
  deviceGroup?: string;
  /** Locations whose policies apply to the device, in evaluation order of pre-rules. */
  locations: string[];
}

/**
 * Config locations that apply to a managed device: shared, then ancestor device groups,
 * then its own device group. Falls back to every location when the device group is unknown.
 */
export async function scopeForDevice(target: FirewallTarget, serial: string): Promise<DeviceScope> {
  const groups = await listDeviceGroups(target);
  const group = groups.find((g) => g.devices.some((d) => d.serial === serial));
  if (!group) return { locations: ["shared", ...groups.map((g) => g.name)] };

  const ancestors = (await fetchDgAncestors(target)).get(group.name) ?? [];
  return { deviceGroup: group.name, locations: ["shared", ...ancestors, group.name] };
}

/** True when a rule's target restriction lets it apply to the given device. */
export function ruleAppliesToDevice(rule: RuleSummary, serial?: string): boolean {
  if (!serial || rule.targetDevices.length === 0) return true;
  const listed = rule.targetDevices.includes(serial);
  return rule.targetNegate ? !listed : listed;
}

/**
 * Sorts rules in Panorama evaluation order for the given scope:
 * pre-rules shared -> ancestors -> device group, then post-rules device group -> ancestors -> shared.
 */
export function sortByEvaluationOrder(rules: RuleSummary[], locations: string[]): RuleSummary[] {
  const rank = (r: RuleSummary) => {
    const idx = locations.indexOf(r.location);
    const locRank = r.rulebase === "pre" ? idx : locations.length * 2 - idx;
    return [r.policy === "security" ? 0 : 1, r.rulebase === "pre" ? 0 : 1, locRank, r.position];
  };
  return [...rules].sort((a, b) => {
    const ra = rank(a);
    const rb = rank(b);
    for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) return ra[i] - rb[i];
    return 0;
  });
}

/** Short one-line-ish view of a rule for tool output. */
export function compactRule(r: RuleSummary): Record<string, unknown> {
  const out: Record<string, unknown> = {
    rule: r.name,
    where: `${r.location}/${r.rulebase}-${r.policy}#${r.position}`,
    action: r.action,
  };
  if (r.disabled) out.disabled = true;
  const lists: Array<[string, string[], boolean?]> = [
    ["from", r.from],
    ["to", r.to],
    ["source", r.source, r.negateSource],
    ["destination", r.destination, r.negateDestination],
    ["source_user", r.sourceUser],
    ["application", r.application],
    ["service", r.service],
    ["category", r.category],
  ];
  for (const [key, values, negate] of lists) {
    if (values.length && !(values.length === 1 && values[0] === "any")) out[key] = negate ? { not: values } : values;
  }
  if (r.targetDevices.length) out.target_devices = r.targetNegate ? { not: r.targetDevices } : r.targetDevices;
  if (r.profileGroup) out.profile_group = r.profileGroup;
  if (Object.keys(r.profiles).length) out.profiles = r.profiles;
  for (const [key, values] of [["source_hip", r.sourceHip], ["destination_hip", r.destinationHip]] as const) {
    if (values.length && !(values.length === 1 && values[0] === "any")) out[key] = values;
  }
  if (r.schedule) out.schedule = r.schedule;
  if (r.policy === "security") {
    if (!r.logSetting) out.log_forwarding = "none (logs not forwarded to Panorama)";
    if (!r.logEnd) out.log_at_session_end = false;
  }
  if (r.description) out.description = r.description;
  return out;
}

/**
 * Picks the object visible from the most specific location: device group first, then
 * its ancestors, then shared (same override logic as Panorama).
 */
export function findInScope<T extends { location: string; name: string }>(
  items: T[],
  name: string,
  locations: string[]
): T | undefined {
  for (let i = locations.length - 1; i >= 0; i--) {
    const hit = items.find((it) => it.name === name && it.location === locations[i]);
    if (hit) return hit;
  }
  return items.find((it) => it.name === name);
}

/** Security profiles effectively applied by a rule (profile group resolved), by type. */
export function effectiveProfiles(rule: RuleSummary, groups: ProfileGroup[], locations: string[]): Record<string, string> {
  if (rule.profileGroup) {
    const group = findInScope(groups, rule.profileGroup, locations);
    return { ...(group?.profiles ?? {}) };
  }
  return { ...rule.profiles };
}

export interface ThreatException {
  threatId: string;
  action: string;
  exemptIps: string[];
}

export interface ThreatProfile {
  location: string;
  type: "virus" | "spyware" | "vulnerability";
  name: string;
  threatExceptions: ThreatException[];
  /** Antivirus only: per-application action overrides. */
  applicationExceptions: Array<{ application: string; action: string }>;
  /** Antivirus only: action per decoder (http, smtp, ...), signature and WildFire. */
  decoders: Array<{ decoder: string; action: string; wildfireAction: string }>;
}

function firstKey(node: any): string {
  if (!node || typeof node !== "object") return nodeText(node);
  const key = Object.keys(node).find((k) => !k.startsWith("@_") && k !== "#text");
  return key ?? "";
}

export async function fetchThreatProfiles(
  target: FirewallTarget,
  locations: string[],
  types: Array<ThreatProfile["type"]> = ["virus", "spyware", "vulnerability"]
): Promise<ThreatProfile[]> {
  const jobs: Array<Promise<ThreatProfile[]>> = [];
  for (const location of locations) {
    for (const type of types) {
      jobs.push(
        readEntries(target, location, `profiles/${type}`).then((entries) =>
          entries.map((e: any): ThreatProfile => ({
            location,
            type,
            name: nodeText(e["@_name"]),
            threatExceptions: asArray(e["threat-exception"]?.entry).map((t: any) => ({
              threatId: nodeText(t["@_name"]),
              // Action is a single child element (<default/>, <allow/>, ...).
              action: firstKey(t.action) || "default",
              exemptIps: asArray(t["exempt-ip"]?.entry).map((ip: any) => nodeText(ip["@_name"])),
            })),
            applicationExceptions: asArray(e["application-exception"]?.entry).map((a: any) => ({
              application: nodeText(a["@_name"]),
              action: nodeText(a.action),
            })),
            decoders: asArray(e.decoder?.entry).map((d: any) => ({
              decoder: nodeText(d["@_name"]),
              action: nodeText(d.action),
              wildfireAction: nodeText(d["wildfire-action"]),
            })),
          }))
        )
      );
    }
  }
  return (await Promise.all(jobs)).flat();
}

export interface FileBlockingProfile {
  location: string;
  name: string;
  rules: Array<{ name: string; application: string[]; fileType: string[]; direction: string; action: string }>;
}

export async function fetchFileBlockingProfiles(target: FirewallTarget, locations: string[]): Promise<FileBlockingProfile[]> {
  const perLocation = await Promise.all(
    locations.map(async (location) =>
      (await readEntries(target, location, "profiles/file-blocking")).map((e: any): FileBlockingProfile => ({
        location,
        name: nodeText(e["@_name"]),
        rules: asArray(e.rules?.entry).map((r: any) => ({
          name: nodeText(r["@_name"]),
          application: memberList(r.application),
          fileType: memberList(r["file-type"]),
          direction: nodeText(r.direction) || "both",
          action: nodeText(r.action) || "alert",
        })),
      }))
    )
  );
  return perLocation.flat();
}
