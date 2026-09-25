import type { FirewallTarget } from "./client.js";
import { getConfig } from "./client.js";
import { asArray, memberList, nodeText, readEntries } from "./panorama.js";
import { explainApiError } from "./ops.js";

export interface AppInfo {
  name: string;
  category?: string;
  subcategory?: string;
  technology?: string;
  risk?: string;
  tags: string[];
}

export interface AppContainer {
  kind: "application-group" | "application-filter" | "custom-application";
  name: string;
  location: string;
  /** Group members, or filter criteria. */
  definition: Record<string, string[] | string>;
}

/** Predefined App-ID attributes, from Panorama's predefined config. */
/** Predefined App-ID from Panorama's content, or from a managed firewall's with `deviceSerial`. */
export async function predefinedApp(target: FirewallTarget, name: string, deviceSerial?: string): Promise<AppInfo | undefined> {
  if (name.includes("'")) return undefined;
  const result = await getConfig(`/config/predefined/application/entry[@name='${name}']`, target, deviceSerial);
  if (!result.success) {
    if (/not authorized/i.test(result.error ?? "")) throw new Error(explainApiError(result.error));
    return undefined;
  }
  const e = result.data?.entry;
  if (!e) return undefined;
  return {
    name,
    category: nodeText(e.category) || undefined,
    subcategory: nodeText(e.subcategory) || undefined,
    technology: nodeText(e.technology) || undefined,
    risk: nodeText(e.risk) || undefined,
    tags: [...memberList(e.tags), ...memberList(e.tag)],
  };
}

const FILTER_DIMENSIONS = ["category", "subcategory", "technology", "risk"] as const;

/** Whether an application filter includes an application (AND across dimensions, OR within one). */
export function filterMatchesApp(definition: Record<string, string[] | string>, app: AppInfo): boolean {
  if (asArray(definition.exclude as string[]).includes(app.name)) return false;
  let constrained = false;
  for (const dim of FILTER_DIMENSIONS) {
    const allowed = asArray(definition[dim] as string[]);
    if (!allowed.length) continue;
    constrained = true;
    if (!app[dim] || !allowed.includes(app[dim]!)) return false;
  }
  const tags = asArray(definition.tags as string[]);
  if (tags.length) {
    constrained = true;
    if (!tags.some((t) => app.tags.includes(t))) return false;
  }
  return constrained;
}

export async function fetchAppContainers(target: FirewallTarget, locations: string[]): Promise<AppContainer[]> {
  const perLocation = await Promise.all(
    locations.map(async (location) => {
      const [groups, filters, customApps] = await Promise.all([
        readEntries(target, location, "application-group"),
        readEntries(target, location, "application-filter"),
        readEntries(target, location, "application"),
      ]);
      return [
        ...customApps.map((a: any): AppContainer => {
          const definition: Record<string, string[] | string> = {};
          for (const key of ["category", "subcategory", "technology", "risk", "description", "default"]) {
            const value = key === "default" ? JSON.stringify(a.default ?? "") : nodeText(a[key]);
            if (value && value !== '""') definition[key] = value;
          }
          if (a.signature) definition.signatures = asArray(a.signature?.entry).map((sig: any) => nodeText(sig["@_name"]));
          return { kind: "custom-application", name: nodeText(a["@_name"]), location, definition };
        }),
        ...groups.map((g: any): AppContainer => ({
          kind: "application-group",
          name: nodeText(g["@_name"]),
          location,
          definition: { members: memberList(g.members ?? g) },
        })),
        ...filters.map((f: any): AppContainer => {
          const definition: Record<string, string[] | string> = {};
          for (const dim of FILTER_DIMENSIONS) {
            const values = memberList(f[dim]);
            if (values.length) definition[dim] = values;
          }
          const tags = memberList(f.tagging?.tag);
          if (tags.length) definition.tags = tags;
          const exclude = memberList(f.exclude);
          if (exclude.length) definition.exclude = exclude;
          for (const flag of ["evasive", "excessive-bandwidth-use", "used-by-malware", "transfers-files", "has-known-vulnerabilities", "tunnels-other-apps", "prone-to-misuse", "pervasive", "is-saas", "new-appid"]) {
            if (nodeText(f[flag]) === "yes") definition[flag] = "yes";
          }
          return { kind: "application-filter", name: nodeText(f["@_name"]), location, definition };
        }),
      ];
    })
  );
  return perLocation.flat();
}

/** Groups (recursively) and filters that contain an application. */
export function containersOf(app: AppInfo, containers: AppContainer[]): AppContainer[] {
  const found = new Set<AppContainer>();
  const names = new Set([app.name]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const c of containers) {
      if (found.has(c) || c.kind === "custom-application") continue;
      const hit =
        c.kind === "application-group"
          ? asArray(c.definition.members as string[]).some((m) => names.has(m))
          : filterMatchesApp(c.definition, app);
      if (hit) {
        found.add(c);
        names.add(c.name);
        grew = true;
      }
    }
  }
  return [...found];
}
