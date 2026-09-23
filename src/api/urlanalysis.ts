import type { FirewallTarget } from "./client.js";
import { locationsToSearch, resolveDevice, type ManagedDevice } from "./panorama.js";
import { testUrl } from "./ops.js";
import {
  compactRule,
  effectiveProfiles,
  fetchCustomUrlCategories,
  fetchProfileGroups,
  fetchRules,
  fetchUrlFilteringProfiles,
  ruleAppliesToDevice,
  scopeForDevice,
  sortByEvaluationOrder,
  type CustomUrlCategory,
  type RuleSummary,
} from "./policy.js";
import { matchEntries } from "../lib/urlmatch.js";

export interface Scope {
  device?: ManagedDevice;
  deviceGroup?: string;
  locations: string[];
}

export async function resolveScope(target: FirewallTarget, device?: string, deviceGroup?: string): Promise<Scope> {
  if (device) {
    const dev = await resolveDevice(target, device);
    const scope = await scopeForDevice(target, dev.serial);
    return { device: dev, ...scope };
  }
  return { deviceGroup, locations: await locationsToSearch(target, deviceGroup) };
}

export interface CategoryHit {
  category: string;
  location: string;
  entries: string[];
}

export interface UrlAnalysis {
  url: string;
  covering: CategoryHit[];
  related: CategoryHit[];
  categoryMatch: CategoryHit[];
  panDb?: { categories: string[]; lines: string[] };
  panDbError?: string;
  /** Every category the URL most likely belongs to (custom first, then PAN-DB). */
  effectiveCategories: string[];
}

/** Which custom categories (and PAN-DB categories when a device is known) cover a URL. */
export async function analyzeUrl(
  target: FirewallTarget,
  url: string,
  scope: Scope,
  categories?: CustomUrlCategory[]
): Promise<UrlAnalysis> {
  const [cats, panDbResult] = await Promise.all([
    categories ?? fetchCustomUrlCategories(target, scope.locations),
    scope.device
      ? testUrl(target, scope.device.serial, url).then(
          (r) => ({ ok: true as const, r }),
          (err) => ({ ok: false as const, err: err instanceof Error ? err.message : String(err) })
        )
      : Promise.resolve(undefined),
  ]);

  const covering: CategoryHit[] = [];
  const related: CategoryHit[] = [];
  for (const c of cats.filter((c) => c.type !== "Category Match")) {
    const hits = matchEntries(url, c.list);
    const matched = hits.filter((h) => h.kind === "match").map((h) => h.entry);
    if (matched.length) covering.push({ category: c.name, location: c.location, entries: matched });
    else if (hits.length) related.push({ category: c.name, location: c.location, entries: hits.map((h) => h.entry) });
  }

  const panDb = panDbResult?.ok ? panDbResult.r : undefined;
  const categoryMatch: CategoryHit[] = [];
  if (panDb) {
    for (const c of cats.filter((c) => c.type === "Category Match")) {
      // "Category Match" requires the URL to belong to every listed PAN-DB category.
      if (c.list.length && c.list.every((pc) => panDb.categories.includes(pc))) {
        categoryMatch.push({ category: c.name, location: c.location, entries: c.list });
      }
    }
  }

  const effectiveCategories = [
    ...new Set([...covering.map((c) => c.category), ...categoryMatch.map((c) => c.category), ...(panDb?.categories ?? [])]),
  ];
  return {
    url,
    covering,
    related,
    categoryMatch,
    panDb,
    panDbError: panDbResult && !panDbResult.ok ? panDbResult.err : undefined,
    effectiveCategories,
  };
}

export interface CategoryUsage {
  rules: RuleSummary[];
  profiles: Array<{
    profile: string;
    location: string;
    actions: Record<string, string>;
    credential_actions: Record<string, string>;
    used_by_rules: string[];
  }>;
}

/** Security/decryption rules referencing the categories, and URL filtering profiles acting on them. */
export async function categoryUsage(
  target: FirewallTarget,
  categories: string[],
  scope: Scope
): Promise<CategoryUsage> {
  const [rules, profiles, groups] = await Promise.all([
    fetchRules(target, scope.locations, ["security", "decryption"]),
    fetchUrlFilteringProfiles(target, scope.locations),
    fetchProfileGroups(target, scope.locations),
  ]);
  const serial = scope.device?.serial;
  const applicable = rules.filter((r) => ruleAppliesToDevice(r, serial));
  const wanted = new Set(categories);

  const referencing = sortByEvaluationOrder(
    applicable.filter((r) => r.category.some((c) => wanted.has(c))),
    scope.locations
  );

  const usage: CategoryUsage["profiles"] = [];
  for (const p of profiles) {
    const actions: Record<string, string> = {};
    const credential: Record<string, string> = {};
    for (const c of categories) {
      if (p.actions[c]) actions[c] = p.actions[c];
      if (p.credentialActions[c]) credential[c] = p.credentialActions[c];
    }
    if (!Object.keys(actions).length && !Object.keys(credential).length) continue;
    const usedBy = applicable
      .filter((r) => r.policy === "security" && !r.disabled && effectiveProfiles(r, groups, scope.locations)["url-filtering"] === p.name)
      .map((r) => `${r.location}/${r.rulebase}:${r.name}`);
    usage.push({ profile: p.name, location: p.location, actions, credential_actions: credential, used_by_rules: usedBy });
  }
  return { rules: referencing, profiles: usage };
}

/** Deterministic conclusions for a URL, so the model does not suggest duplicating existing config. */
export function urlFindings(analysis: UrlAnalysis, usage: CategoryUsage, scope: Scope): string[] {
  const f: string[] = [];
  const customNames = [...analysis.covering, ...analysis.categoryMatch].map((c) => c.category);

  if (analysis.covering.length) {
    f.push(
      `ALREADY COVERED: the URL matches existing custom URL categor${analysis.covering.length > 1 ? "ies" : "y"} ` +
        analysis.covering.map((c) => `'${c.category}' (${c.location}, entry ${c.entries.map((e) => `'${e}'`).join(", ")})`).join("; ") +
        ". Do NOT propose creating a new category: find why the policy using it does not apply."
    );
  }
  if (analysis.categoryMatch.length) {
    f.push(`The URL also falls in 'Category Match' custom categor${analysis.categoryMatch.length > 1 ? "ies" : "y"}: ${analysis.categoryMatch.map((c) => `'${c.category}'`).join(", ")}.`);
  }
  if (analysis.related.length) {
    f.push(
      "Existing categories contain entries for the same domain that do NOT match this exact URL: " +
        analysis.related.map((c) => `'${c.category}' (${c.location}: ${c.entries.slice(0, 5).map((e) => `'${e}'`).join(", ")})`).join("; ") +
        ". If the intent was to cover this URL, fix the entry pattern in that EXISTING category (e.g. add '*.domain/' or the exact host) instead of creating a new one."
    );
  }
  if (!analysis.covering.length && !analysis.categoryMatch.length && !analysis.related.length) {
    f.push("No custom URL category covers this URL or its domain.");
  }
  if (analysis.panDb) {
    f.push(`PAN-DB categorizes it as: ${analysis.panDb.categories.join(", ") || "(unparsed, see pan_db.lines)"}.`);
    if (analysis.panDb.categories.includes("not-resolved")) {
      f.push("'not-resolved' means the firewall could not query the PAN-DB cloud: a firewall connectivity issue, not a website issue.");
    }
  } else if (analysis.panDbError) {
    f.push(`PAN-DB lookup failed on the firewall: ${analysis.panDbError}`);
  } else {
    f.push("Pass 'device' to also get the PAN-DB category from the firewall.");
  }

  for (const name of customNames) {
    const inRules = usage.rules.filter((r) => r.category.includes(name));
    const inProfiles = usage.profiles.filter((p) => p.actions[name] || p.credential_actions[name]);
    if (!inRules.length && !inProfiles.length) {
      f.push(
        `Category '${name}' exists but is not used by any security rule or URL filtering profile in scope ${scope.locations.join(" > ")}: ` +
          "the fix is to reference it where needed (rule 'category' field or profile action), not to create a new category."
      );
    }
  }

  for (const r of usage.rules) {
    const issues: string[] = [];
    if (r.disabled) issues.push("rule is DISABLED");
    if (r.sourceUser.length && !r.sourceUser.includes("any")) issues.push(`only for users/groups ${r.sourceUser.join(", ")}: check the user's group membership`);
    if (r.schedule) issues.push(`has schedule '${r.schedule}'`);
    if (r.policy === "decryption") issues.push("decryption rule (does not allow/deny by itself)");
    f.push(`Rule '${r.name}' (${r.location}/${r.rulebase}, action ${r.action}) references ${r.category.filter((c) => analysis.effectiveCategories.includes(c)).join(", ")}${issues.length ? `: ${issues.join("; ")}` : ""}.`);
  }

  for (const p of usage.profiles) {
    const blocking = Object.entries(p.actions).filter(([, a]) => a !== "allow" && a !== "alert");
    if (blocking.length) {
      f.push(
        `URL filtering profile '${p.profile}' (${p.location}) sets ${blocking.map(([c, a]) => `${c}=${a}`).join(", ")}` +
          `${p.used_by_rules.length ? `, used by ${p.used_by_rules.join(", ")}` : ", not used by any rule in scope"}.`
      );
    }
    const cred = Object.entries(p.credential_actions).filter(([, a]) => a === "block");
    if (cred.length) f.push(`Profile '${p.profile}' blocks credential submission for ${cred.map(([c]) => c).join(", ")} (login forms fail while browsing works).`);
  }

  if (scope.device?.policySync && !/in sync/i.test(scope.device.policySync)) {
    f.push(`Device ${scope.device.hostname} policy status is '${scope.device.policySync}': recent Panorama changes may not be pushed.`);
  }
  if (/\/./.test(analysis.url.replace(/^[a-z]+:\/\//i, "")) && !/^http:\/\//i.test(analysis.url)) {
    f.push("The URL has a path: without SSL decryption only the hostname (SNI) is seen, so path-based entries do not apply to HTTPS.");
  }
  return f;
}

export function summarizeUsage(usage: CategoryUsage) {
  return {
    rules: usage.rules.map(compactRule),
    url_filtering_profiles: usage.profiles,
  };
}
