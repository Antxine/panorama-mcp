import type { RuleSummary } from "../api/policy.js";
import { matchSourceUser, type Membership } from "./groups.js";

/**
 * Candidate fixes for a blocked application or URL, ranked from the smallest change on
 * existing config to a new rule. They are suggestions for a human: each one states who
 * else is affected and why it was proposed.
 */
export interface FixOption {
  confidence: "high" | "medium" | "low";
  change: string;
  impact: string;
  why: string;
  rule?: string;
  where?: string;
}

export interface FixContext {
  rules: RuleSummary[];
  locations: string[];
  /** Rule that denied or filtered the traffic, when known. */
  blocking?: RuleSummary;
  membership?: Membership;
  /** Human label of the user, for messages. */
  userLabel: string;
}

function family(app: string): string {
  return app.split("-")[0].toLowerCase();
}

function where(r: RuleSummary): string {
  return `${r.location}/${r.rulebase}-${r.policy} #${r.position}`;
}

/** Index in evaluation order, used to keep only rules evaluated before the blocking one. */
function orderIndex(rules: RuleSummary[], locations: string[]): (r: RuleSummary) => number {
  const rank = (r: RuleSummary) => {
    const idx = locations.indexOf(r.location);
    return [r.rulebase === "pre" ? 0 : 1, r.rulebase === "pre" ? idx : locations.length * 2 - idx, r.position];
  };
  const sorted = [...rules].sort((a, b) => {
    const ra = rank(a);
    const rb = rank(b);
    for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) return ra[i] - rb[i];
    return 0;
  });
  return (r) => sorted.indexOf(r);
}

function targetsUser(r: RuleSummary, membership?: Membership): string[] {
  if (!membership) return [];
  return matchSourceUser(r.sourceUser, membership).matchedBy;
}

function usable(r: RuleSummary, ctx: FixContext, index: (r: RuleSummary) => number): boolean {
  if (r.policy !== "security" || r.action !== "allow" || r.disabled) return false;
  return !ctx.blocking || index(r) < index(ctx.blocking);
}

function caveats(r: RuleSummary): string {
  const notes: string[] = [];
  if (r.category.length && !r.category.includes("any")) notes.push(`it also requires URL categories ${r.category.slice(0, 5).join(", ")}`);
  if (r.service.length && !r.service.some((s) => s === "application-default" || s === "any")) notes.push(`its service is ${r.service.join(", ")}`);
  if (r.schedule) notes.push(`it has schedule '${r.schedule}'`);
  return notes.length ? ` Check that ${notes.join("; ")}.` : "";
}

/** Fix options for an App-ID blocked by policy. */
export function suggestAppFixes(app: string, ctx: FixContext): FixOption[] {
  const options: FixOption[] = [];
  const index = orderIndex(ctx.rules, ctx.locations);
  const fam = family(app);

  // 1. A rule already granting apps to the user (identity or group): add the App-ID there.
  for (const r of ctx.rules) {
    if (!usable(r, ctx, index) || r.application.includes(app) || r.application.includes("any")) continue;
    const matchedBy = targetsUser(r, ctx.membership);
    if (!matchedBy.length) continue;
    const sameFamily = r.application.filter((a) => family(a) === fam);
    const named = new RegExp(`\\b${fam}\\b`, "i").test(`${r.name} ${r.description ?? ""}`);
    options.push({
      confidence: sameFamily.length || named ? "high" : "low",
      change: `Add App-ID '${app}' to rule '${r.name}'`,
      rule: r.name,
      where: where(r),
      impact: `Every identity matched by ${matchedBy.join(", ")} gets '${app}' (not only ${ctx.userLabel}).`,
      why:
        (sameFamily.length
          ? `The rule already applies to ${ctx.userLabel} (via ${matchedBy.join(", ")}) and allows related apps (${sameFamily.slice(0, 5).join(", ")}).`
          : named
            ? `The rule applies to ${ctx.userLabel} (via ${matchedBy.join(", ")}) and its name/description mentions '${fam}'.`
            : `The rule applies to ${ctx.userLabel} (via ${matchedBy.join(", ")}) and grants other apps; check it is meant for this kind of usage.`) +
        caveats(r),
    });
  }

  // 2. A rule already allowing the app, but for other users/groups.
  for (const r of ctx.rules) {
    if (!usable(r, ctx, index) || !r.application.includes(app)) continue;
    const m = ctx.membership ? matchSourceUser(r.sourceUser, ctx.membership) : undefined;
    if (!m || m.unrestricted || m.matchedBy.length) continue;
    const groups = r.sourceUser.filter((u) => /^CN=|\\/.test(u) && !u.includes("@"));
    options.push({
      confidence: "medium",
      change: groups.length
        ? `Add ${ctx.userLabel} to group ${groups[0]} (identity change, no firewall change), or to the source users of '${r.name}'`
        : `Add ${ctx.userLabel} to the source users of '${r.name}'`,
      rule: r.name,
      where: where(r),
      impact: `${ctx.userLabel} gets everything '${r.name}' allows (${r.application.slice(0, 8).join(", ")}${r.application.length > 8 ? ", ..." : ""}).`,
      why: `'${r.name}' already allows '${app}' for ${r.sourceUser.slice(0, 5).join(", ")}.` + caveats(r),
    });
  }

  options.push({
    confidence: "low",
    change: `Create a dedicated exception rule for ${ctx.userLabel} and '${app}'${ctx.blocking ? ` before '${ctx.blocking.name}' (${where(ctx.blocking)})` : ""}`,
    impact: `Only ${ctx.userLabel}; one more rule to maintain (use an expiry schedule).`,
    why: "Fallback when no existing rule fits: copy the pattern of existing exception rules (profile group, naming, schedule).",
  });
  return rank(options);
}

/** Fix options for a URL blocked by URL filtering or a category-based rule. */
export function suggestUrlFixes(host: string, coveringCategories: string[], ctx: FixContext): FixOption[] {
  const options: FixOption[] = [];
  const index = orderIndex(ctx.rules, ctx.locations);
  const covering = new Set(coveringCategories);

  for (const r of ctx.rules) {
    if (!usable(r, ctx, index)) continue;
    const custom = r.category.filter((c) => /[A-Z ]/.test(c));
    if (!custom.length) continue;
    const matchedBy = targetsUser(r, ctx.membership);
    const hasCovering = custom.some((c) => covering.has(c));

    if (matchedBy.length && !hasCovering) {
      options.push({
        confidence: "medium",
        change: `Add '${host}' to custom category '${custom[0]}' used by rule '${r.name}'`,
        rule: r.name,
        where: where(r),
        impact: `Everyone allowed by rules using '${custom[0]}' gets '${host}' (category may be shared by other rules).`,
        why: `'${r.name}' already applies to ${ctx.userLabel} (via ${matchedBy.join(", ")}) and allows categories ${custom.slice(0, 4).join(", ")}.` + caveats(r),
      });
    } else if (hasCovering && ctx.membership && !matchedBy.length) {
      const m = matchSourceUser(r.sourceUser, ctx.membership);
      if (m.unrestricted) continue;
      options.push({
        confidence: "high",
        change: `Add ${ctx.userLabel} to the source users (or group) of rule '${r.name}'`,
        rule: r.name,
        where: where(r),
        impact: `${ctx.userLabel} gets every category allowed by '${r.name}' (${r.category.slice(0, 5).join(", ")}).`,
        why: `'${r.name}' already allows a category covering '${host}' (${custom.filter((c) => covering.has(c)).join(", ")}) for ${r.sourceUser.slice(0, 5).join(", ")}.` + caveats(r),
      });
    }
  }

  options.push({
    confidence: "low",
    change: `Create a dedicated exception for ${ctx.userLabel} and '${host}'${ctx.blocking ? ` before '${ctx.blocking.name}' (${where(ctx.blocking)})` : ""}, reusing an existing custom category when one covers it`,
    impact: `Only ${ctx.userLabel}.`,
    why: "Fallback when no existing rule fits: copy the pattern of existing exception rules.",
  });
  return rank(options);
}

const WEIGHT = { high: 0, medium: 1, low: 2 };

function rank(options: FixOption[]): FixOption[] {
  return options.sort((a, b) => WEIGHT[a.confidence] - WEIGHT[b.confidence]).slice(0, 6);
}
