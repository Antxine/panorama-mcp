import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { adLookupEnabled, adLookupUser, userMembership } from "../api/ad.js";
import { entraGroups, entraLookupEnabled } from "../api/entra.js";
import { jsonResponse } from "../api/panorama.js";
import { panoramaTarget } from "../api/ops.js";
import { compactRule, fetchRules, sortByEvaluationOrder } from "../api/policy.js";
import { resolveScope } from "../api/urlanalysis.js";
import { matchSourceUser } from "../lib/groups.js";
import { firewallName } from "../schemas/panos.js";
import { deviceGroupFilter } from "../schemas/debug.js";
import { READ_ONLY } from "./debug.js";

export function registerDirectoryTools(server: McpServer) {
  const ad = adLookupEnabled();
  const entra = entraLookupEnabled();
  if (!ad && !entra) return;

  if (entra) {
    server.tool(
      "entra_user_groups",
      "[READ-ONLY] Entra ID (Azure AD) groups of a user, transitive and cloud-only included, via the Azure CLI session of this machine (az ad user get-member-groups). Rules may reference these groups through the Cloud Identity Engine (CN=...,DC=tenant,DC=onmicrosoft,DC=com).",
      { user: z.string().min(3).max(256).describe("UPN/email or Entra object ID") },
      { title: "Entra User Groups", ...READ_ONLY },
      async ({ user }) => {
        const groups = await entraGroups(user);
        return jsonResponse({ user, count: groups.length, groups: groups.sort() });
      }
    );
  }

  // ad_lookup_user needs Windows ADSI and a domain session: hidden elsewhere so the model does not try it.
  if (ad) server.tool(
    "ad_lookup_user",
    "[READ-ONLY] Looks a user up in Active Directory (email, UPN, DOMAIN\\id, account name or 'First Last'): account name, UPN, mail, department, disabled flag, AD groups, and the identities under which the user appears in PAN-OS logs (DOMAIN\\id for Citrix/AD, UPN for GlobalProtect/Prisma). Use it to turn a ticket's name/email into log identities and to check group-based rules.",
    {
      user: z.string().min(2).max(256).describe("Email, UPN, DOMAIN\\id, account name or display name"),
    },
    { title: "AD Lookup User", ...READ_ONLY },
    async ({ user }) => {
      const result = await adLookupUser(user);
      return jsonResponse({
        source: result.source,
        count: result.users.length,
        users: result.users.map(({ groupDns, groups, ...u }) => ({ ...u, groups, group_dns: groupDns.slice(0, 50) })),
        ...(result.users.length === 0 ? { hint: "Not found: try the display name, or the account may live in another forest." } : {}),
      });
    }
  );

  server.tool(
    "ad_user_rules",
    "[READ-ONLY] Which security/decryption rules target this user explicitly or through one of their groups (on-prem AD with nested groups, and Entra ID groups via Azure CLI when available), and, with 'contains' (app, category, rule name...), which relevant rules are restricted to OTHER users/groups with the group the user would need. Use it for 'the user should be allowed by the rule for group X'.",
    {
      user: z.string().min(2).max(256).describe("Email, UPN, DOMAIN\\id or display name"),
      contains: z.string().max(127).optional().describe("Only rules mentioning this (application, URL category, rule name, tag...)"),
      device_group: deviceGroupFilter.describe("Device group; inferred from the user's recent traffic when omitted"),
      policy: z.enum(["security", "decryption"]).optional().describe("Default: security"),
      firewall: firewallName.describe("Panorama entry from firewalls.json. Optional when a single Panorama is configured."),
    },
    { title: "AD User Rules", ...READ_ONLY },
    async ({ user, contains, device_group, policy, firewall }) => {
      const membership = await userMembership(user);
      if (!membership) throw new Error(`'${user}' not found in AD/Entra or ambiguous: use ad_lookup_user or entra_user_groups.`);
      const target = panoramaTarget(firewall);

      let scope = await resolveScope(target, undefined, device_group, { user: membership.identities[0] });
      for (const id of membership.identities.slice(1)) {
        if (device_group || scope.deviceDescription || scope.note) break;
        scope = await resolveScope(target, undefined, undefined, { user: id });
      }

      const needle = contains?.toLowerCase();
      const rules = sortByEvaluationOrder(
        (await fetchRules(target, scope.locations, [policy ?? "security"])).filter(
          (r) =>
            !r.disabled &&
            (!needle ||
              [r.name, r.description ?? "", ...r.application, ...r.category, ...r.service, ...r.tags, ...r.destination].some((v) => v.toLowerCase().includes(needle)))
        ),
        scope.locations
      );

      const targeting = [];
      const otherUsers = [];
      for (const r of rules) {
        const m = matchSourceUser(r.sourceUser, membership);
        if (m.matchedBy.length) targeting.push({ ...compactRule(r), matched_by: m.matchedBy });
        else if (!m.unrestricted && needle) otherUsers.push({ ...compactRule(r), requires_one_of: r.sourceUser.slice(0, 20) });
      }

      return jsonResponse({
        user: {
          displayName: membership.displayName,
          identities: membership.identities,
          group_count: membership.groups.length,
          group_sources: membership.sources,
          ...(membership.warnings.length ? { warnings: membership.warnings } : {}),
        },
        scope: scope.locations,
        ...(scope.note ? { note: scope.note } : {}),
        rules_targeting_user: targeting.slice(0, 40),
        ...(needle ? { relevant_rules_for_other_users: otherUsers.slice(0, 40) } : {}),
        caveat: "Group names are matched by name across formats (on-prem DN, Entra DN, domain\\group, Entra display name). If a group source is missing (see group_sources/warnings), some memberships may be unknown.",
      });
    }
  );
}
