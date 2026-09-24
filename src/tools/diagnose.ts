import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { FirewallTarget } from "../api/client.js";
import { jsonResponse, nodeText, resolveDevice } from "../api/panorama.js";
import { describePick, originOf, pickDevice } from "../api/device.js";
import { containersOf, fetchAppContainers, predefinedApp } from "../api/apps.js";
import { ipUserMapping, logTime, panoramaTarget, searchLogs, testSecurityPolicyMatch, userGroups } from "../api/ops.js";
import {
  appFamily,
  compactRule,
  effectiveProfiles,
  exceptionPattern,
  findExceptionRules,
  fetchFileBlockingProfiles,
  fetchProfileGroups,
  fetchRules,
  fetchThreatProfiles,
  ruleAppliesToDevice,
  scopeForDevice,
  sortByEvaluationOrder,
} from "../api/policy.js";
import { analyzeUrl, categoryUsage, resolveScope, summarizeUsage, urlFindings } from "../api/urlanalysis.js";
import { classifyLogEntry, isBlockingAction } from "../lib/classify.js";
import { summarizeLogs } from "../lib/summarize.js";
import { groupEvents, NO_LOG_HINTS, reportedSiteFindings, type LogEvent } from "../lib/correlate.js";
import { assertFullIdentity, trimLogEntry, type LogFilters, type LogPeriod, type LogType } from "../lib/logquery.js";
import { baseDomain, hostOf, normalizeUrl } from "../lib/urlmatch.js";
import { firewallName } from "../schemas/panos.js";
import { deviceGroupFilter, ipAddress, logPeriod, managedDevice, port, urlInput, userName } from "../schemas/debug.js";
import { PLAYBOOK, SERVER_INSTRUCTIONS, TICKET_METHOD } from "../playbook.js";
import { READ_ONLY } from "./debug.js";

const panoramaEntry = firewallName.describe("Panorama entry from firewalls.json. Optional when a single Panorama is configured.");
const incidentTime = z
  .string()
  .regex(/^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}(:\d{2})?$/, "format 'YYYY/MM/DD HH:MM[:SS]'")
  .optional()
  .describe("When the issue happened, 'YYYY/MM/DD HH:MM' in Panorama's timezone. Searches +/-30 minutes around it instead of 'period'.");

function formatLogTime(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}/${p(d.getMonth() + 1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** Time filters: +/-30 min around the incident when known, else the relative period. */
function timeWindow(incident?: string, period?: LogPeriod): { filters: Pick<LogFilters, "period" | "start_time" | "end_time">; incidentMs?: number } {
  if (incident) {
    const ms = logTime(incident.length === 16 ? `${incident}:00` : incident);
    if (!Number.isNaN(ms)) {
      return { filters: { start_time: formatLogTime(ms - 30 * 60_000), end_time: formatLogTime(ms + 30 * 60_000) }, incidentMs: ms };
    }
  }
  return { filters: { period: period ?? "last-24-hrs" } };
}

function isFullIdentity(user?: string): boolean {
  return Boolean(user && /[@\\]/.test(user));
}

/** Identities (and their source IPs) seen in URL logs for a URL: resolves "Jane Doe" into the logged identity. */
async function identitiesForUrl(target: FirewallTarget, url: string, time: Pick<LogFilters, "period" | "start_time" | "end_time">) {
  const res = await searchLogs(target, "url", { url_contains: hostOf(normalizeUrl(url)), ...time }, 500);
  const seen = new Map<string, { user: string; count: number; sources: string[] }>();
  for (const e of res.entries) {
    const u = nodeText(e.srcuser);
    if (!u) continue;
    const item = seen.get(u) ?? { user: u, count: 0, sources: [] };
    item.count++;
    const src = nodeText(e.src);
    if (src && !item.sources.includes(src) && item.sources.length < 3) item.sources.push(src);
    seen.set(u, item);
  }
  return [...seen.values()].sort((a, b) => b.count - a.count);
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Runs several log searches in parallel; failures are reported instead of aborting the diagnosis. */
async function gatherLogs(
  target: FirewallTarget,
  searches: Array<{ type: LogType; filters: LogFilters; max: number; keep?: (e: Record<string, any>) => boolean }>
) {
  const events: LogEvent[] = [];
  const counts: Record<string, number> = {};
  const errors: Record<string, string> = {};
  await Promise.all(
    searches.map(async (s, i) => {
      const label = searches.filter((x) => x.type === s.type).length > 1 ? `${s.type}#${i}` : s.type;
      try {
        const res = await searchLogs(target, s.type, s.filters, s.max, s.keep);
        counts[label] = res.matched;
        for (const entry of res.entries) events.push({ logType: s.type, time: logTime(entry.receive_time), entry });
      } catch (err) {
        errors[label] = errMsg(err);
      }
    })
  );
  return { events, counts, errors };
}

function threatNumber(threatid: string): string | undefined {
  return /\((\d+)\)\s*$/.exec(threatid)?.[1] ?? (/^\d+$/.test(threatid) ? threatid : undefined);
}

const SUBTYPE_PROFILE: Record<string, string> = {
  virus: "virus",
  "wildfire-virus": "virus",
  "ml-virus": "virus",
  spyware: "spyware",
  vulnerability: "vulnerability",
  file: "file-blocking",
  data: "data-filtering",
  url: "url-filtering",
  wildfire: "wildfire-analysis",
};

export function registerDiagnoseTools(server: McpServer) {
  server.tool(
    "diagnose_user_blocks",
    "[READ-ONLY] START HERE for a ticket. Builds a timeline of everything that blocked a user or source IP across traffic, threat, URL, WildFire, data filtering, decryption and GlobalProtect logs, grouped and explained (which layer blocked, why, what to check next). With reported_url, flags blocks on OTHER domains at the same time (upload/storage/CDN/SSO dependencies of the site). If the exact logged identity is unknown, pass blocked_url/reported_url (and the name as 'user'): it lists the identities seen for that URL.",
    {
      user: userName.optional().describe("Exact logged identity (name@domain or DOMAIN\\id). A partial name is used only to pick among identities seen for the URL."),
      src_ip: ipAddress.optional(),
      reported_url: urlInput.optional().describe("Site the user was trying to use (from the ticket)"),
      blocked_url: urlInput.optional().describe("URL shown on the block page / screenshot, if any"),
      incident_time: incidentTime,
      period: logPeriod,
      max_groups: z.number().int().min(1).max(100).optional().describe("Default 25"),
      firewall: panoramaEntry,
    },
    { title: "Diagnose User Blocks", ...READ_ONLY },
    async ({ user, src_ip, reported_url, blocked_url, incident_time, period, max_groups, firewall }) => {
      const target = panoramaTarget(firewall);
      const { filters: time, incidentMs } = timeWindow(incident_time, period);
      const findings: string[] = [];

      // Resolve the identity as logged when only a name (or nothing) is known.
      if (!src_ip && !isFullIdentity(user)) {
        const probe = blocked_url ?? reported_url;
        if (!probe) {
          throw new Error(
            "Provide src_ip, the exact logged identity (name@domain or DOMAIN\\id), or blocked_url/reported_url to discover who accessed it."
          );
        }
        const seen = await identitiesForUrl(target, probe, time);
        const hint = user?.toLowerCase();
        const candidates = hint ? seen.filter((i) => i.user.toLowerCase().includes(hint)) : seen;
        if (candidates.length !== 1) {
          return jsonResponse({
            need_identity: true,
            message:
              candidates.length === 0
                ? `No identity matching '${user ?? ""}' accessed ${hostOf(normalizeUrl(probe))} in this window. Citrix users appear as DOMAIN\\id: ask for the user's ID, or use the source IP.`
                : "Several identities accessed this URL: re-run with the right one as 'user' (or its src_ip).",
            identities_seen_for_url: seen.slice(0, 20),
          });
        }
        user = candidates[0].user;
        findings.push(`Identity resolved from URL logs: '${user}' (sources ${candidates[0].sources.join(", ")}).`);
      }

      const who: LogFilters = { user: src_ip ? undefined : user, src_ip, ...time };
      const searches: Parameters<typeof gatherLogs>[1] = [
        { type: "traffic", filters: { ...who, only_blocked: true }, max: 200 },
        { type: "threat", filters: { ...who, only_blocked: true }, max: 200 },
        { type: "url", filters: { ...who, only_blocked: true }, max: 200 },
        { type: "data", filters: { ...who, only_blocked: true }, max: 50 },
        { type: "wildfire", filters: who, max: 50, keep: (e) => !/benign/i.test(nodeText(e.category)) },
        { type: "decryption", filters: who, max: 100, keep: (e) => Boolean(nodeText(e.error) || nodeText(e.error_index)) },
      ];
      if (user) searches.push({ type: "globalprotect", filters: { user, ...time }, max: 50, keep: (e) => /fail/i.test(nodeText(e.status)) });

      // Moments when the user reached the reported site (alert/block categories are logged).
      const reportedHost = reported_url ? hostOf(normalizeUrl(reported_url)) : undefined;
      const anchorSearch = reportedHost
        ? gatherLogs(target, [{ type: "url", filters: { ...who, url_contains: baseDomain(reportedHost) }, max: 100 }])
        : Promise.resolve({ events: [] as LogEvent[], counts: {}, errors: {} });

      const [{ events, counts, errors }, anchors] = await Promise.all([gatherLogs(target, searches), anchorSearch]);

      const groups = groupEvents(
        events,
        (t, e) => trimLogEntry(t, e),
        reported_url ? { url: reported_url, incidentTime: incidentMs } : undefined,
        anchors.events
      ).filter((g) => g.blocked || g.layer !== "none");

      findings.push(...reportedSiteFindings(groups, reported_url));
      if (blocked_url) {
        const blockedHost = hostOf(normalizeUrl(blocked_url));
        const hit = groups.find((g) => g.destination === blockedHost);
        findings.push(
          hit
            ? `The block page URL ${blockedHost} is confirmed in the logs: ${hit.summary}.`
            : `The block page URL ${blockedHost} was not found in the blocked logs of this window: check the time window and identity.`
        );
        if (reportedHost && baseDomain(blockedHost) !== baseDomain(reportedHost)) {
          findings.push(`The blocked resource (${blockedHost}) is NOT the requested site (${reportedHost}): the fix must target ${blockedHost}.`);
        }
      }
      const layers = [...new Set(groups.filter((g) => g.blocked).map((g) => g.layer))];
      if (layers.length) findings.push(`Blocking layers found: ${layers.join(", ")}. Drill down with the next_steps of each group.`);
      const devices = [...new Set(events.map((e) => nodeText(e.entry.device_name)).filter(Boolean))];

      return jsonResponse({
        searched: { user, src_ip, ...time, matches_per_log_type: counts },
        devices_seen: devices,
        findings,
        groups: groups.slice(0, max_groups ?? 25),
        ...(Object.keys(errors).length ? { errors } : {}),
        ...(groups.length ? {} : { no_result_hints: NO_LOG_HINTS }),
      });
    }
  );

  server.tool(
    "diagnose_url_access",
    "[READ-ONLY] Full analysis of why a URL is blocked/allowed: existing custom categories covering it (from config AND from the categories the firewall logged), same-domain entries that do not match, PAN-DB category, rules and URL filtering profiles using those categories, the organization's existing exception rules to extend or copy, recent URL logs, and conclusions. Prevents proposing a category, profile or rule that already exists.",
    {
      url: urlInput,
      user: userName.optional().describe("Exact logged identity (name@domain or DOMAIN\\id); other values are ignored for log filtering"),
      src_ip: ipAddress.optional(),
      device_group: deviceGroupFilter.describe("Device group of the user's site. Inferred from the logs when omitted."),
      device: managedDevice.optional().describe("Specific firewall; usually omit it."),
      incident_time: incidentTime,
      period: logPeriod,
      firewall: panoramaEntry,
    },
    { title: "Diagnose URL Access", ...READ_ONLY },
    async ({ url, device, device_group, user, src_ip, incident_time, period, firewall }) => {
      const target = panoramaTarget(firewall);
      const host = hostOf(normalizeUrl(url));
      const { filters: time } = timeWindow(incident_time, period);
      const findings: string[] = [];
      const logUser = isFullIdentity(user) ? user : undefined;
      if (user && !logUser) findings.push(`'${user}' is not a complete logged identity: URL logs were searched for all users (see users in recent_url_logs).`);

      const logs = await searchLogs(target, "url", { user: src_ip ? undefined : logUser, src_ip, url_contains: host, ...time }, 200).catch((err) => ({
        query: "",
        entries: [] as Record<string, any>[],
        matched: 0,
        error: errMsg(err),
      }));
      const blockedLogs = logs.entries.filter((e) => isBlockingAction("url", nodeText(e.action)));
      const latest = blockedLogs[0] ?? logs.entries[0];

      const scope = await resolveScope(target, device, device_group, { origin: originOf(latest), src_ip, user: logUser, anyConnected: true });
      if (scope.note) findings.push(scope.note);
      const analysis = await analyzeUrl(target, url, scope);

      // Categories the firewall actually assigned (custom ones included) complement the config analysis.
      const loggedCategories = [...new Set(logs.entries.flatMap((e) => (nodeText(e.url_category_list) || nodeText(e.category)).split(",")).map((c) => c.trim()).filter(Boolean))];
      const categories = [...new Set([...analysis.effectiveCategories, ...loggedCategories])];
      const usage = await categoryUsage(target, categories, scope);
      findings.push(...urlFindings(analysis, usage, scope));

      const loggedCustom = loggedCategories.filter((c) => /[A-Z ]/.test(c) && !analysis.covering.some((x) => x.category === c));
      if (loggedCustom.length) {
        findings.push(
          `The firewall logged custom categor${loggedCustom.length > 1 ? "ies" : "y"} ${loggedCustom.map((c) => `'${c}'`).join(", ")} for this URL: ` +
            "they ALREADY exist (check usage below) - do not propose creating one."
        );
      }

      if (latest) {
        const logged = nodeText(latest.url_category_list) || nodeText(latest.category);
        findings.push(`Latest ${blockedLogs.length ? "blocked " : ""}URL log (${nodeText(latest.receive_time)}): action ${nodeText(latest.action)}, categories '${logged}', rule '${nodeText(latest.rule)}', user '${nodeText(latest.srcuser)}'.`);
        for (const c of analysis.covering) {
          if (!logged.split(",").includes(c.category)) {
            findings.push(`The firewall did NOT classify the URL in '${c.category}' at that time: entry pattern not matching the real hostname, config not pushed, or log older than the change.`);
          }
        }
      } else {
        findings.push(`No URL log for ${host}: the category may be set to 'allow' (not logged), or the block happens elsewhere (another domain, file blocking, policy).`);
      }

      // Existing exception rules to reuse or copy, around the rule that enforced the block.
      const blockingRule = latest
        ? sortByEvaluationOrder(usage.allRules.filter((r) => r.policy === "security" && r.name === nodeText(latest.rule)), scope.locations)[0]
        : undefined;
      const customCats = categories.filter((c) => /[A-Z ]/.test(c));
      const exceptions = findExceptionRules(usage.allRules, { categories: customCats }, blockingRule);
      const pattern = exceptionPattern(exceptions);
      if (pattern) findings.push(pattern);
      if (blockingRule) {
        findings.push(
          `The enforcing rule '${blockingRule.name}' is in ${blockingRule.location}/${blockingRule.rulebase} #${blockingRule.position}: an exception rule must be placed before it, in the same device group (or a parent evaluated earlier).`
        );
      }
      findings.push("If this URL is allowed but the site still fails, run diagnose_user_blocks with reported_url: the site may depend on other domains.");

      return jsonResponse({
        url,
        firewall_used: scope.deviceDescription,
        scope: scope.locations,
        findings,
        custom_categories: { covered_by: analysis.covering, category_match: analysis.categoryMatch, same_domain_not_matching: analysis.related },
        logged_categories: loggedCategories,
        pan_db: analysis.panDb ?? analysis.panDbError,
        usage: summarizeUsage(usage),
        blocking_rule: blockingRule ? compactRule(blockingRule) : undefined,
        existing_exception_rules: exceptions.map(compactRule),
        recent_url_logs: summarizeLogs("url", logs.entries, 10),
      });
    }
  );

  server.tool(
    "diagnose_threat_block",
    "[READ-ONLY] Analyzes a threat/file block (antivirus, WildFire, anti-spyware, vulnerability, file blocking, data filtering): finds the log, the rule and the security profile actually applied (profile group resolved), whether an exception for that threat ID ALREADY exists (in the applied profile or elsewhere), the matching file-blocking rule, and the WildFire verdict.",
    {
      user: userName.optional(),
      src_ip: ipAddress.optional(),
      threat_id: z.string().max(20).regex(/^\d+$/).optional().describe("Numeric threat ID (e.g. 52020)"),
      file_hash: z.string().regex(/^[0-9a-fA-F]{32,64}$/).optional().describe("SHA-256 of the file"),
      filename: z.string().max(255).regex(/^[^'"<>]+$/).optional().describe("File name (substring)"),
      incident_time: incidentTime,
      period: logPeriod,
      firewall: panoramaEntry,
    },
    { title: "Diagnose Threat/File Block", ...READ_ONLY },
    async ({ user, src_ip, threat_id, file_hash, filename, incident_time, period, firewall }) => {
      if (!user && !src_ip && !threat_id && !file_hash && !filename) throw new Error("Provide at least one of user, src_ip, threat_id, file_hash, filename");
      const target = panoramaTarget(firewall);
      const { filters: time } = timeWindow(incident_time, period);
      const hash = file_hash?.toLowerCase();
      const keep = (e: Record<string, any>) =>
        (!threat_id || threatNumber(nodeText(e.threatid)) === threat_id) &&
        (!hash || nodeText(e.filedigest).toLowerCase() === hash) &&
        (!filename || nodeText(e.misc).toLowerCase().includes(filename.toLowerCase()));

      const { events, errors } = await gatherLogs(target, [
        { type: "threat", filters: { user, src_ip, ...time }, max: 100, keep },
        { type: "wildfire", filters: { user, src_ip, ...time }, max: 20, keep },
      ]);
      const threats = events.filter((e) => e.logType === "threat");
      const verdicts = events
        .filter((e) => e.logType === "wildfire")
        .map((e) => ({ file: nodeText(e.entry.misc), sha256: nodeText(e.entry.filedigest), verdict: nodeText(e.entry.category), time: nodeText(e.entry.receive_time) }));

      if (!threats.length) {
        return jsonResponse({
          findings: ["No matching threat log found.", ...NO_LOG_HINTS],
          wildfire_verdicts: verdicts,
          ...(Object.keys(errors).length ? { errors } : {}),
        });
      }

      // Analyze distinct (device, rule, subtype, threat) combinations, most recent first.
      const seen = new Map<string, LogEvent>();
      for (const ev of threats.sort((a, b) => b.time - a.time)) {
        const e = ev.entry;
        const key = [nodeText(e.serial), nodeText(e.rule), nodeText(e.subtype), nodeText(e.threatid)].join("|");
        if (!seen.has(key)) seen.set(key, ev);
      }

      const analyses = [];
      for (const ev of [...seen.values()].slice(0, 5)) {
        const e = ev.entry;
        const subtype = nodeText(e.subtype);
        const profileType = SUBTYPE_PROFILE[subtype];
        const tid = threatNumber(nodeText(e.threatid));
        const serial = nodeText(e.serial);
        const findings: string[] = [classifyLogEntry("threat", e).summary];
        const out: Record<string, unknown> = { event: trimLogEntry("threat", e), occurrences: threats.filter((t) => t.entry.rule === e.rule && t.entry.threatid === e.threatid).length };

        try {
          const dev = await resolveDevice(target, serial);
          const { locations } = await scopeForDevice(target, dev.serial);
          const [rules, groups] = await Promise.all([fetchRules(target, locations), fetchProfileGroups(target, locations)]);
          const rule = sortByEvaluationOrder(rules.filter((r) => r.name === nodeText(e.rule) && ruleAppliesToDevice(r, dev.serial)), locations)[0];
          if (!rule) {
            findings.push(`Rule '${nodeText(e.rule)}' not found in Panorama scope ${locations.join(" > ")}: it may be a local firewall rule.`);
          } else {
            const applied = effectiveProfiles(rule, groups, locations);
            out.rule = compactRule(rule);
            out.applied_profiles = { ...(rule.profileGroup ? { via_group: rule.profileGroup } : {}), ...applied };
            const appliedName = profileType ? applied[profileType] : undefined;

            if (profileType && ["virus", "spyware", "vulnerability"].includes(profileType) && tid) {
              const profiles = await fetchThreatProfiles(target, locations, [profileType as "virus" | "spyware" | "vulnerability"]);
              const withException = profiles.flatMap((p) =>
                p.threatExceptions.filter((x) => x.threatId === tid).map((x) => ({ profile: p.name, location: p.location, action: x.action, exempt_ips: x.exemptIps, applied: p.name === appliedName }))
              );
              out.existing_exceptions = withException;
              const inApplied = withException.find((x) => x.applied);
              if (inApplied) {
                findings.push(
                  `An exception for threat ${tid} ALREADY exists in the applied ${profileType} profile '${appliedName}' (action '${inApplied.action}'). ` +
                    (inApplied.action === "default"
                      ? "Action 'default' keeps the signature's default action: it does not allow the traffic. Change the action rather than adding another exception."
                      : "If it still blocks: check exempt IPs, that the change was pushed, and that the log is newer than the change.")
                );
              } else if (withException.length) {
                findings.push(
                  `Exceptions for threat ${tid} exist in ${withException.map((x) => `'${x.profile}'`).join(", ")} but rule '${rule.name}' applies '${appliedName ?? "none"}': ` +
                    "the exception must be in the profile actually applied (or the rule must use that profile/group). Do not create yet another profile."
                );
              } else {
                findings.push(
                  `No exception exists for threat ${tid}. If it is a confirmed false positive: request a verdict/signature fix from Palo Alto, and as a workaround add a threat exception in '${appliedName ?? "the applied profile"}'` +
                    `${rule.profileGroup ? ` (profile group '${rule.profileGroup}')` : ""}, scoped as narrowly as possible (exempt IPs).`
                );
              }
              if (profileType === "virus") {
                const p = profiles.find((x) => x.name === appliedName);
                if (p) out.antivirus_decoders = p.decoders;
              }
            }

            if (profileType === "file-blocking") {
              const fbProfiles = await fetchFileBlockingProfiles(target, locations);
              const fb = fbProfiles.find((p) => p.name === appliedName);
              const fileType = nodeText(e.filetype) || nodeText(e.threatid).replace(/\(\d+\)$/, "").trim();
              const direction = nodeText(e.direction).includes("server-to-client") ? "download" : "upload";
              const app = nodeText(e.app);
              const match = fb?.rules.find(
                (r) =>
                  (r.application.includes("any") || r.application.includes(app)) &&
                  (r.direction === "both" || r.direction === direction) &&
                  (r.fileType.includes("any") || r.fileType.some((t) => fileType.toLowerCase().includes(t.toLowerCase())))
              );
              out.file_blocking = { profile: appliedName, direction, file_type: fileType, app, matching_profile_rule: match, all_rules: fb?.rules };
              findings.push(
                match
                  ? `File-blocking profile '${appliedName}' rule '${match.name}' (${match.direction}, ${match.fileType.join(",")}, apps ${match.application.join(",")}) -> ${match.action}. Rules are evaluated top-down: an allow-type exception must be placed ABOVE it in the same profile.`
                  : `Could not pinpoint the file-blocking rule in '${appliedName}'; check all_rules.`
              );
            }

            if (!profileType) findings.push(`Subtype '${subtype}' is not tied to a security profile type; see the playbook.`);
          }
          if (dev.policySync && !/in sync/i.test(dev.policySync)) findings.push(`Device ${dev.hostname} policy status is '${dev.policySync}'.`);
        } catch (err) {
          findings.push(`Could not analyze config: ${errMsg(err)}`);
        }
        out.findings = findings;
        analyses.push(out);
      }

      const malicious = verdicts.filter((v) => v.verdict && !/benign/i.test(v.verdict));
      return jsonResponse({
        analyses,
        wildfire_verdicts: verdicts,
        ...(malicious.length ? { note: "WildFire verdicts other than benign: if believed wrong, request a verdict change from Palo Alto (WildFire portal) with the SHA-256." } : {}),
        ...(Object.keys(errors).length ? { errors } : {}),
      });
    }
  );

  server.tool(
    "diagnose_flow",
    "[READ-ONLY] Analyzes a flow (source -> destination:port) and/or an application: User-ID mapping and groups of the source, rule the firewall actually matches (test security-policy-match), which application groups/filters contain the App-ID and which rules allow or deny them, the organization's existing exception rules for that app family, and recent traffic logs explained. Use for 'no rule allows X', upload app functions, App-ID or network issues. Works for Prisma Access users with config and logs only.",
    {
      destination: ipAddress.describe("Destination IP (pre-NAT)"),
      destination_port: port,
      protocol: z.number().int().min(0).max(255).optional().describe("Default 6 (TCP)"),
      src_ip: ipAddress.optional(),
      user: userName.optional().describe("Exact logged identity (name@domain or DOMAIN\\id)"),
      application: z.string().max(63).optional().describe("App-ID seen in logs, e.g. 'adobe-podcast' or 'box-uploading'"),
      device_group: deviceGroupFilter,
      device: managedDevice.optional().describe("Specific firewall; usually omit it (inferred from the source's traffic or device_group)."),
      period: logPeriod,
      firewall: panoramaEntry,
    },
    { title: "Diagnose Flow", ...READ_ONLY },
    async ({ device, device_group, destination, destination_port, protocol, src_ip, user, application, period, firewall }) => {
      if (!src_ip && !user) throw new Error("Provide 'src_ip' and/or 'user'");
      const target = panoramaTarget(firewall);
      const findings: string[] = [];
      const out: Record<string, unknown> = {};
      const time = { period: period ?? ("last-24-hrs" as LogPeriod) };

      if (!src_ip && user) {
        const recent = await searchLogs(target, "traffic", { user: assertFullIdentity(user), ...time }, 200);
        const counts = new Map<string, number>();
        for (const e of recent.entries) counts.set(nodeText(e.src), (counts.get(nodeText(e.src)) ?? 0) + 1);
        src_ip = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
        if (!src_ip) throw new Error(`No traffic log for user '${user}' in ${time.period}: provide src_ip`);
        findings.push(`Source IP inferred from traffic logs: ${src_ip}${counts.size > 1 ? ` (other IPs seen: ${[...counts.keys()].filter((k) => k !== src_ip).join(", ")})` : ""}.`);
      }

      // Live checks need a managed firewall; Prisma Access traffic only has logs and config.
      const pick = await pickDevice(target, { device, device_group, src_ip, user }).catch((err) => err as Error);
      let locations: string[];
      let serial: string | undefined;
      if (pick instanceof Error) {
        out.live_checks = pick.message;
        const scope = await resolveScope(target, undefined, device_group, { src_ip });
        locations = scope.locations;
        if (scope.note) findings.push(scope.note);
      } else {
        const dev = pick.device;
        serial = dev.serial;
        out.firewall_used = describePick(pick);
        locations = (await scopeForDevice(target, dev.serial)).locations;

        const mapping = await ipUserMapping(target, dev.serial, src_ip!).catch((err) => errMsg(err));
        out.user_id_mapping = mapping;
        const mappedUser = Array.isArray(mapping) ? mapping[0]?.user : undefined;
        if (Array.isArray(mapping) && !mapping.length) {
          findings.push(`No User-ID mapping for ${src_ip} on ${dev.hostname}: rules restricted to users/groups cannot match; traffic falls to 'any'-user rules or the default deny.`);
        } else if (mappedUser && user && !mappedUser.toLowerCase().includes(user.toLowerCase().split("\\").pop()!)) {
          findings.push(`${src_ip} is mapped to '${mappedUser}', not '${user}': shared IP (Citrix/terminal server/proxy) or stale mapping.`);
        }
        const identity = user ?? mappedUser;
        if (identity) out.user_groups = await userGroups(target, dev.serial, identity).catch((err) => errMsg(err));

        try {
          const matched = await testSecurityPolicyMatch(target, dev.serial, {
            source: src_ip!,
            destination,
            destination_port,
            protocol: protocol ?? 6,
            application,
            source_user: mappedUser ?? user,
          });
          out.policy_match = matched;
          const first = matched[0];
          if (!first) findings.push("test security-policy-match: no rule matches, the default rule applies (interzone-default = deny, not logged by default).");
          else findings.push(`The firewall matches rule '${first.name ?? JSON.stringify(first)}'${first.action ? ` (action ${first.action})` : ""} for this flow${application ? ` and application ${application}` : ""}.`);
        } catch (err) {
          out.policy_match = errMsg(err);
        }
        if (dev.policySync && !/in sync/i.test(dev.policySync)) findings.push(`Device policy status is '${dev.policySync}': Panorama config may differ from the firewall.`);
      }

      if (application) {
        const [rules, containers, app] = await Promise.all([
          fetchRules(target, locations),
          fetchAppContainers(target, locations),
          predefinedApp(target, application).catch(() => undefined),
        ]);
        const inside = app ? containersOf(app, containers) : [];
        if (app) out.application = { ...app, contained_in: inside.map((c) => ({ kind: c.kind, name: c.name, location: c.location, definition: c.definition })) };
        const names = new Set([application, ...inside.map((c) => c.name)]);
        const family = appFamily(application);
        const relevant = sortByEvaluationOrder(
          rules.filter((r) => !r.disabled && ruleAppliesToDevice(r, serial) && r.application.some((a) => names.has(a) || appFamily(a) === family)),
          locations
        );
        out.rules_for_application = relevant.slice(0, 20).map(compactRule);

        const denying = relevant.filter((r) => r.action !== "allow" && r.application.some((a) => names.has(a)));
        for (const r of denying.slice(0, 3)) {
          const via = r.application.filter((a) => names.has(a) && a !== application);
          findings.push(
            `Rule '${r.name}' (${r.location}/${r.rulebase} #${r.position}, action ${r.action}) matches '${application}'` +
              (via.length ? ` through ${via.map((v) => `'${v}' (${inside.find((c) => c.name === v)?.kind ?? "container"})`).join(", ")}` : "") +
              "."
          );
        }
        const allowing = relevant.filter((r) => r.action === "allow" && r.application.some((a) => names.has(a)));
        if (!allowing.length) findings.push(`No enabled rule in scope explicitly allows '${application}' (directly or via a group/filter).`);

        const exceptions = findExceptionRules(rules, { apps: [application] }, denying[0]);
        out.existing_exception_rules = exceptions.map(compactRule);
        const pattern = exceptionPattern(exceptions);
        if (pattern) findings.push(pattern);
        if (denying[0]) findings.push(`An exception must be placed before '${denying[0].name}' in ${denying[0].location}/${denying[0].rulebase}.`);
      }

      const logs = await gatherLogs(target, [
        { type: "traffic", filters: { src_ip, dst_ip: destination, dst_port: destination_port, ...time }, max: 50 },
        { type: "threat", filters: { src_ip, dst_ip: destination, only_blocked: true, ...time }, max: 20 },
      ]);
      const groups = groupEvents(logs.events, (t, e) => trimLogEntry(t, e));
      out.log_groups = groups.slice(0, 15);
      if (!groups.length) findings.push(...NO_LOG_HINTS);
      for (const g of groups.filter((g) => g.blocked || g.layer !== "none").slice(0, 5)) findings.push(`Logs: ${g.summary} (x${g.count}, last ${g.last_seen}).`);
      if (Object.keys(logs.errors).length) out.log_errors = logs.errors;

      return jsonResponse({ findings, ...out });
    }
  );

  server.tool(
    "start_ticket_diagnosis",
    "[READ-ONLY] Call this FIRST when the user shares a support ticket or asks to debug a blocked user: returns the diagnosis method, the rules to follow and the expected answer format.",
    {},
    { title: "Start Ticket Diagnosis", ...READ_ONLY },
    async () => ({ content: [{ type: "text" as const, text: `${SERVER_INSTRUCTIONS}\n\n${TICKET_METHOD}` }] })
  );

  server.tool(
    "get_troubleshooting_playbook",
    "[READ-ONLY] Returns the troubleshooting playbook: visibility pitfalls, third-party dependencies, URL filtering, file/threat false positives, App-ID, User-ID, NAT, decryption, DNS security, EDL, zone protection. Read it when the cause is unclear or before concluding.",
    {},
    { title: "Troubleshooting Playbook", ...READ_ONLY },
    async () => ({ content: [{ type: "text" as const, text: PLAYBOOK }] })
  );

  server.resource(
    "troubleshooting-playbook",
    "panorama://playbook",
    { mimeType: "text/markdown", description: "Troubleshooting playbook for Panorama-managed firewalls" },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: "text/markdown", text: PLAYBOOK }] })
  );

  server.prompt(
    "diagnose_ticket",
    "Diagnose a ServiceNow ticket excerpt: extract facts, gather evidence with the diagnose_* tools, and propose the minimal fix without duplicating existing config.",
    { ticket: z.string().describe("Ticket excerpt (description, user, time, URL...)") },
    ({ ticket }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Here is a support ticket excerpt:\n\n<ticket>\n${ticket}\n</ticket>\n\nDiagnose it with the Panorama tools.\n\n${TICKET_METHOD}`,
          },
        },
      ],
    })
  );
}
