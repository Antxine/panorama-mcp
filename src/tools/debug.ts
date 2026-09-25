import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { XMLParser } from "fast-xml-parser";
import { asArray, jsonResponse, listDeviceGroups, listManagedDevices, nodeText, readEntries, resolveDevice } from "../api/panorama.js";
import { describePick, pickDevice } from "../api/device.js";
import { resolveScope } from "../api/urlanalysis.js";
import {
  ipUserMapping,
  op,
  panoramaTarget,
  searchLogs,
  testSecurityPolicyMatch,
  testUrl,
  userGroups,
  xmlLeaf,
} from "../api/ops.js";
import { compactRule, fetchDgAncestors, fetchRules, ruleAppliesToDevice, scopeForDevice, sortByEvaluationOrder } from "../api/policy.js";
import { classifyLogEntry } from "../lib/classify.js";
import { NO_LOG_HINTS } from "../lib/correlate.js";
import { ipInEntry } from "../lib/ip.js";
import { trimLogEntry } from "../lib/logquery.js";
import { summarizeLogs } from "../lib/summarize.js";
import { containersOf, fetchAppContainers, predefinedApp } from "../api/apps.js";
import { matchEntry } from "../lib/urlmatch.js";
import { firewallName, xmlEscape } from "../schemas/panos.js";
import {
  deviceGroupFilter,
  ipAddress,
  logPeriod,
  logType,
  managedDevice,
  maxResults,
  port,
  urlInput,
  userName,
} from "../schemas/debug.js";

export const READ_ONLY = { readOnlyHint: true, destructiveHint: false, openWorldHint: false } as const;

const panoramaEntry = firewallName.describe(
  "Panorama entry from firewalls.json. Optional when a single Panorama is configured."
);

const OBJECT_XPATHS = {
  "profile-group": "profile-group",
  "url-filtering-profile": "profiles/url-filtering",
  "antivirus-profile": "profiles/virus",
  "anti-spyware-profile": "profiles/spyware",
  "vulnerability-profile": "profiles/vulnerability",
  "file-blocking-profile": "profiles/file-blocking",
  "wildfire-profile": "profiles/wildfire-analysis",
  "decryption-profile": "profiles/decryption",
  "custom-url-category": "profiles/custom-url-category",
  application: "application",
  "application-group": "application-group",
  "application-filter": "application-filter",
  schedule: "schedule",
  tag: "tag",
  "log-forwarding-profile": "log-settings/profiles",
  edl: "external-list",
  address: "address",
  "address-group": "address-group",
  service: "service",
  "service-group": "service-group",
} as const;
const OBJECT_TYPES = Object.keys(OBJECT_XPATHS) as [keyof typeof OBJECT_XPATHS, ...Array<keyof typeof OBJECT_XPATHS>];

const optionalDevice = managedDevice
  .optional()
  .describe(
    "Specific firewall (hostname or serial). Usually omit it: the firewall is chosen from device_group, or from the user's/IP's recent traffic."
  );

export function registerDebugTools(server: McpServer) {
  server.tool(
    "panorama_list_firewalls",
    "[READ-ONLY] Lists firewalls managed by Panorama: hostname, serial, IP, model, version, connection and policy/template sync state. Use the hostname or serial as 'device' in other tools.",
    {
      filter: z.string().max(63).optional().describe("Case-insensitive filter on hostname, serial, IP or model"),
      refresh: z.boolean().optional().describe("Bypass the 5-minute cache"),
      firewall: panoramaEntry,
    },
    { title: "List Managed Firewalls", ...READ_ONLY },
    async ({ filter, refresh, firewall }) => {
      const devices = await listManagedDevices(panoramaTarget(firewall), refresh);
      const needle = filter?.toLowerCase();
      return jsonResponse(
        needle
          ? devices.filter((d) => [d.hostname, d.serial, d.ip, d.model].some((v) => v.toLowerCase().includes(needle)))
          : devices
      );
    }
  );

  server.tool(
    "panorama_list_device_groups",
    "[READ-ONLY] Lists device groups with their parent chain and member firewalls (hostname, serial, connected). Policies of a device group include everything inherited from shared and its parents.",
    {
      refresh: z.boolean().optional().describe("Bypass the 5-minute cache"),
      firewall: panoramaEntry,
    },
    { title: "List Device Groups", ...READ_ONLY },
    async ({ refresh, firewall }) => {
      const target = panoramaTarget(firewall);
      const [groups, devices, ancestors] = await Promise.all([
        listDeviceGroups(target, refresh),
        listManagedDevices(target, refresh),
        fetchDgAncestors(target),
      ]);
      return jsonResponse(
        groups.map((g) => ({
          device_group: g.name,
          inherits_from: ["shared", ...(ancestors.get(g.name) ?? [])],
          firewalls: g.devices.map((d) => {
            const dev = devices.find((x) => x.serial === d.serial);
            return { hostname: dev?.hostname || d.hostname, serial: d.serial, connected: dev?.connected ?? false, policy_sync: dev?.policySync };
          }),
        }))
      );
    }
  );

  server.tool(
    "search_logs",
    "[READ-ONLY] Low-level log search (for a ticket, start with diagnose_user_blocks instead). Searches logs stored on Panorama (traffic, threat, url, wildfire, data, globalprotect, userid, auth, decryption, system). Returns a 'summary' grouping matching events (same destination/action/rule/category...) with counts, users and sources, plus a few raw 'entries' each explained in '_why'. 'user' must be the exact logged identity (name@domain or DOMAIN\\id); 'url_contains' only works on url logs. Keep each window short (start_time/end_time or last-24-hrs; the diagnose tools search back over several days automatically): 30-day searches time out.",
    {
      log_type: logType,
      src_ip: z.string().max(49).optional().describe("Source IP or CIDR"),
      dst_ip: z.string().max(49).optional().describe("Destination IP or CIDR"),
      user: userName.optional(),
      dst_port: port.optional().describe("Destination port"),
      app: z.string().max(63).optional().describe("App-ID name (e.g. 'sharepoint-online-uploading')"),
      rule: z.string().max(127).optional().describe("Security rule name"),
      action: z.string().max(31).optional().describe("Exact action (allow, deny, drop, block-url, reset-both, ...)"),
      only_blocked: z.boolean().optional().describe("Only non-allowed events"),
      url_contains: z.string().max(255).optional().describe("Substring of the URL (log_type=url only)"),
      period: logPeriod,
      start_time: z.string().optional().describe("Absolute start 'YYYY/MM/DD HH:MM:SS' (Panorama timezone); overrides period"),
      end_time: z.string().optional().describe("Absolute end 'YYYY/MM/DD HH:MM:SS'"),
      query: z.string().max(1024).optional().describe("Extra raw PAN-OS filter, ANDed (e.g. \"( severity geq high )\")"),
      max_results: z.number().int().min(1).max(200).optional().describe("Raw entries returned (default 10); the summary covers up to 500 matches"),
      all_fields: z.boolean().optional().describe("Return every log field in raw entries"),
      firewall: panoramaEntry,
    },
    { title: "Search Logs", ...READ_ONLY },
    async ({ log_type, max_results, all_fields, firewall, period, start_time, ...filters }) => {
      const result = await searchLogs(
        panoramaTarget(firewall),
        log_type,
        { ...filters, start_time, period: period ?? (start_time ? undefined : "last-24-hrs") },
        500
      );
      return jsonResponse({
        query: result.query,
        matched: result.matched,
        ...(result.partial ? { partial: "Query timed out: only the logs received so far are included. Narrow the window for complete results." } : {}),
        summary: summarizeLogs(log_type, result.entries),
        entries: result.entries.slice(0, max_results ?? 10).map((e) => {
          const why = classifyLogEntry(log_type, e).summary;
          return { ...trimLogEntry(log_type, e, all_fields), ...(why ? { _why: why } : {}) };
        }),
        ...(result.matched === 0 ? { no_result_hints: NO_LOG_HINTS } : {}),
      });
    }
  );

  server.tool(
    "userid_lookup",
    "[READ-ONLY] User-ID state on a managed firewall: which user is mapped to an IP (show user ip-user-mapping) and/or which groups a user belongs to (show user user-ids match-user). A missing mapping means user/group-based rules cannot match that IP.",
    {
      ip: ipAddress.optional(),
      user: userName.optional(),
      device: optionalDevice,
      device_group: deviceGroupFilter,
      firewall: panoramaEntry,
    },
    { title: "User-ID Lookup", ...READ_ONLY },
    async ({ device, device_group, ip, user, firewall }) => {
      if (!ip && !user) throw new Error("Provide 'ip' and/or 'user'");
      const target = panoramaTarget(firewall);
      const pick = await pickDevice(target, { device, device_group, src_ip: ip, user });
      const dev = pick.device;
      const out: Record<string, unknown> = { firewall_used: describePick(pick) };
      if (ip) {
        const mapping = await ipUserMapping(target, dev.serial, ip);
        out.ip_user_mapping = mapping.length ? mapping : `No User-ID mapping for ${ip}`;
        if (!user && mapping[0]?.user) user = mapping[0].user;
      }
      if (user) out.user_groups = await userGroups(target, dev.serial, user);
      return jsonResponse(out);
    }
  );

  server.tool(
    "gp_current_users",
    "[READ-ONLY] GlobalProtect users currently connected to a gateway firewall (show global-protect-gateway current-user), optionally for one user.",
    {
      user: userName.optional(),
      device: optionalDevice.describe("GlobalProtect gateway firewall. Inferred from the user's traffic when omitted."),
      device_group: deviceGroupFilter,
      firewall: panoramaEntry,
    },
    { title: "GlobalProtect Current Users", ...READ_ONLY },
    async ({ device, device_group, user, firewall }) => {
      const target = panoramaTarget(firewall);
      const pick = await pickDevice(target, { device, device_group, user });
      const dev = pick.device;
      const data = await op(
        target,
        `<show><global-protect-gateway><current-user>${xmlLeaf("user", user)}</current-user></global-protect-gateway></show>`,
        dev.serial
      );
      const entries = asArray(data?.entry);
      return jsonResponse({ firewall_used: describePick(pick), count: entries.length, users: entries });
    }
  );

  server.tool(
    "test_security_policy_match",
    "[READ-ONLY] Asks a managed firewall which security rule matches a flow (test security-policy-match). This is the ground truth, including local rules invisible from Panorama. Include source_user so user/group-based rules are evaluated.",
    {
      device: optionalDevice,
      device_group: deviceGroupFilter,
      source: ipAddress.describe("Source IP"),
      destination: ipAddress.describe("Destination IP (pre-NAT)"),
      destination_port: port,
      protocol: z.number().int().min(0).max(255).optional().describe("IP protocol number (default 6 = TCP, 17 = UDP)"),
      from: z.string().max(31).optional().describe("Source zone"),
      to: z.string().max(31).optional().describe("Destination zone (post-NAT)"),
      application: z.string().max(63).optional(),
      source_user: userName.optional(),
      category: z.string().max(63).optional().describe("URL category"),
      show_all: z.boolean().optional().describe("Return every matching rule instead of the first one"),
      firewall: panoramaEntry,
    },
    { title: "Test Security Policy Match", ...READ_ONLY },
    async ({ device, device_group, firewall, protocol, ...input }) => {
      const target = panoramaTarget(firewall);
      const pick = await pickDevice(target, { device, device_group, src_ip: input.source });
      const rules = await testSecurityPolicyMatch(target, pick.device.serial, { ...input, protocol: protocol ?? 6 });
      return jsonResponse({ firewall_used: describePick(pick), matching_rules: rules.length ? rules : "No rule matched (default rules apply)" });
    }
  );

  server.tool(
    "test_url_category",
    "[READ-ONLY] Asks a managed firewall how it categorizes a URL (test url): PAN-DB categories from the local cache and the cloud. Custom categories are not shown here: use url_category_find.",
    {
      url: urlInput,
      device: optionalDevice.describe("Firewall to ask. Any connected firewall when omitted (PAN-DB is the same everywhere)."),
      device_group: deviceGroupFilter,
      firewall: panoramaEntry,
    },
    { title: "Test URL Category", ...READ_ONLY },
    async ({ device, device_group, url, firewall }) => {
      const target = panoramaTarget(firewall);
      const pick = await pickDevice(target, { device, device_group, anyConnected: true });
      return jsonResponse({ firewall_used: describePick(pick), ...(await testUrl(target, pick.device.serial, url)) });
    }
  );

  server.tool(
    "show_sessions",
    "[READ-ONLY] Active sessions on a managed firewall matching a filter (show session all filter). Useful while the user reproduces the issue.",
    {
      device: optionalDevice,
      device_group: deviceGroupFilter,
      source: ipAddress.optional(),
      destination: ipAddress.optional(),
      destination_port: port.optional(),
      application: z.string().max(63).optional(),
      max_results: maxResults,
      firewall: panoramaEntry,
    },
    { title: "Show Sessions", ...READ_ONLY },
    async ({ device, device_group, source, destination, destination_port, application, max_results, firewall }) => {
      if (!source && !destination) throw new Error("Provide at least 'source' or 'destination'");
      const target = panoramaTarget(firewall);
      const pick = await pickDevice(target, { device, device_group, src_ip: source });
      const dev = pick.device;
      const filter =
        xmlLeaf("source", source) +
        xmlLeaf("destination", destination) +
        xmlLeaf("destination-port", destination_port) +
        xmlLeaf("application", application);
      const data = await op(target, `<show><session><all><filter>${filter}</filter></all></session></show>`, dev.serial);
      const entries = asArray(data?.entry);
      return jsonResponse({ firewall_used: describePick(pick), total: entries.length, sessions: entries.slice(0, max_results ?? 50) });
    }
  );

  server.tool(
    "find_security_rules",
    "[READ-ONLY] Searches security or decryption rules (pre/post) in Panorama's running config. Matches 'contains' against rule name, zones, addresses, users, applications, services, categories, tags and description. With 'device_group', rules of that group AND everything it inherits (shared, parent groups) are returned in evaluation order; with 'device', only rules applying to that firewall. Output flags rules without log forwarding.",
    {
      contains: z.string().max(127).optional().describe("Case-insensitive text to look for (object, user, group, app, category, rule name...)"),
      device_group: deviceGroupFilter,
      device: optionalDevice,
      policy: z.enum(["security", "decryption"]).optional().describe("Default: security"),
      include_disabled: z.boolean().optional(),
      max_results: maxResults,
      firewall: panoramaEntry,
    },
    { title: "Find Security Rules", ...READ_ONLY },
    async ({ contains, device, device_group, policy, include_disabled, max_results, firewall }) => {
      const target = panoramaTarget(firewall);
      const scope = await resolveScope(target, device, device_group);
      const { locations, ruleSerial: serial } = scope;
      const needle = contains?.toLowerCase();
      let rules = await fetchRules(target, locations, [policy ?? "security"]);
      rules = rules.filter((r) => (include_disabled || !r.disabled) && ruleAppliesToDevice(r, serial));
      if (needle) {
        rules = rules.filter((r) =>
          [r.name, r.description ?? "", ...r.from, ...r.to, ...r.source, ...r.destination, ...r.sourceUser, ...r.application, ...r.service, ...r.category, ...r.tags]
            .some((v) => v.toLowerCase().includes(needle))
        );
      }
      if (device || device_group) rules = sortByEvaluationOrder(rules, locations);
      return jsonResponse({
        scope: locations,
        ...(scope.deviceDescription ? { firewall_used: scope.deviceDescription } : {}),
        total: rules.length,
        rules: rules.slice(0, max_results ?? 50).map(compactRule),
        note: "Panorama running config. Local firewall rules and unpushed changes are not included.",
      });
    }
  );

  server.tool(
    "resolve_application",
    "[READ-ONLY] Explains an application name used in rules or logs: whether it is a custom application (with its signatures), an application group, an application filter (with its criteria) or a predefined App-ID (category, subcategory, risk, tags), which groups/filters contain an App-ID (e.g. why 'adobe-podcast' falls in a GenAI block filter), and the rules referencing it or its containers.",
    {
      name: z.string().min(1).max(63).regex(/^[^'"<>]+$/).describe("App-ID, application group or application filter name"),
      device_group: deviceGroupFilter,
      firewall: panoramaEntry,
    },
    { title: "Resolve Application", ...READ_ONLY },
    async ({ name, device_group, firewall }) => {
      const target = panoramaTarget(firewall);
      const scope = await resolveScope(target, undefined, device_group);
      const [containers, rules] = await Promise.all([fetchAppContainers(target, scope.locations), fetchRules(target, scope.locations)]);
      const referencing = (names: string[]) =>
        sortByEvaluationOrder(
          rules.filter((r) => !r.disabled && r.application.some((a) => names.includes(a))),
          scope.locations
        )
          .slice(0, 20)
          .map(compactRule);

      const own = containers.filter((c) => c.name === name);
      if (own.length) {
        return jsonResponse({ scope: scope.locations, definitions: own, rules_using_it: referencing([name]) });
      }
      const app = await predefinedApp(target, name);
      if (!app) {
        return jsonResponse({ name, found: false, note: "Not an application group/filter in scope nor a predefined App-ID: may be a custom application (see get_config_xpath) or a typo." });
      }
      const inside = containersOf(app, containers);
      return jsonResponse({
        scope: scope.locations,
        app,
        contained_in: inside.map((c) => ({ kind: c.kind, name: c.name, location: c.location, definition: c.definition })),
        rules_referencing_app_or_containers: referencing([name, ...inside.map((c) => c.name)]),
      });
    }
  );

  server.tool(
    "find_objects",
    "[READ-ONLY] Checks that objects exist before proposing them, and finds reusable ones: searches by name in security profile groups, security profiles, custom URL categories, applications (custom, groups, filters), schedules, tags, log forwarding profiles, EDLs, addresses and services. Returns type, name and location.",
    {
      name_contains: z.string().min(2).max(63).regex(/^[^'"<>]+$/).describe("Case-insensitive part of the name"),
      types: z.array(z.enum(OBJECT_TYPES)).optional().describe("Restrict to these object types (default: all)"),
      device_group: deviceGroupFilter,
      firewall: panoramaEntry,
    },
    { title: "Find Objects", ...READ_ONLY },
    async ({ name_contains, types, device_group, firewall }) => {
      const target = panoramaTarget(firewall);
      const scope = await resolveScope(target, undefined, device_group);
      const needle = name_contains.toLowerCase();
      const wanted = types?.length ? types : [...OBJECT_TYPES];
      const found: Array<{ type: string; name: string; location: string; detail?: unknown }> = [];
      await Promise.all(
        scope.locations.flatMap((location) =>
          wanted.map(async (type) => {
            for (const e of await readEntries(target, location, OBJECT_XPATHS[type]).catch(() => [])) {
              const name = nodeText(e["@_name"]);
              if (!name.toLowerCase().includes(needle)) continue;
              const detail =
                type === "profile-group"
                  ? Object.fromEntries(Object.entries(e).filter(([k]) => !k.startsWith("@_")).map(([k, v]) => [k, (v as any)?.member ?? v]))
                  : type === "schedule"
                    ? e["schedule-type"]
                    : undefined;
              found.push({ type, name, location, ...(detail ? { detail } : {}) });
            }
          })
        )
      );
      return jsonResponse({ scope: scope.locations, total: found.length, objects: found.slice(0, 100) });
    }
  );

  server.tool(
    "edl_lookup",
    "[READ-ONLY] Checks whether an IP, domain or URL is present in the External Dynamic Lists applying to a firewall (config from Panorama, current content from the firewall), including EDL exception lists.",
    {
      device: optionalDevice,
      device_group: deviceGroupFilter,
      value: z.string().min(1).max(2048).regex(/^[^\s'"<>]+$/).describe("IP, domain or URL to look for"),
      name: z.string().max(63).regex(/^[^'"<>]+$/).optional().describe("Only this EDL"),
      firewall: panoramaEntry,
    },
    { title: "EDL Lookup", ...READ_ONLY },
    async ({ device, device_group, value, name, firewall }) => {
      const target = panoramaTarget(firewall);
      const pick = await pickDevice(target, { device, device_group, anyConnected: true });
      const dev = pick.device;
      const { locations } = await scopeForDevice(target, dev.serial);
      const valueKind = /^[0-9.:/-]+$/.test(value) ? "ip" : value.includes("/") ? "url" : "domain";

      const edls = (
        await Promise.all(
          locations.map(async (location) =>
            (await readEntries(target, location, "external-list")).map((e: any) => {
              const typeNode = e.type ?? {};
              const kind = Object.keys(typeNode).find((k) => !k.startsWith("@_")) ?? "unknown";
              return {
                location,
                name: nodeText(e["@_name"]),
                kind,
                source: nodeText(typeNode[kind]?.url) || undefined,
                exceptions: asArray(typeNode[kind]?.["exception-list"]?.member).map(nodeText),
              };
            })
          )
        )
      )
        .flat()
        .filter((e) => (!name || e.name === name) && (e.kind === valueKind || e.kind === `predefined-${valueKind}`));

      const entryMatches = (entry: string) =>
        valueKind === "ip"
          ? ipInEntry(value, entry)
          : valueKind === "domain"
            ? entry === value || (entry.startsWith("*.") && value.endsWith(entry.slice(1)))
            : matchEntry(value, entry)?.kind === "match";

      const results = [];
      for (const edl of edls.slice(0, 20)) {
        const cmdKind = edl.kind.replace(/^predefined-/, "");
        let found: string[] = [];
        let error: string | undefined;
        try {
          const data = await op(
            target,
            `<request><system><external-list><show><type><${cmdKind}><name>${xmlEscape(edl.name)}</name></${cmdKind}></type></show></external-list></system></request>`,
            dev.serial
          );
          const strings: string[] = [];
          const walk = (n: any) => {
            if (typeof n === "string") strings.push(...n.split(/\s+/));
            else if (n && typeof n === "object") Object.values(n).forEach(walk);
          };
          walk(data);
          found = strings.filter((s) => s && entryMatches(s)).slice(0, 10);
        } catch (err) {
          error = err instanceof Error ? err.message : String(err);
        }
        results.push({
          edl: edl.name,
          location: edl.location,
          type: edl.kind,
          source: edl.source,
          contains_value: error ? "unknown" : found.length > 0,
          matching_entries: found.length ? found : undefined,
          excepted: edl.exceptions.some(entryMatches) || undefined,
          error,
        });
      }
      return jsonResponse({
        firewall_used: describePick(pick),
        value,
        value_type: valueKind,
        edls_checked: results,
        note: "An EDL only blocks if a rule references it; use find_security_rules with the EDL name.",
      });
    }
  );

  server.tool(
    "run_show_command",
    "[READ-ONLY] Runs an arbitrary read-only operational command (root element must be <show> or <test>) on Panorama, or on a managed firewall with 'device'. Use when no dedicated tool exists.",
    {
      command: z.string().min(1).max(4096).startsWith("<").describe("XML op command, e.g. '<show><system><info></info></system></show>'"),
      device: managedDevice.optional(),
      firewall: panoramaEntry,
    },
    { title: "Run Show Command", ...READ_ONLY },
    async ({ command, device, firewall }) => {
      assertReadOnlyCommand(command);
      const target = panoramaTarget(firewall);
      const serial = device ? (await resolveDevice(target, device)).serial : undefined;
      return jsonResponse(await op(target, command, serial));
    }
  );
}

const commandParser = new XMLParser({ ignoreAttributes: false });

/** Only a single <show> or <test> root is accepted; anything else could change state. */
export function assertReadOnlyCommand(command: string): void {
  let parsed: Record<string, unknown>;
  try {
    parsed = commandParser.parse(command, true);
  } catch (err) {
    throw new Error(`Invalid XML command: ${err instanceof Error ? err.message : String(err)}`);
  }
  const roots = Object.keys(parsed).filter((k) => !k.startsWith("?"));
  if (roots.length !== 1 || !["show", "test"].includes(roots[0]) || Array.isArray(parsed[roots[0]])) {
    throw new Error("Only a single <show> or <test> command is allowed");
  }
}
