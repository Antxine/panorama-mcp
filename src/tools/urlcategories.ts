import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse } from "../api/panorama.js";
import { panoramaTarget } from "../api/ops.js";
import { fetchCustomUrlCategories } from "../api/policy.js";
import { analyzeUrl, categoryUsage, resolveScope, summarizeUsage } from "../api/urlanalysis.js";
import { firewallName } from "../schemas/panos.js";
import { deviceGroupFilter, managedDevice, urlInput } from "../schemas/debug.js";
import { READ_ONLY } from "./debug.js";

const panoramaEntry = firewallName.describe("Panorama entry from firewalls.json. Optional when a single Panorama is configured.");
const categoryName = z.string().min(1).max(63).regex(/^[^'"<>]+$/).describe("Custom URL category name, or PAN-DB category (e.g. 'social-networking')");

export function registerUrlCategoryTools(server: McpServer) {
  server.tool(
    "url_category_list",
    "[READ-ONLY] Lists custom URL categories (shared and device groups) with their type and number of entries. Use url_category_get for the entries.",
    {
      device_group: deviceGroupFilter,
      name_contains: z.string().max(63).optional().describe("Case-insensitive filter on name or description"),
      firewall: panoramaEntry,
    },
    { title: "List Custom URL Categories", ...READ_ONLY },
    async ({ device_group, name_contains, firewall }) => {
      const target = panoramaTarget(firewall);
      const scope = await resolveScope(target, undefined, device_group);
      const needle = name_contains?.toLowerCase();
      const cats = (await fetchCustomUrlCategories(target, scope.locations)).filter(
        (c) => !needle || c.name.toLowerCase().includes(needle) || (c.description ?? "").toLowerCase().includes(needle)
      );
      return jsonResponse(
        cats.map((c) => ({ name: c.name, location: c.location, type: c.type, entries: c.list.length, description: c.description }))
      );
    }
  );

  server.tool(
    "url_category_get",
    "[READ-ONLY] Returns the entries of a custom URL category (URL list, or PAN-DB categories for 'Category Match'). Searches shared and every device group unless device_group is set.",
    {
      name: categoryName,
      device_group: deviceGroupFilter,
      firewall: panoramaEntry,
    },
    { title: "Get Custom URL Category", ...READ_ONLY },
    async ({ name, device_group, firewall }) => {
      const target = panoramaTarget(firewall);
      const scope = await resolveScope(target, undefined, device_group);
      const cats = (await fetchCustomUrlCategories(target, scope.locations)).filter((c) => c.name === name);
      if (!cats.length) throw new Error(`Custom URL category '${name}' not found in ${scope.locations.join(", ")}`);
      return jsonResponse(cats);
    }
  );

  server.tool(
    "url_category_find",
    "[READ-ONLY] Finds which existing custom URL categories already cover a URL (PAN-OS wildcard/prefix rules), which ones contain the same domain but do not match (pattern issue), and with 'device' the PAN-DB category. Run this BEFORE proposing any new URL category.",
    {
      url: urlInput,
      device_group: deviceGroupFilter.describe("Device group: its categories plus those inherited from shared/parents. All locations when omitted."),
      device: managedDevice.optional().describe("Specific firewall; usually omit it"),
      firewall: panoramaEntry,
    },
    { title: "Find URL in Categories", ...READ_ONLY },
    async ({ url, device, device_group, firewall }) => {
      const target = panoramaTarget(firewall);
      const scope = await resolveScope(target, device, device_group, { anyConnected: true });
      const analysis = await analyzeUrl(target, url, scope);
      return jsonResponse({
        scope: scope.locations,
        firewall_used_for_pan_db: scope.deviceDescription,
        covered_by: analysis.covering,
        category_match: analysis.categoryMatch,
        same_domain_not_matching: analysis.related,
        pan_db: analysis.panDb ?? analysis.panDbError,
        note: "Matching is an approximation of PAN-OS rules; the firewall is the source of truth.",
      });
    }
  );

  server.tool(
    "url_category_usage",
    "[READ-ONLY] Shows where URL categories are used: security/decryption rules referencing them (in evaluation order when 'device' is set) and URL filtering profiles acting on them, with the rules using those profiles.",
    {
      categories: z.array(categoryName).min(1).max(20).describe("Custom or PAN-DB categories"),
      device: managedDevice.optional(),
      device_group: deviceGroupFilter,
      firewall: panoramaEntry,
    },
    { title: "URL Category Usage", ...READ_ONLY },
    async ({ categories, device, device_group, firewall }) => {
      const target = panoramaTarget(firewall);
      const scope = await resolveScope(target, device, device_group);
      const usage = await categoryUsage(target, categories, scope);
      return jsonResponse({ scope: scope.locations, ...summarizeUsage(usage) });
    }
  );
}

