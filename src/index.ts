#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadFirewallConfig } from "./config/firewalls.js";
import { isKeychainAvailable } from "./config/keychain.js";
import { describeProxy } from "./api/proxy.js";

import { registerFirewallTools } from "./tools/firewalls.js";
import { registerSystemTools } from "./tools/system.js";
import { registerNetworkTools } from "./tools/network.js";
import { registerSecurityTools } from "./tools/security.js";
import { registerObjectsTools } from "./tools/objects.js";
import { registerNatTools } from "./tools/nat.js";
import { registerUserIdTools } from "./tools/userid.js";
import { registerAdminTools } from "./tools/admin.js";
import { registerVpnTools } from "./tools/vpn.js";
import { registerPanoramaTools } from "./tools/panorama.js";
import { registerLogsTools } from "./tools/logs.js";
import { registerThreatTools } from "./tools/threat.js";
import { registerCertificatesTools } from "./tools/certificates.js";
import { registerLicensesTools } from "./tools/licenses.js";
import { registerConfigTools } from "./tools/config.js";
import { registerUtilityTools } from "./tools/utility.js";
import { registerDebugTools } from "./tools/debug.js";
import { registerUrlCategoryTools } from "./tools/urlcategories.js";
import { registerDiagnoseTools } from "./tools/diagnose.js";
import { registerDirectoryTools } from "./tools/directory.js";
import { SERVER_INSTRUCTIONS } from "./playbook.js";
import { isReadOnlyMode, selectedModules } from "./config/mode.js";

const server = new McpServer(
  {
    name: "panos-mcp",
    version: "1.3.30",
  },
  { instructions: SERVER_INSTRUCTIONS }
);

const readOnly = isReadOnlyMode();
let skippedTools = 0;

// Wrap all tool handlers to catch unexpected errors cleanly
const _tool = server.tool.bind(server);
(server.tool as any) = function (...args: any[]) {
  const last = args.length - 1;
  const handler = args[last];
  // Read-only mode: tools not explicitly annotated readOnlyHint are never registered.
  const annotations = args.find((a, i) => i > 0 && i < last && a && typeof a === "object" && "readOnlyHint" in a);
  if (readOnly && annotations?.readOnlyHint !== true) {
    skippedTools++;
    return undefined;
  }
  args[last] = async (...hArgs: any[]) => {
    try {
      return await handler(...hArgs);
    } catch (error) {
      return {
        content: [{ type: "text" as const, text: `Error: ${error instanceof Error ? error.message : String(error)}` }],
      };
    }
  };
  return (_tool as (...a: any[]) => any)(...args);
};

const modules: Record<string, (s: McpServer) => void> = {
  firewalls: registerFirewallTools,
  system: registerSystemTools,
  network: registerNetworkTools,
  security: registerSecurityTools,
  objects: registerObjectsTools,
  nat: registerNatTools,
  userid: registerUserIdTools,
  admin: registerAdminTools,
  vpn: registerVpnTools,
  panorama: registerPanoramaTools,
  logs: registerLogsTools,
  threat: registerThreatTools,
  certificates: registerCertificatesTools,
  licenses: registerLicensesTools,
  config: registerConfigTools,
  utility: registerUtilityTools,
  debug: registerDebugTools,
  urlcategories: registerUrlCategoryTools,
  diagnose: registerDiagnoseTools,
  directory: registerDirectoryTools,
};

const enabledModules = selectedModules(Object.keys(modules));
for (const name of enabledModules) modules[name](server);

async function main() {
  await loadFirewallConfig();
  if (!isKeychainAvailable()) {
    process.stderr.write(
      "[panos-mcp] WARNING: System keychain unavailable — API keys are stored in plaintext. " +
      "Install a keychain provider (macOS Keychain, libsecret on Linux, Windows Credential Manager) " +
      "and re-run `panos-mcp keygen` to migrate keys to secure storage.\n"
    );
  }
  process.stderr.write(
    `[panos-mcp] modules: ${enabledModules.join(", ")}; read-only: ${readOnly}` +
      (skippedTools ? ` (${skippedTools} write tools disabled, set PANOS_READ_ONLY=false to enable)` : "") +
      "\n"
  );
  const proxy = describeProxy();
  if (proxy) {
    console.error(`PanOS proxy: ${proxy}`);
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
