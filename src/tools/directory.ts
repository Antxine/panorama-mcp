import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { adLookupEnabled, adLookupUser } from "../api/ad.js";
import { jsonResponse } from "../api/panorama.js";
import { READ_ONLY } from "./debug.js";

export function registerDirectoryTools(server: McpServer) {
  // Needs Windows ADSI and a domain session: hidden elsewhere so the model does not try it.
  if (!adLookupEnabled()) return;

  server.tool(
    "ad_lookup_user",
    "[READ-ONLY] Looks a user up in Active Directory (email, UPN, DOMAIN\\\\id, account name or 'First Last'): account name, UPN, mail, department, disabled flag, AD groups, and the identities under which the user appears in PAN-OS logs (DOMAIN\\\\id for Citrix/AD, UPN for GlobalProtect/Prisma). Use it to turn a ticket's name/email into log identities and to check group-based rules.",
    {
      user: z.string().min(2).max(256).describe("Email, UPN, DOMAIN\\\\id, account name or display name"),
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
}
