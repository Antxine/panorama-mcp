import { execFile } from "child_process";

/**
 * Entra ID (Azure AD) groups through the Azure CLI (`az ad user get-member-groups`),
 * using the engineer's `az login` session. Returns transitive memberships, including
 * cloud-only groups that on-prem AD cannot see (Cloud Identity Engine groups in rules).
 */
export function entraLookupEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return !["false", "0", "no", "off"].includes((env.PANOS_ENTRA_LOOKUP ?? "auto").toLowerCase());
}

const UPN_RE = /^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Only UPNs/emails and object IDs are accepted: on Windows az.cmd runs through a shell. */
export function assertEntraId(id: string): string {
  const v = id.trim();
  if (!(UPN_RE.test(v) && !v.includes("'")) && !GUID_RE.test(v)) {
    throw new Error(`Entra lookup needs a UPN/email or object ID, got '${id}'`);
  }
  return v;
}

/** Parses `az ad user get-member-groups` output: [{ "displayName": ..., "id": ... }] (key case varies). */
export function parseMemberGroups(stdout: string): string[] {
  const data = JSON.parse(stdout.trim() || "[]");
  const rows: any[] = Array.isArray(data) ? data : [];
  return rows.map((g) => String(g.displayName ?? g.DisplayName ?? g.id ?? "")).filter(Boolean);
}

export async function entraGroups(id: string): Promise<string[]> {
  if (!entraLookupEnabled()) throw new Error("Entra lookup disabled (PANOS_ENTRA_LOOKUP=false).");
  const user = assertEntraId(id);
  const windows = process.platform === "win32";
  const stdout = await new Promise<string>((resolve, reject) => {
    execFile(
      windows ? "az.cmd" : "az",
      ["ad", "user", "get-member-groups", "--id", user, "--output", "json"],
      // Node refuses to spawn .cmd files without a shell; the id is validated above.
      { timeout: 30_000, windowsHide: true, maxBuffer: 8 * 1024 * 1024, shell: windows },
      (err, out, stderr) => {
        if (!err) return resolve(out);
        const msg = stderr?.trim() || err.message;
        reject(
          new Error(
            /az login|AADSTS|expired|refresh token/i.test(msg)
              ? `Azure CLI session missing or expired: run 'az login' on this machine. (${msg.split("\n")[0]})`
              : /not recognized|ENOENT|not found/i.test(msg)
                ? "Azure CLI (az) is not installed on this machine."
                : `Entra lookup failed: ${msg.split("\n")[0]}`
          )
        );
      }
    );
  });
  return parseMemberGroups(stdout);
}
