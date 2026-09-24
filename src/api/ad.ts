import { execFile } from "child_process";
import { buildUserFilter, cnOf, logIdentities, type AdUser } from "../lib/ldap.js";

/**
 * Active Directory lookups through Windows PowerShell ADSI, using the logged-in user's
 * domain credentials. The LDAP filter is passed through an environment variable, never
 * interpolated into the script, so user input cannot inject PowerShell.
 */
export const AD_SCRIPT = `
$ErrorActionPreference = 'Stop'
$props = 'samaccountname','userprincipalname','mail','displayname','distinguishedname','memberof','department','company','useraccountcontrol'
function Find-Users([string]$root) {
  $s = if ($root) { New-Object DirectoryServices.DirectorySearcher([ADSI]$root) } else { New-Object DirectoryServices.DirectorySearcher }
  $s.Filter = $env:PANOS_MCP_LDAP_FILTER
  $s.SizeLimit = 10
  foreach ($p in $props) { [void]$s.PropertiesToLoad.Add($p) }
  return @($s.FindAll())
}
$source = 'domain'
$found = Find-Users $null
if ($found.Count -eq 0) {
  try {
    $forest = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name
    $found = Find-Users "GC://$forest"
    $source = 'global-catalog'
  } catch { }
}
$results = @($found | ForEach-Object {
  $p = $_.Properties
  [pscustomobject]@{
    sam = [string]($p['samaccountname'] | Select-Object -First 1)
    upn = [string]($p['userprincipalname'] | Select-Object -First 1)
    mail = [string]($p['mail'] | Select-Object -First 1)
    displayName = [string]($p['displayname'] | Select-Object -First 1)
    dn = [string]($p['distinguishedname'] | Select-Object -First 1)
    department = [string]($p['department'] | Select-Object -First 1)
    company = [string]($p['company'] | Select-Object -First 1)
    uac = [int]($p['useraccountcontrol'] | Select-Object -First 1)
    memberOf = @($p['memberof'] | ForEach-Object { [string]$_ })
  }
})
# Nested membership (LDAP_MATCHING_RULE_IN_CHAIN): memberOf only lists direct groups.
$nested = @()
if ($results.Count -eq 1 -and $results[0].dn) {
  try {
    $dn = $results[0].dn -replace '\\\\', '\\5c' -replace '\\*', '\\2a' -replace '\\(', '\\28' -replace '\\)', '\\29'
    $g = New-Object DirectoryServices.DirectorySearcher
    if ($source -eq 'global-catalog') { $g.SearchRoot = [ADSI]"GC://$forest" }
    $g.Filter = "(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=$dn))"
    $g.PageSize = 500
    $g.ClientTimeout = [TimeSpan]::FromSeconds(10)
    [void]$g.PropertiesToLoad.Add('distinguishedname')
    $nested = @($g.FindAll() | ForEach-Object { [string]($_.Properties['distinguishedname'] | Select-Object -First 1) })
  } catch { }
}
[pscustomobject]@{ source = $source; results = $results; nested = $nested } | ConvertTo-Json -Depth 4 -Compress
`;

export function adLookupEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const mode = (env.PANOS_AD_LOOKUP ?? "auto").toLowerCase();
  if (["false", "0", "no", "off"].includes(mode)) return false;
  if (["true", "1", "yes", "on"].includes(mode)) return true;
  return process.platform === "win32";
}

export interface AdLookupResult {
  source: string;
  users: Array<AdUser & { log_identities: string[]; direct_group_count: number }>;
}

export async function adLookupUser(input: string): Promise<AdLookupResult> {
  if (!adLookupEnabled()) throw new Error("AD lookup is only available on a domain-joined Windows machine (set PANOS_AD_LOOKUP=true to force).");
  const filter = buildUserFilter(input);
  const stdout = await new Promise<string>((resolve, reject) => {
    execFile(
      "powershell.exe",
      // -EncodedCommand (UTF-16LE base64) avoids Windows command-line quoting issues with the script.
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", Buffer.from(AD_SCRIPT, "utf16le").toString("base64")],
      { env: { ...process.env, PANOS_MCP_LDAP_FILTER: filter }, timeout: 20_000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 },
      (err, out, stderr) => (err ? reject(new Error(`AD lookup failed: ${stderr?.trim() || err.message}`)) : resolve(out))
    );
  });
  const parsed = JSON.parse(stdout.trim() || '{"source":"domain","results":[]}');
  const rows: any[] = Array.isArray(parsed.results) ? parsed.results : parsed.results ? [parsed.results] : [];
  const nested: string[] = Array.isArray(parsed.nested) ? parsed.nested : parsed.nested ? [parsed.nested] : [];
  return {
    source: parsed.source,
    users: rows.map((r) => {
      const direct: string[] = Array.isArray(r.memberOf) ? r.memberOf : r.memberOf ? [r.memberOf] : [];
      // Nested groups are resolved for single matches only; they include the direct ones.
      const groupDns = rows.length === 1 && nested.length ? [...new Set([...direct, ...nested])] : direct;
      const user: AdUser = {
        sam: r.sam ?? "",
        upn: r.upn ?? "",
        mail: r.mail ?? "",
        displayName: r.displayName ?? "",
        dn: r.dn ?? "",
        department: r.department || undefined,
        company: r.company || undefined,
        // ACCOUNTDISABLE flag of userAccountControl.
        disabled: (Number(r.uac) & 2) === 2,
        groups: groupDns.map(cnOf),
        groupDns,
      };
      return { ...user, direct_group_count: direct.length, log_identities: logIdentities(user) };
    }),
  };
}

/** Identities and groups of a single AD user, for matching rules' source_user; undefined when unknown or ambiguous. */
export async function adMembership(user: string): Promise<{ user: AdLookupResult["users"][number]; identities: string[]; groups: string[] } | undefined> {
  if (!adLookupEnabled()) return undefined;
  const result = await adLookupUser(user);
  if (result.users.length !== 1) return undefined;
  const u = result.users[0];
  return { user: u, identities: u.log_identities, groups: u.groupDns };
}

/**
 * Everything known about a user's identity for rule matching: on-prem AD (identities, nested
 * groups) and Entra ID groups (cloud-only included). Sources that are unavailable are skipped.
 */
export async function userMembership(
  user: string
): Promise<{ identities: string[]; groups: string[]; displayName?: string; sources: string[]; warnings: string[] } | undefined> {
  const { entraGroups, entraLookupEnabled } = await import("./entra.js");
  const warnings: string[] = [];
  const sources: string[] = [];
  let identities: string[] = [];
  let groups: string[] = [];
  let displayName: string | undefined;

  try {
    const ad = await adMembership(user);
    if (ad) {
      identities = ad.identities;
      groups = ad.groups;
      displayName = ad.user.displayName;
      sources.push("active-directory");
    }
  } catch (err) {
    warnings.push(err instanceof Error ? err.message : String(err));
  }

  const upn = identities.find((i) => i.includes("@")) ?? (user.includes("@") ? user : undefined);
  if (upn && entraLookupEnabled()) {
    try {
      groups = [...new Set([...groups, ...(await entraGroups(upn))])];
      sources.push("entra-id");
      if (!identities.length) identities = [upn.toLowerCase()];
    } catch (err) {
      warnings.push(err instanceof Error ? err.message : String(err));
    }
  }
  if (!sources.length) return undefined;
  return { identities, groups, displayName, sources, warnings };
}
