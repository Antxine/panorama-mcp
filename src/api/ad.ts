import { execFile } from "child_process";
import { buildUserFilter, cnOf, logIdentities, type AdUser } from "../lib/ldap.js";

/**
 * Active Directory lookups through Windows PowerShell ADSI, using the logged-in user's
 * domain credentials. The LDAP filter is passed through an environment variable, never
 * interpolated into the script, so user input cannot inject PowerShell.
 */
const SCRIPT = `
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
[pscustomobject]@{ source = $source; results = $results } | ConvertTo-Json -Depth 4 -Compress
`;

export function adLookupEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const mode = (env.PANOS_AD_LOOKUP ?? "auto").toLowerCase();
  if (["false", "0", "no", "off"].includes(mode)) return false;
  if (["true", "1", "yes", "on"].includes(mode)) return true;
  return process.platform === "win32";
}

export interface AdLookupResult {
  source: string;
  users: Array<AdUser & { log_identities: string[] }>;
}

export async function adLookupUser(input: string): Promise<AdLookupResult> {
  if (!adLookupEnabled()) throw new Error("AD lookup is only available on a domain-joined Windows machine (set PANOS_AD_LOOKUP=true to force).");
  const filter = buildUserFilter(input);
  const stdout = await new Promise<string>((resolve, reject) => {
    execFile(
      "powershell.exe",
      // -EncodedCommand (UTF-16LE base64) avoids Windows command-line quoting issues with the script.
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", Buffer.from(SCRIPT, "utf16le").toString("base64")],
      { env: { ...process.env, PANOS_MCP_LDAP_FILTER: filter }, timeout: 20_000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 },
      (err, out, stderr) => (err ? reject(new Error(`AD lookup failed: ${stderr?.trim() || err.message}`)) : resolve(out))
    );
  });
  const parsed = JSON.parse(stdout.trim() || '{"source":"domain","results":[]}');
  const rows: any[] = Array.isArray(parsed.results) ? parsed.results : parsed.results ? [parsed.results] : [];
  return {
    source: parsed.source,
    users: rows.map((r) => {
      const groupDns: string[] = Array.isArray(r.memberOf) ? r.memberOf : r.memberOf ? [r.memberOf] : [];
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
      return { ...user, log_identities: logIdentities(user) };
    }),
  };
}
