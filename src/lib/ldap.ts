/** RFC 4515 escaping for values placed inside an LDAP filter. */
export function escapeLdap(value: string): string {
  return value.replace(/[\\*()\0]/g, (c) => `\\${c.charCodeAt(0).toString(16).padStart(2, "0")}`);
}

const PERSON = "(objectCategory=person)(objectClass=user)";

/**
 * LDAP filter finding a user from what a ticket usually contains:
 * email/UPN, DOMAIN\id, account name, or "First Last" display name.
 */
export function buildUserFilter(input: string): string {
  const raw = input.trim();
  if (!raw) throw new Error("Empty user");

  if (raw.includes("@")) {
    const v = escapeLdap(raw);
    return `(&${PERSON}(|(mail=${v})(userPrincipalName=${v})(proxyAddresses=smtp:${v})))`;
  }
  if (raw.includes("\\")) {
    return `(&${PERSON}(sAMAccountName=${escapeLdap(raw.split("\\").pop()!)}))`;
  }
  const words = raw.split(/\s+/).filter(Boolean);
  if (words.length === 1) {
    const v = escapeLdap(raw);
    return `(&${PERSON}(|(sAMAccountName=${v})(sn=${v})(displayName=*${v}*)))`;
  }
  const [a, b] = [escapeLdap(words[0]), escapeLdap(words.slice(1).join(" "))];
  const full = escapeLdap(words.join(" "));
  return `(&${PERSON}(|(displayName=*${full}*)(&(givenName=${a}*)(sn=${b}*))(&(givenName=${b}*)(sn=${a}*))))`;
}

/** NetBIOS-style domain guess from a DN: "CN=x,OU=y,DC=emea,DC=corp,DC=local" -> "emea". */
export function domainFromDn(dn: string): string | undefined {
  return /(?:^|,)DC=([^,]+)/i.exec(dn)?.[1]?.toLowerCase();
}

export interface AdUser {
  sam: string;
  upn: string;
  mail: string;
  displayName: string;
  dn: string;
  department?: string;
  company?: string;
  disabled: boolean;
  groups: string[];
  groupDns: string[];
}

/** Identities under which this user may appear in PAN-OS logs and rules. */
export function logIdentities(user: AdUser): string[] {
  const ids = new Set<string>();
  const domain = domainFromDn(user.dn);
  if (domain && user.sam) ids.add(`${domain}\\${user.sam.toLowerCase()}`);
  if (user.upn) ids.add(user.upn.toLowerCase());
  if (user.mail) ids.add(user.mail.toLowerCase());
  return [...ids];
}

/** "CN=APP-Marketing-Team,OU=Groups,DC=corp" -> "APP-Marketing-Team". */
export function cnOf(dn: string): string {
  return /^CN=((?:\\,|[^,])+)/i.exec(dn)?.[1]?.replace(/\\,/g, ",") ?? dn;
}
