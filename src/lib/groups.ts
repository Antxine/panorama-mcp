import { cnOf } from "./ldap.js";

/**
 * Comparable key for a user or group as written in a rule's source_user or returned by AD:
 * "CN=APP-Marketing,DC=corp,DC=onmicrosoft,DC=com", "corp\\app-marketing" and "APP-Marketing"
 * all become "app-marketing". Formats differ between on-prem AD, Cloud Identity Engine and rules.
 */
export function principalKey(value: string): string {
  const v = value.trim();
  if (/^CN=/i.test(v)) return cnOf(v).toLowerCase();
  if (v.includes("\\")) return v.split("\\").pop()!.toLowerCase();
  return v.toLowerCase();
}

export interface Membership {
  /** Log/rule identities of the user (DOMAIN\\id, UPN, mail). */
  identities: string[];
  /** Direct and nested group names (CN) or DNs. */
  groups: string[];
}

export interface SourceUserMatch {
  /** The rule has no user restriction (any / pre-logon / known-user...). */
  unrestricted: boolean;
  /** Entries of source_user matching the user, directly or through a group. */
  matchedBy: string[];
}

const SPECIAL = new Set(["any", "known-user", "unknown", "pre-logon"]);

/** Whether a rule's source_user list lets this user match, and through which entries. */
export function matchSourceUser(sourceUser: string[], membership: Membership): SourceUserMatch {
  if (!sourceUser.length || sourceUser.some((u) => SPECIAL.has(u.toLowerCase()))) {
    // known-user needs a User-ID mapping; any/unknown/pre-logon do not restrict by identity.
    return { unrestricted: true, matchedBy: [] };
  }
  const ids = new Set(membership.identities.map((i) => i.toLowerCase()));
  const idKeys = new Set(membership.identities.map((i) => principalKey(i.split("@")[0])));
  const groupKeys = new Set(membership.groups.map(principalKey));
  const matchedBy = sourceUser.filter((entry) => {
    const lower = entry.toLowerCase();
    if (ids.has(lower)) return true;
    const key = principalKey(entry);
    return groupKeys.has(key) || (!/^CN=/i.test(entry) && idKeys.has(key));
  });
  return { unrestricted: false, matchedBy };
}
