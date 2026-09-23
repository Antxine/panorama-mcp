/**
 * Approximation of PAN-OS custom URL category matching, used to tell whether a URL
 * is already covered by an existing category before suggesting a new one.
 *
 * PAN-OS rules (URL List type), simplified:
 *  - Entries are matched against "host/path" without scheme, case-insensitively.
 *  - An entry matches as a prefix of the URL, on token boundaries: "example.com"
 *    matches "example.com", "example.com/a" and also "example.com.evil.net"
 *    (hence the PAN-OS advice to end domains with "/").
 *  - "*" and "^" are wildcards for exactly one token (a label between "." or "/").
 *    "*.example.com" matches "www.example.com" but not "example.com".
 *
 * Results are hints: the firewall remains the source of truth (test_url_category).
 */

export type UrlMatchKind = "match" | "related";

export interface UrlEntryMatch {
  entry: string;
  kind: UrlMatchKind;
}

/** "https://User@WWW.Example.com:443/Path?q=1" -> "www.example.com/Path" (host lowercased). */
export function normalizeUrl(raw: string): string {
  let url = raw.trim();
  url = url.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  url = url.replace(/[?#].*$/, "");
  const slash = url.indexOf("/");
  let host = slash === -1 ? url : url.slice(0, slash);
  const path = slash === -1 ? "" : url.slice(slash);
  host = host.replace(/^[^@]*@/, "").replace(/:\d+$/, "").replace(/\.$/, "").toLowerCase();
  return host + path;
}

export function hostOf(normalized: string): string {
  const slash = normalized.indexOf("/");
  return slash === -1 ? normalized : normalized.slice(0, slash);
}

function escapeRegex(s: string): string {
  return s.replace(/[.+?${}()|[\]\\]/g, "\\$&");
}

function entryToRegex(entry: string): RegExp {
  const normalized = normalizeUrl(entry);
  const pattern = normalized
    .split(/([*^])/)
    .map((part) => (part === "*" || part === "^" ? "[^./]+" : escapeRegex(part)))
    .join("");
  // Prefix match that stops on a token boundary (end, ".", "/" or ":").
  const boundary = normalized.endsWith("/") || normalized.endsWith(".") ? "" : "(?=$|[./:])";
  return new RegExp(`^${pattern}${boundary}`, "i");
}

/** Registrable-ish base domain ("a.b.example.co.uk" -> "example.co.uk", best effort). */
export function baseDomain(host: string): string {
  const labels = host.split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const secondLevel = new Set(["co", "com", "net", "org", "gov", "ac", "edu", "gouv"]);
  const take = secondLevel.has(labels[labels.length - 2]) && labels[labels.length - 1].length === 2 ? 3 : 2;
  return labels.slice(-take).join(".");
}

/**
 * Checks one category entry against a URL.
 * - "match": PAN-OS would most likely classify the URL in this category.
 * - "related": same base domain but no match (e.g. entry "example.com/" vs URL
 *   "www.example.com"), usually the cause of "the URL is in the category but still blocked".
 */
export function matchEntry(url: string, entry: string): UrlEntryMatch | null {
  const target = normalizeUrl(url);
  if (!entry.trim()) return null;
  if (entryToRegex(entry).test(target)) return { entry, kind: "match" };

  const entryHost = hostOf(normalizeUrl(entry)).replace(/^[*^]\./, "");
  const base = baseDomain(hostOf(target));
  if (entryHost && (entryHost === base || entryHost.endsWith(`.${base}`))) return { entry, kind: "related" };
  return null;
}

/** All entries of a list that match or relate to the URL, matches first. */
export function matchEntries(url: string, entries: string[]): UrlEntryMatch[] {
  const found = entries.map((e) => matchEntry(url, e)).filter((m): m is UrlEntryMatch => m !== null);
  return found.sort((a, b) => (a.kind === b.kind ? 0 : a.kind === "match" ? -1 : 1));
}
