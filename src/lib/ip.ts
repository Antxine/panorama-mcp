import { isIPv4 } from "net";

function toInt(ip: string): number {
  return ip.split(".").reduce((acc, octet) => acc * 256 + Number(octet), 0);
}

/**
 * True when an IPv4 address belongs to an EDL-style entry: single IP, CIDR ("10.0.0.0/8")
 * or range ("10.0.0.1-10.0.0.9"). IPv6 entries are compared literally.
 */
export function ipInEntry(ip: string, entry: string): boolean {
  const e = entry.trim();
  if (!isIPv4(ip)) return e.toLowerCase() === ip.toLowerCase();
  const value = toInt(ip);

  const range = /^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$/.exec(e);
  if (range && isIPv4(range[1]) && isIPv4(range[2])) return value >= toInt(range[1]) && value <= toInt(range[2]);

  const [base, prefix] = e.split("/");
  if (!isIPv4(base)) return false;
  if (prefix === undefined) return base === ip;
  const bits = Number(prefix);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const size = 2 ** (32 - bits);
  const start = Math.floor(toInt(base) / size) * size;
  return value >= start && value < start + size;
}
