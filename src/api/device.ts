import type { FirewallTarget } from "./client.js";
import { listDeviceGroups, listManagedDevices, nodeText, resolveDevice, type ManagedDevice } from "./panorama.js";
import { fetchDgAncestors, listDeviceGroupNames } from "./policy.js";
import { searchLogs } from "./ops.js";

export interface DeviceHints {
  /** Explicit firewall (hostname or serial). */
  device?: string;
  /** Pick a connected firewall of this device group (or of its child groups). */
  device_group?: string;
  /** Pick the firewall this source IP / user's traffic went through, from recent logs. */
  src_ip?: string;
  user?: string;
  /** Where a known log came from, when the caller already has one. */
  origin?: LogOrigin;
  /** Last resort: any connected firewall (enough for PAN-DB lookups). */
  anyConnected?: boolean;
}

export interface DevicePick {
  device: ManagedDevice;
  /** How the firewall was chosen, shown to the model so it can judge the result. */
  reason: string;
}

/** Firewall/service that produced a log entry. */
export interface LogOrigin {
  serial?: string;
  deviceName?: string;
}

export function originOf(entry: Record<string, any> | undefined): LogOrigin | undefined {
  if (!entry) return undefined;
  return { serial: nodeText(entry.serial) || undefined, deviceName: nodeText(entry.device_name) || undefined };
}

/** Latest traffic log of a source IP or user: tells which firewall (or Prisma Access service) handles it. */
export async function originFromLogs(target: FirewallTarget, src_ip?: string, user?: string): Promise<LogOrigin | undefined> {
  if (!src_ip && !user) return undefined;
  const logs = await searchLogs(target, "traffic", { src_ip, user: src_ip ? undefined : user, period: "last-24-hrs" }, 1).catch(
    () => undefined
  );
  return originOf(logs?.entries[0]);
}

/**
 * Prisma Access logs come from cloud services, not managed firewalls: mobile users
 * ("GP cloud service") and remote networks ("RN-..."). Returns the matching device group.
 */
export function prismaDeviceGroup(deviceName: string | undefined, deviceGroups: string[]): string | undefined {
  if (!deviceName) return undefined;
  const find = (re: RegExp) => deviceGroups.find((g) => re.test(g));
  if (/GP cloud service|mobile/i.test(deviceName)) return find(/mobile.?user/i);
  if (/^RN[-_ ]|remote.?network/i.test(deviceName)) return find(/remote.?network/i);
  if (/service.?conn/i.test(deviceName)) return find(/service.?conn/i);
  return undefined;
}

async function firstConnectedInGroup(target: FirewallTarget, deviceGroup: string): Promise<ManagedDevice | undefined> {
  const [groups, devices, ancestors] = await Promise.all([
    listDeviceGroups(target),
    listManagedDevices(target),
    fetchDgAncestors(target),
  ]);
  // The group itself first, then its descendants.
  const names = [deviceGroup, ...[...ancestors.entries()].filter(([, chain]) => chain.includes(deviceGroup)).map(([name]) => name)];
  for (const name of names) {
    for (const member of groups.find((g) => g.name === name)?.devices ?? []) {
      const dev = devices.find((d) => d.serial === member.serial);
      if (dev?.connected) return dev;
    }
  }
  return undefined;
}

/**
 * Chooses the managed firewall to run a live command on, so users can reason in device groups:
 * explicit device > device group member > firewall seen in the user's/IP's logs > any connected firewall.
 */
export async function pickDevice(target: FirewallTarget, hints: DeviceHints): Promise<DevicePick> {
  if (hints.device) return { device: await resolveDevice(target, hints.device), reason: "requested" };

  if (hints.device_group) {
    const dev = await firstConnectedInGroup(target, hints.device_group);
    if (dev) return { device: dev, reason: `connected member of device group '${hints.device_group}'` };
    throw new Error(
      `No connected firewall in device group '${hints.device_group}' (Prisma Access groups have none): live firewall commands are not available for it.`
    );
  }

  const origin = hints.origin ?? (await originFromLogs(target, hints.src_ip, hints.user));
  if (origin?.serial) {
    const dev = await resolveDevice(target, origin.serial).catch(() => undefined);
    const who = hints.src_ip ?? hints.user ?? "this traffic";
    if (dev) return { device: dev, reason: `firewall that handled traffic of ${who} (latest log)` };
  }
  if (origin?.deviceName && prismaDeviceGroup(origin.deviceName, await listDeviceGroupNames(target))) {
    throw new Error(
      `Traffic is handled by Prisma Access ('${origin.deviceName}'), not by a managed firewall: live commands (User-ID, test, sessions) are not available. Rely on logs and on the device group config.`
    );
  }

  if (hints.anyConnected) {
    const dev = (await listManagedDevices(target)).find((d) => d.connected);
    if (dev) return { device: dev, reason: "any connected firewall (result is the same on every firewall)" };
  }

  throw new Error(
    "Cannot choose a firewall: pass 'device_group' or 'device', or a src_ip/user with recent traffic. Use panorama_list_device_groups."
  );
}

export function describePick(pick: DevicePick): string {
  return `${pick.device.hostname} (${pick.device.serial}), ${pick.reason}`;
}
