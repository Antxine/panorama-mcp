import type { FirewallTarget } from "./client.js";
import { listDeviceGroups, listManagedDevices, nodeText, resolveDevice, type ManagedDevice } from "./panorama.js";
import { fetchDgAncestors } from "./policy.js";
import { searchLogs } from "./ops.js";

export interface DeviceHints {
  /** Explicit firewall (hostname or serial). */
  device?: string;
  /** Pick a connected firewall of this device group (or of its child groups). */
  device_group?: string;
  /** Pick the firewall this source IP / user's traffic went through, from recent logs. */
  src_ip?: string;
  user?: string;
  /** Last resort: any connected firewall (enough for PAN-DB lookups). */
  anyConnected?: boolean;
}

export interface DevicePick {
  device: ManagedDevice;
  /** How the firewall was chosen, shown to the model so it can judge the result. */
  reason: string;
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
    throw new Error(`No connected firewall in device group '${hints.device_group}'. Use panorama_list_device_groups.`);
  }

  if (hints.src_ip || hints.user) {
    const logs = await searchLogs(target, "traffic", { src_ip: hints.src_ip, user: hints.src_ip ? undefined : hints.user, period: "last-24-hrs" }, 1).catch(
      () => undefined
    );
    const serial = logs?.entries[0] ? nodeText(logs.entries[0].serial) : "";
    if (serial) {
      const who = hints.src_ip ?? hints.user;
      return { device: await resolveDevice(target, serial), reason: `firewall that handled traffic of ${who} (latest traffic log)` };
    }
  }

  if (hints.anyConnected) {
    const dev = (await listManagedDevices(target)).find((d) => d.connected);
    if (dev) return { device: dev, reason: "any connected firewall (result is the same on every firewall)" };
  }

  const groups = (await listDeviceGroups(target)).map((g) => g.name);
  throw new Error(
    `Cannot choose a firewall: pass 'device_group' (one of: ${groups.join(", ")}) or 'device', or a src_ip/user with recent traffic.`
  );
}

export function describePick(pick: DevicePick): string {
  return `${pick.device.hostname} (${pick.device.serial}), ${pick.reason}`;
}
