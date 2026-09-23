/**
 * Runtime mode from environment variables.
 *
 * PANOS_READ_ONLY (default "true"): only tools annotated readOnlyHint are registered.
 * PANOS_MODULES (default "all"): comma-separated module names, or the "panorama-debug" preset.
 */

export const PANORAMA_DEBUG_PRESET = ["firewalls", "panorama", "utility", "debug", "urlcategories", "diagnose"];

export function isReadOnlyMode(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = (env.PANOS_READ_ONLY ?? "true").trim().toLowerCase();
  return !["false", "0", "no", "off"].includes(raw);
}

export function selectedModules(available: string[], env: NodeJS.ProcessEnv = process.env): string[] {
  const raw = (env.PANOS_MODULES ?? "all").trim().toLowerCase();
  if (!raw || raw === "all") return available;

  const requested = raw
    .split(",")
    .map((m) => m.trim())
    .filter(Boolean)
    .flatMap((m) => (m === "panorama-debug" ? PANORAMA_DEBUG_PRESET : [m]));
  const unknown = requested.filter((m) => !available.includes(m));
  if (unknown.length) {
    throw new Error(`Unknown PANOS_MODULES entries: ${unknown.join(", ")}. Available: ${available.join(", ")}, panorama-debug`);
  }
  return available.filter((m) => requested.includes(m));
}
