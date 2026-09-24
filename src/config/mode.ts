/**
 * Runtime mode from environment variables.
 *
 * PANOS_READ_ONLY (default "true"): only tools annotated readOnlyHint are registered.
 * PANOS_MODULES (default "panorama-debug"): "all", comma-separated module names, or the "panorama-debug" preset.
 * The preset is the default because upstream firewall-level tools confuse the model on a Panorama.
 */

// "panorama" (upstream raw config dumps) is left out: its outputs are huge and covered by debug/diagnose tools.
export const PANORAMA_DEBUG_PRESET = ["firewalls", "utility", "debug", "urlcategories", "diagnose"];

export function isReadOnlyMode(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = (env.PANOS_READ_ONLY ?? "true").trim().toLowerCase();
  return !["false", "0", "no", "off"].includes(raw);
}

export function selectedModules(available: string[], env: NodeJS.ProcessEnv = process.env): string[] {
  const raw = (env.PANOS_MODULES ?? "panorama-debug").trim().toLowerCase();
  if (raw === "all") return available;

  const requested = (raw || "panorama-debug")
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
