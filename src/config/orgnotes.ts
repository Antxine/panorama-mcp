import { readFileSync } from "fs";
import { join } from "path";
import { homedir } from "os";

/**
 * Organization notes: conventions the config does not tell (which device group serves which traffic,
 * where exceptions go, who owns what). Kept outside the repository so internal names are never published.
 *
 * PANOS_ORG_NOTES overrides the path (default ~/.config/panorama-mcp/org-notes.md).
 * Read on every call so edits apply without restarting the server.
 */

const MAX_CHARS = 20_000;

export function orgNotesPath(env: NodeJS.ProcessEnv = process.env): string {
  return env.PANOS_ORG_NOTES ?? join(homedir(), ".config", "panorama-mcp", "org-notes.md");
}

export function loadOrgNotes(env: NodeJS.ProcessEnv = process.env): string | undefined {
  let text: string;
  try {
    text = readFileSync(orgNotesPath(env), "utf8").trim();
  } catch {
    return undefined;
  }
  if (!text) return undefined;
  return text.length > MAX_CHARS ? `${text.slice(0, MAX_CHARS)}\n[truncated]` : text;
}

/** Appends the organization notes, if any, to a playbook or instruction text. */
export function withOrgNotes(text: string, env: NodeJS.ProcessEnv = process.env): string {
  const notes = loadOrgNotes(env);
  if (!notes) return text;
  return `${text}\n\n# Organization notes (from the local org-notes file; they take precedence over generic guidance)\n\n${notes}`;
}
