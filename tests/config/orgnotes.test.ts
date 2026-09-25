import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { loadOrgNotes, withOrgNotes } from "../../src/config/orgnotes.js";

describe("org notes", () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "orgnotes-"));
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("returns the text unchanged when the file is missing", () => {
    const env = { PANOS_ORG_NOTES: join(dir, "missing.md") };
    expect(loadOrgNotes(env)).toBeUndefined();
    expect(withOrgNotes("playbook", env)).toBe("playbook");
  });

  it("ignores an empty file", () => {
    const path = join(dir, "empty.md");
    writeFileSync(path, "  \n");
    expect(withOrgNotes("playbook", { PANOS_ORG_NOTES: path })).toBe("playbook");
  });

  it("appends the notes after the text", () => {
    const path = join(dir, "notes.md");
    writeFileSync(path, "- DG-Users-Rules: regular users\n- DG-VDI-Rules: VDI sessions\n");
    const out = withOrgNotes("playbook", { PANOS_ORG_NOTES: path });
    expect(out.startsWith("playbook\n\n# Organization notes")).toBe(true);
    expect(out).toContain("DG-VDI-Rules: VDI sessions");
  });

  it("truncates very large files", () => {
    const path = join(dir, "big.md");
    writeFileSync(path, "x".repeat(30_000));
    const notes = loadOrgNotes({ PANOS_ORG_NOTES: path })!;
    expect(notes.length).toBeLessThan(20_100);
    expect(notes.endsWith("[truncated]")).toBe(true);
  });
});
