import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/api/client.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/api/client.js")>()),
  showConfig: vi.fn(),
}));

import { showConfig } from "../../src/api/client.js";
import { clearConfigCache, readEntries } from "../../src/api/panorama.js";

const target = { host: "panorama.example.com", apiKey: "k", verifySSL: false };
const rules = { success: true, data: { rules: { entry: [{ "@_name": "allow-web" }] } } };

describe("config read cache", () => {
  beforeEach(() => {
    clearConfigCache();
    vi.mocked(showConfig).mockReset();
    delete process.env.PANOS_CONFIG_CACHE_SECONDS;
  });

  it("reads each node once, concurrent reads included", async () => {
    vi.mocked(showConfig).mockResolvedValue(rules);
    const [a, b] = await Promise.all([
      readEntries(target, "DG-Branch", "pre-rulebase/security/rules"),
      readEntries(target, "DG-Branch", "pre-rulebase/security/rules"),
    ]);
    await readEntries(target, "DG-Branch", "pre-rulebase/security/rules");
    expect(a).toEqual(b);
    expect(a[0]["@_name"]).toBe("allow-web");
    expect(showConfig).toHaveBeenCalledTimes(1);
  });

  it("does not cache errors", async () => {
    vi.mocked(showConfig).mockResolvedValueOnce({ success: false, error: "HTTP 503" }).mockResolvedValueOnce(rules);
    await expect(readEntries(target, "shared", "pre-rulebase/security/rules")).rejects.toThrow("503");
    expect(await readEntries(target, "shared", "pre-rulebase/security/rules")).toHaveLength(1);
  });

  it("can be disabled", async () => {
    process.env.PANOS_CONFIG_CACHE_SECONDS = "0";
    vi.mocked(showConfig).mockResolvedValue(rules);
    await readEntries(target, "shared", "profile-group");
    await readEntries(target, "shared", "profile-group");
    expect(showConfig).toHaveBeenCalledTimes(2);
  });
});
