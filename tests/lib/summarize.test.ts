import { describe, it, expect } from "vitest";
import { summarizeLogs } from "../../src/lib/summarize.js";

describe("summarizeLogs", () => {
  it("groups URL logs by host, action, categories and rule", () => {
    const base = { action: "block-url", url_category_list: "SOC - x,online-storage-and-backup", rule: "web" };
    const groups = summarizeLogs("url", [
      { ...base, misc: "www.yumpu.com/fr/embed/1", srcuser: "a@corp.com", src: "10.0.0.1", receive_time: "2026/09/24 10:00:00" },
      { ...base, misc: "www.yumpu.com/other", srcuser: "b@corp.com", src: "10.0.0.2", receive_time: "2026/09/24 10:05:00" },
      { ...base, misc: "other.com/", srcuser: "a@corp.com", src: "10.0.0.1", receive_time: "2026/09/24 09:00:00" },
    ]);
    expect(groups).toHaveLength(2);
    expect(groups[0]).toMatchObject({
      count: 2,
      key: { host: "www.yumpu.com", action: "block-url", rule: "web" },
      users: ["a@corp.com", "b@corp.com"],
      first_seen: "2026/09/24 10:00:00",
      last_seen: "2026/09/24 10:05:00",
    });
  });

  it("caps listed users", () => {
    const entries = Array.from({ length: 8 }, (_, i) => ({ dst: "1.1.1.1", action: "deny", srcuser: `u${i}@corp.com` }));
    const [g] = summarizeLogs("traffic", entries);
    expect(g.users).toHaveLength(6);
    expect(g.users[5]).toBe("+3 more");
  });
});
