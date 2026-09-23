import { describe, it, expect } from "vitest";
import { assertReadOnlyCommand } from "../../src/tools/debug.js";

describe("assertReadOnlyCommand", () => {
  it.each(["<show><system><info></info></system></show>", "<test><url>example.com</url></test>"])("accepts %s", (cmd) => {
    expect(() => assertReadOnlyCommand(cmd)).not.toThrow();
  });

  it.each([
    "<request><restart><system></system></restart></request>",
    "<show><clock/></show><request><restart><system/></restart></request>",
    "<set><cli><pager>off</pager></cli></set>",
    "<show><clock>",
    "<debug><dataplane/></debug>",
  ])("rejects %s", (cmd) => {
    expect(() => assertReadOnlyCommand(cmd)).toThrow();
  });
});
