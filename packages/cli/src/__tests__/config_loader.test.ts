import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { loadRunConfig } from "../config_loader.js";

function tempFile(name: string, content: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), "aspx-cfg-"));
  const file = path.join(dir, name);
  writeFileSync(file, content);
  return file;
}

describe("loadRunConfig", () => {
  it("parses an ASB-style yaml", async () => {
    const file = tempFile(
      "dpi.yml",
      `injection_method: direct_prompt_injection
attack_tool: all
write_db: false
llms:
  - qwen-flash
attack_types:
  - naive
  - combined_attack
task_num: 2
`,
    );
    const cfg = await loadRunConfig(file);
    expect(cfg.injection_method).toBe("direct_prompt_injection");
    expect(cfg.llms).toEqual(["qwen-flash"]);
    expect(cfg.attack_types).toEqual(["naive", "combined_attack"]);
    expect(cfg.task_num).toBe(2);
  });

  it("parses JSON too", async () => {
    const file = tempFile(
      "x.json",
      JSON.stringify({
        injection_method: "clean",
        llms: ["m"],
      }),
    );
    const cfg = await loadRunConfig(file);
    expect(cfg.injection_method).toBe("clean");
  });

  it("rejects an invalid config with a Zod error", async () => {
    const file = tempFile("bad.yml", `llms: []\n`);
    await expect(loadRunConfig(file)).rejects.toThrow();
  });
});
