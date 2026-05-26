import { readFile } from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import { RunConfigSchema, type RunConfig } from "@asp-x/shared";

/**
 * Load and validate a run config from a file. Auto-detects .json vs .yml/.yaml.
 * ASB-format yaml files (with the original snake_case field names) parse
 * directly because RunConfigSchema mirrors them.
 */
export async function loadRunConfig(filePath: string): Promise<RunConfig> {
  const abs = path.resolve(filePath);
  const text = await readFile(abs, "utf8");
  const ext = path.extname(abs).toLowerCase();
  let raw: unknown;
  if (ext === ".json") raw = JSON.parse(text);
  else raw = YAML.parse(text);

  // ASB yaml uses `injection_method: null` for some legacy clean configs.
  if (raw && typeof raw === "object" && (raw as { injection_method?: unknown }).injection_method == null) {
    (raw as { injection_method?: string }).injection_method = "clean";
  }

  return RunConfigSchema.parse(raw);
}
