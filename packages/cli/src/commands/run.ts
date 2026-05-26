import { writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import kleur from "kleur";
import {
  AGENT_REGISTRY,
  estimateTotalUnits,
  buildDefaultRegistry,
  readLLMEnv,
  runOrchestrator,
  type OrchestratorOpts,
} from "@asp-x/core";
import { loadRunConfig } from "../config_loader.js";

export interface RunCmdOpts {
  configPath: string;
  outDir?: string;
  /** If set, prints one line per result as they arrive. */
  verbose?: boolean;
}

export async function runCommand(opts: RunCmdOpts): Promise<number> {
  const config = await loadRunConfig(opts.configPath);
  const env = readLLMEnv();
  const registry = buildDefaultRegistry(env);
  const provider = registry.resolve(config.llms[0]!);

  const total = estimateTotalUnits(config);
  console.log(
    kleur.cyan(
      `▸ ${config.injection_method} | agents=${config.agents?.length ?? AGENT_REGISTRY.listAgents().length} | tasks/agent=${config.task_num ?? "all"} | variants=${config.attack_types.length} | tool_set=${config.attack_tool} | llms=${config.llms.length} | defense=${config.defense_type ?? "none"}`,
    ),
  );
  console.log(kleur.dim(`  ≈ ${total} runs`));

  let done = 0;
  const runArgs: OrchestratorOpts = {
    config,
    provider,
    judgeModel: config.judge_model ?? env.judgeModel,
    onResult: (r) => {
      done += 1;
      if (opts.verbose) {
        const flags = [
          r.judge.attack_success ? kleur.red("ASR✓") : kleur.dim("ASR✗"),
          r.judge.refused ? kleur.yellow("REFUSE") : "",
          r.judge.original_task_success ? kleur.green("PNA✓") : kleur.dim("PNA✗"),
          r.error ? kleur.bgRed(" ERR ") : "",
        ]
          .filter((s) => s.length > 0)
          .join(" ");
        console.log(
          `  [${done.toString().padStart(4)}/${total}] ${r.agent_id} :: ${r.attack_method} :: ${r.llm} → ${flags}`,
        );
      }
    },
  };
  const out = await runOrchestrator(runArgs);

  console.log("");
  console.log(kleur.bold("Aggregate metrics"));
  console.log(`  N        ${out.metrics.n}`);
  console.log(`  ASR      ${(out.metrics.asr * 100).toFixed(1)}%`);
  console.log(`  RR       ${(out.metrics.rr * 100).toFixed(1)}%`);
  if (out.metrics.pna !== undefined) {
    console.log(`  PNA      ${(out.metrics.pna * 100).toFixed(1)}%`);
  }

  const outDir = opts.outDir
    ? path.resolve(opts.outDir)
    : path.resolve(process.cwd(), "logs", out.run_id);
  await mkdir(outDir, { recursive: true });
  await writeFile(
    path.join(outDir, "results.json"),
    JSON.stringify(out, null, 2),
  );
  console.log(kleur.dim(`  → wrote ${path.join(outDir, "results.json")}`));
  return out.results.some((r) => r.error) ? 1 : 0;
}
