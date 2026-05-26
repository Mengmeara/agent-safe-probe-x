#!/usr/bin/env node
import { Command } from "commander";
import "dotenv/config";
import {
  listAgentsCommand,
  listAttacksCommand,
  listDefensesCommand,
  listModelsCommand,
} from "./commands/list.js";
import { runCommand } from "./commands/run.js";

const program = new Command();
program
  .name("asp-x")
  .description(
    "Agent Safe Probe — TypeScript rewrite of ASB with web UI and trace visualization.",
  )
  .version("0.1.0");

program
  .command("run")
  .description("Run a benchmark configuration end-to-end and write results.")
  .requiredOption("-c, --config <path>", "Path to a yaml or json RunConfig")
  .option("-o, --out <dir>", "Directory to write results.json into")
  .option("-v, --verbose", "Print one line per result as it completes")
  .action(async (opts: { config: string; out?: string; verbose?: boolean }) => {
    const cmdOpts: Parameters<typeof runCommand>[0] = {
      configPath: opts.config,
    };
    if (opts.out) cmdOpts.outDir = opts.out;
    if (opts.verbose) cmdOpts.verbose = opts.verbose;
    const code = await runCommand(cmdOpts);
    process.exit(code);
  });

program
  .command("list-models")
  .description("List models available at the configured LLM endpoint.")
  .action(async () => {
    process.exit(await listModelsCommand());
  });

program
  .command("list-agents")
  .description("List built-in agents and their tool counts.")
  .action(() => {
    process.exit(listAgentsCommand());
  });

program
  .command("list-attacks")
  .description("List injection methods and variants.")
  .action(() => {
    process.exit(listAttacksCommand());
  });

program
  .command("list-defenses")
  .description("List supported defense methods.")
  .action(() => {
    process.exit(listDefensesCommand());
  });

program
  .command("serve")
  .description("Start the HTTP backend with the web UI.")
  .option("-p, --port <n>", "Listen port", "4399")
  .action(async (opts: { port: string }) => {
    // Lazy import to avoid loading server-only deps for unrelated commands.
    const { startServer } = await import("@asp-x/server");
    const port = Number(opts.port);
    await startServer({ port });
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
