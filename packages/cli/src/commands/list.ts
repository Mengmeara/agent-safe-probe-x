import kleur from "kleur";
import {
  AGENT_REGISTRY,
  buildDefaultRegistry,
  readLLMEnv,
} from "@asp-x/core";
import {
  AttackVariantSchema,
  DefenseKindSchema,
  InjectionMethodSchema,
} from "@asp-x/shared";

export async function listModelsCommand(): Promise<number> {
  try {
    const env = readLLMEnv();
    const registry = buildDefaultRegistry(env);
    const provider = registry.resolve("*");
    const models = await provider.listModels();
    console.log(kleur.bold(`${models.length} model(s) available at ${env.baseUrl}`));
    for (const m of models) {
      const prov = m.provider ? kleur.dim(` (${m.provider})`) : "";
      console.log(`  ${m.id}${prov}`);
    }
    return 0;
  } catch (e) {
    console.error(
      kleur.red(
        `Failed to list models: ${e instanceof Error ? e.message : String(e)}`,
      ),
    );
    return 1;
  }
}

export function listAgentsCommand(): number {
  const agents = AGENT_REGISTRY.listAgents();
  console.log(kleur.bold(`${agents.length} built-in agents`));
  for (const a of agents) {
    const normal = AGENT_REGISTRY.getNormalToolsFor(a.id).length;
    const attack = AGENT_REGISTRY.getAttackToolCandidates(a.id, "all").length;
    console.log(
      `  ${kleur.cyan(a.id.padEnd(32))} ${kleur.dim(`tasks=${a.tasks.length}  normal_tools=${normal}  attack_lures=${attack}`)}`,
    );
  }
  return 0;
}

export function listAttacksCommand(): number {
  console.log(kleur.bold("Injection methods"));
  for (const m of InjectionMethodSchema.options) console.log(`  ${m}`);
  console.log("");
  console.log(kleur.bold("Variants (apply to DPI/OPI/memory/PoT)"));
  for (const v of AttackVariantSchema.options) console.log(`  ${v}`);
  return 0;
}

export function listDefensesCommand(): number {
  console.log(kleur.bold("Defenses"));
  for (const d of DefenseKindSchema.options) console.log(`  ${d}`);
  return 0;
}
