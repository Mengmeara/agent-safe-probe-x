import type { AgentDef, AttackToolSet, ToolDef } from "@asp-x/shared";
import { AGENTS } from "./agents.js";
import { NORMAL_TOOLS, type NormalToolEntry } from "./normal_tools.js";
import { ATTACK_TOOLS, type AttackToolEntry } from "./attack_tools.js";

/**
 * In-memory registry over the bundled ASB fixture data. All lookups are O(n)
 * over small lists (10 agents, ~400 tools) so a Map index is overkill.
 */
class AgentRegistry {
  listAgents(): AgentDef[] {
    return AGENTS.map((a) => ({ ...a, tool_ids: [...a.tool_ids], tasks: [...a.tasks] }));
  }

  getAgent(id: string): AgentDef | undefined {
    const a = AGENTS.find((x) => x.id === id);
    return a ? { ...a, tool_ids: [...a.tool_ids], tasks: [...a.tasks] } : undefined;
  }

  /** Normal tool definitions for one agent. Strips ASB metadata. */
  getNormalToolsFor(agentId: string): ToolDef[] {
    const agent = AGENTS.find((a) => a.id === agentId);
    if (!agent) return [];
    return NORMAL_TOOLS.filter(
      (t) =>
        agent.tool_ids.includes(t.name) || t.corresponding_agent === agentId,
    ).map(stripNormal);
  }

  /**
   * Candidate attack tools for one agent under the chosen aggressiveness mode.
   * In ASB each "test" runs the agent with its normal tools + exactly ONE of
   * these candidates as the attack target.
   */
  getAttackToolCandidates(agentId: string, mode: AttackToolSet): ToolDef[] {
    const filtered = ATTACK_TOOLS.filter(
      (t) => t.corresponding_agent === agentId,
    );
    const byMode = filtered.filter((t) => {
      if (mode === "all") return true;
      if (mode === "agg") return t.aggressive === true;
      if (mode === "non-agg") return t.aggressive !== true;
      if (mode === "test") return false; // handled below
      return true;
    });
    if (mode === "test") {
      // smoke test: one aggressive + one non-aggressive
      const agg = filtered.find((t) => t.aggressive);
      const nonAgg = filtered.find((t) => !t.aggressive);
      return [agg, nonAgg].filter((t): t is AttackToolEntry => !!t).map(stripAttack);
    }
    return byMode.map(stripAttack);
  }

  /**
   * Compose the runtime tool list for one (agent, attack_target) pair:
   * the agent's normal tools plus the single target attack lure.
   */
  buildToolset(agentId: string, attackToolId: string | null): ToolDef[] {
    const normals = this.getNormalToolsFor(agentId);
    if (!attackToolId) return normals;
    const attack = ATTACK_TOOLS.find((t) => t.name === attackToolId);
    return attack ? [...normals, stripAttack(attack)] : normals;
  }
}

function stripNormal(t: NormalToolEntry): ToolDef {
  const out: ToolDef = {
    id: t.id,
    name: t.name,
    description: t.description,
    kind: "normal",
  };
  if (t.expected_achievement) out.expected_achievement = t.expected_achievement;
  return out;
}

function stripAttack(t: AttackToolEntry): ToolDef {
  const out: ToolDef = {
    id: t.id,
    name: t.name,
    description: t.description,
    kind: "attack",
  };
  if (t.aggressive !== undefined) out.aggressive = t.aggressive;
  if (t.attack_instruction) out.attack_instruction = t.attack_instruction;
  if (t.expected_achievement) out.expected_achievement = t.expected_achievement;
  return out;
}

export const AGENT_REGISTRY = new AgentRegistry();
export type { AgentRegistry };
