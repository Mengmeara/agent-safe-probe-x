import { describe, expect, it } from "vitest";
import { AGENT_REGISTRY } from "../registry.js";
import { AGENTS } from "../agents.js";
import { ATTACK_TOOLS } from "../attack_tools.js";
import { NORMAL_TOOLS } from "../normal_tools.js";
import { ToolDefSchema, AgentDefSchema } from "@asp-x/shared";

describe("ASB-ported data fixtures", () => {
  it("contains the 10 expected agents", () => {
    expect(AGENTS).toHaveLength(10);
    const ids = AGENTS.map((a) => a.id);
    for (const expected of [
      "financial_analyst_agent",
      "legal_consultant_agent",
      "medical_advisor_agent",
      "academic_search_agent",
      "system_admin_agent",
      "ecommerce_manager_agent",
      "education_consultant_agent",
      "autonomous_driving_agent",
      "aerospace_engineer_agent",
      "psychological_counselor_agent",
    ]) {
      expect(ids).toContain(expected);
    }
  });

  it("each agent has at least 5 tasks and a non-empty role", () => {
    for (const a of AGENTS) {
      expect(a.tasks.length).toBeGreaterThanOrEqual(5);
      expect(a.role.length).toBeGreaterThan(20);
    }
  });

  it("loaded 20 normal tools and 400 attack tools", () => {
    expect(NORMAL_TOOLS).toHaveLength(20);
    expect(ATTACK_TOOLS).toHaveLength(400);
  });

  it("attack tool aggressiveness splits 200/200", () => {
    const agg = ATTACK_TOOLS.filter((t) => t.aggressive).length;
    const nonAgg = ATTACK_TOOLS.filter((t) => !t.aggressive).length;
    expect(agg).toBe(200);
    expect(nonAgg).toBe(200);
  });

  it("every agent has at least 2 normal tools and 20+20 attack candidates", () => {
    for (const a of AGENTS) {
      const normals = AGENT_REGISTRY.getNormalToolsFor(a.id);
      expect(normals.length).toBeGreaterThanOrEqual(2);
      expect(AGENT_REGISTRY.getAttackToolCandidates(a.id, "agg").length).toBe(20);
      expect(AGENT_REGISTRY.getAttackToolCandidates(a.id, "non-agg").length).toBe(20);
      expect(AGENT_REGISTRY.getAttackToolCandidates(a.id, "all").length).toBe(40);
    }
  });

  it("registry yields zod-valid ToolDef and AgentDef instances", () => {
    const agent = AGENT_REGISTRY.getAgent("financial_analyst_agent")!;
    expect(() => AgentDefSchema.parse(agent)).not.toThrow();
    for (const t of AGENT_REGISTRY.getNormalToolsFor("financial_analyst_agent")) {
      expect(() => ToolDefSchema.parse(t)).not.toThrow();
    }
    for (const t of AGENT_REGISTRY.getAttackToolCandidates("system_admin_agent", "all")) {
      expect(() => ToolDefSchema.parse(t)).not.toThrow();
    }
  });

  it("buildToolset combines normal + chosen attack lure", () => {
    const agentId = "financial_analyst_agent";
    const attacks = AGENT_REGISTRY.getAttackToolCandidates(agentId, "agg");
    const targetId = attacks[0]?.id;
    expect(targetId).toBeDefined();
    const tools = AGENT_REGISTRY.buildToolset(agentId, targetId!);
    const normals = AGENT_REGISTRY.getNormalToolsFor(agentId);
    expect(tools.length).toBe(normals.length + 1);
    expect(tools.some((t) => t.kind === "attack" && t.name === targetId)).toBe(true);
  });

  it("test mode returns a small smoke set", () => {
    const tools = AGENT_REGISTRY.getAttackToolCandidates(
      "financial_analyst_agent",
      "test",
    );
    expect(tools.length).toBeGreaterThan(0);
    expect(tools.length).toBeLessThanOrEqual(2);
  });

  it("returns undefined for unknown agent id", () => {
    expect(AGENT_REGISTRY.getAgent("nonexistent")).toBeUndefined();
  });
});
