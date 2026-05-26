import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api.js";
import type { RunConfig } from "@asp-x/shared";
import clsx from "clsx";

const INJECTION_METHODS = [
  "direct_prompt_injection",
  "observation_prompt_injection",
  "memory_attack",
  "pot_backdoor",
  "clean",
  "mixed",
] as const;

const VARIANTS = [
  "naive",
  "fake_completion",
  "escape_characters",
  "context_ignoring",
  "combined_attack",
] as const;

const TOOL_SETS = ["all", "agg", "non-agg", "test"] as const;

export function NewRunPage() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const agentsQ = useQuery({ queryKey: ["agents"], queryFn: api.listAgents });
  const modelsQ = useQuery({ queryKey: ["models"], queryFn: api.listModels });
  const defensesQ = useQuery({ queryKey: ["defenses"], queryFn: api.listDefenses });

  const [label, setLabel] = useState("");
  const [injectionMethod, setInjectionMethod] = useState<typeof INJECTION_METHODS[number]>(
    "direct_prompt_injection",
  );
  const [attackTool, setAttackTool] = useState<typeof TOOL_SETS[number]>("test");
  const [variants, setVariants] = useState<string[]>(["naive"]);
  const [selectedAgents, setSelectedAgents] = useState<string[]>([]);
  const [selectedModel, setSelectedModel] = useState<string>("");
  const [taskNum, setTaskNum] = useState<number>(1);
  const [defense, setDefense] = useState<string>("none");
  const [maxSteps, setMaxSteps] = useState<number>(8);
  const [triggers, setTriggers] = useState<string>("strawberry");

  // Initialize model default once it loads.
  if (modelsQ.data && !selectedModel) setSelectedModel(modelsQ.data.default);

  const create = useMutation({
    mutationFn: (cfg: RunConfig) => api.createRun(cfg, label.trim() || undefined),
    onSuccess: (run) => {
      void qc.invalidateQueries({ queryKey: ["runs"] });
      nav(`/runs/${run.id}`);
    },
  });

  function submit() {
    const cfg: RunConfig = {
      injection_method: injectionMethod,
      attack_types: injectionMethod === "clean" ? ["naive"] : (variants as RunConfig["attack_types"]),
      attack_tool: attackTool,
      llms: selectedModel ? [selectedModel] : [],
      task_num: taskNum,
      read_db: false,
      write_db: false,
      max_steps: maxSteps,
      agents: selectedAgents.length > 0 ? selectedAgents : undefined,
      defense_type: defense !== "none" ? (defense as RunConfig["defense_type"]) : undefined,
      triggers: injectionMethod === "pot_backdoor"
        ? triggers.split(",").map((s) => s.trim()).filter(Boolean)
        : undefined,
    } as RunConfig;
    // Drop undefined to keep the JSON tidy.
    create.mutate(JSON.parse(JSON.stringify(cfg)) as RunConfig);
  }

  return (
    <div className="max-w-3xl mx-auto px-6 py-8 space-y-6">
      <header>
        <h1 className="text-xl font-semibold">New Run</h1>
        <p className="text-sm text-ink-500">
          Configure one benchmark run. The matrix size is shown below the form.
        </p>
      </header>

      <Section title="Identification">
        <Field label="Label (optional)">
          <Input
            value={label}
            onChange={(v) => setLabel(v)}
            placeholder="e.g. baseline DPI on qwen-flash"
          />
        </Field>
      </Section>

      <Section title="Attack">
        <Field label="Injection method">
          <Select
            value={injectionMethod}
            options={INJECTION_METHODS.map((m) => ({ value: m, label: m }))}
            onChange={(v) => setInjectionMethod(v as typeof injectionMethod)}
          />
        </Field>

        {injectionMethod !== "clean" && (
          <Field label="Attack tool set">
            <Select
              value={attackTool}
              options={TOOL_SETS.map((t) => ({ value: t, label: t }))}
              onChange={(v) => setAttackTool(v as typeof attackTool)}
            />
          </Field>
        )}

        {injectionMethod !== "clean" && (
          <Field label="Variants">
            <div className="flex flex-wrap gap-1.5">
              {VARIANTS.map((v) => (
                <Chip
                  key={v}
                  active={variants.includes(v)}
                  onClick={() =>
                    setVariants((cur) =>
                      cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v],
                    )
                  }
                >
                  {v}
                </Chip>
              ))}
            </div>
          </Field>
        )}

        {injectionMethod === "pot_backdoor" && (
          <Field label="Triggers (comma-separated)">
            <Input value={triggers} onChange={setTriggers} placeholder="strawberry, magenta" />
          </Field>
        )}
      </Section>

      <Section title="Defense">
        <Field label="Defense method">
          <Select
            value={defense}
            options={(defensesQ.data?.defenses ?? ["none"]).map((d) => ({
              value: d,
              label: d,
            }))}
            onChange={setDefense}
          />
        </Field>
      </Section>

      <Section title="Target">
        <Field label="LLM model">
          <Select
            value={selectedModel}
            options={(modelsQ.data?.models ?? []).map((m) => ({
              value: m.id,
              label: m.id,
            }))}
            onChange={setSelectedModel}
          />
        </Field>

        <Field label="Agents (none = all)">
          <div className="flex flex-wrap gap-1.5">
            {(agentsQ.data ?? []).map((a) => (
              <Chip
                key={a.id}
                active={selectedAgents.includes(a.id)}
                onClick={() =>
                  setSelectedAgents((cur) =>
                    cur.includes(a.id) ? cur.filter((x) => x !== a.id) : [...cur, a.id],
                  )
                }
              >
                {a.id}
              </Chip>
            ))}
          </div>
        </Field>

        <Field label="Tasks per agent">
          <Input
            type="number"
            value={String(taskNum)}
            onChange={(v) => setTaskNum(Math.max(1, Number(v) || 1))}
          />
        </Field>

        <Field label="Max ReAct steps">
          <Input
            type="number"
            value={String(maxSteps)}
            onChange={(v) => setMaxSteps(Math.max(1, Number(v) || 1))}
          />
        </Field>
      </Section>

      {create.error && (
        <div className="text-accent-attack text-sm">
          Failed to create run: {(create.error as Error).message}
        </div>
      )}

      <div className="flex items-center gap-3 pt-2">
        <button
          onClick={submit}
          disabled={!selectedModel || create.isPending}
          className={clsx(
            "px-4 py-2 rounded-md text-sm font-medium",
            !selectedModel || create.isPending
              ? "bg-bg-600 text-ink-500 cursor-not-allowed"
              : "bg-accent-info text-bg-900 hover:bg-accent-info/90",
          )}
        >
          {create.isPending ? "Starting…" : "Start Run"}
        </button>
        <button
          onClick={() => nav("/")}
          className="px-4 py-2 rounded-md text-sm text-ink-700 hover:bg-bg-700"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border border-bg-600 rounded-lg p-5 space-y-4 bg-bg-800/60">
      <h2 className="text-sm uppercase tracking-wide text-ink-500 font-semibold">{title}</h2>
      <div className="space-y-3">{children}</div>
    </section>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs text-ink-500 block mb-1">{label}</span>
      {children}
    </label>
  );
}

function Input({
  value,
  onChange,
  placeholder,
  type = "text",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
}) {
  return (
    <input
      type={type}
      value={value}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      className="w-full bg-bg-700 border border-bg-500 rounded-md px-3 py-1.5 text-sm text-ink-900 placeholder-ink-500 focus:outline-none focus:border-accent-info"
    />
  );
}

function Select({
  value,
  options,
  onChange,
}: {
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full bg-bg-700 border border-bg-500 rounded-md px-3 py-1.5 text-sm text-ink-900 focus:outline-none focus:border-accent-info"
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

function Chip({
  active,
  children,
  onClick,
}: {
  active?: boolean;
  children: React.ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={clsx(
        "px-2.5 py-1 rounded text-xs font-mono border transition-colors",
        active
          ? "bg-accent-info/15 border-accent-info text-accent-info"
          : "bg-bg-700 border-bg-500 text-ink-500 hover:text-ink-700",
      )}
    >
      {children}
    </button>
  );
}
