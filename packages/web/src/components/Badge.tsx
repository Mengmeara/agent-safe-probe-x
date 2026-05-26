import clsx from "clsx";
import type { ReactNode } from "react";

type Tone =
  | "default"
  | "attack"
  | "safe"
  | "warn"
  | "info"
  | "tool"
  | "user"
  | "system";

const TONES: Record<Tone, string> = {
  default: "bg-bg-600 text-ink-700 border-bg-500",
  attack: "bg-accent-attack/10 text-accent-attack border-accent-attack/30",
  safe: "bg-accent-safe/10 text-accent-safe border-accent-safe/30",
  warn: "bg-accent-warn/10 text-accent-warn border-accent-warn/30",
  info: "bg-accent-info/10 text-accent-info border-accent-info/30",
  tool: "bg-accent-tool/10 text-accent-tool border-accent-tool/30",
  user: "bg-accent-user/10 text-accent-user border-accent-user/30",
  system: "bg-accent-system/10 text-accent-system border-accent-system/30",
};

export function Badge({
  tone = "default",
  children,
  className,
}: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] uppercase tracking-wide rounded border font-medium font-mono",
        TONES[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}
