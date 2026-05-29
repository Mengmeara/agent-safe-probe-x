import { NavLink, Outlet } from "react-router-dom";
import clsx from "clsx";

const NAV = [
  { to: "/", label: "Runs", icon: "▢" },
  { to: "/runs/new", label: "New Run", icon: "+" },
];

export function Layout() {
  return (
    <div className="min-h-screen flex flex-col text-ink-900">
      <header className="glass sticky top-0 z-30 border-b px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Logo />
          <div>
            <div className="font-semibold tracking-tight leading-none">ASP-X</div>
            <div className="text-xs text-ink-500 mt-1">
              Agent Safe Probe — benchmark dashboard
            </div>
          </div>
        </div>
        <nav className="flex gap-1 p-1 rounded-xl bg-white/[0.03] border border-white/[0.05]">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === "/"}
              className={({ isActive }) =>
                clsx(
                  "px-3 py-1.5 rounded-lg text-sm font-medium transition-all duration-200",
                  isActive
                    ? "bg-white/[0.08] text-ink-900 shadow-[0_1px_0_0_rgba(255,255,255,0.06)_inset]"
                    : "text-ink-500 hover:text-ink-900 hover:bg-white/[0.04]",
                )
              }
            >
              <span className="mr-1.5 opacity-70">{n.icon}</span>
              {n.label}
            </NavLink>
          ))}
        </nav>
      </header>
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}

function Logo() {
  return (
    <div className="relative w-9 h-9 rounded-xl bg-gradient-to-br from-accent-attack via-accent-tool to-accent-info grid place-items-center shadow-[0_6px_20px_-6px_rgba(167,139,250,0.6)]">
      <div className="absolute inset-0 rounded-xl ring-1 ring-inset ring-white/20" />
      <span className="text-white font-mono text-base font-bold drop-shadow">X</span>
    </div>
  );
}
