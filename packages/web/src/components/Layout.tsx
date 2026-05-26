import { NavLink, Outlet } from "react-router-dom";
import clsx from "clsx";

const NAV = [
  { to: "/", label: "Runs", icon: "▢" },
  { to: "/runs/new", label: "New Run", icon: "+" },
];

export function Layout() {
  return (
    <div className="min-h-screen flex flex-col bg-bg-900 text-ink-900">
      <header className="border-b border-bg-600/60 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Logo />
          <div>
            <div className="font-semibold tracking-tight">ASP-X</div>
            <div className="text-xs text-ink-500 -mt-0.5">
              Agent Safe Probe — benchmark dashboard
            </div>
          </div>
        </div>
        <nav className="flex gap-1">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === "/"}
              className={({ isActive }) =>
                clsx(
                  "px-3 py-1.5 rounded-md text-sm transition-colors",
                  isActive
                    ? "bg-bg-600 text-ink-900"
                    : "text-ink-500 hover:text-ink-700 hover:bg-bg-700",
                )
              }
            >
              <span className="mr-1.5 text-ink-500">{n.icon}</span>
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
    <div className="w-8 h-8 rounded-md bg-gradient-to-br from-accent-attack to-accent-tool grid place-items-center shadow-glow">
      <span className="text-white font-mono text-sm font-bold">X</span>
    </div>
  );
}
