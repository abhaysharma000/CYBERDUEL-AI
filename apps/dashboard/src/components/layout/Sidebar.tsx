import React from "react";
import { NavLink } from "react-router-dom";
import {
  Activity,
  ShieldAlert,
  Flame,
  Shield,
  CheckCircle2,
  Package,
  Smartphone,
  Eye,
  FileText,
  Server,
  Zap,
  X,
} from "lucide-react";
import clsx from "clsx";

interface NavItem {
  name: string;
  path: string;
  icon: React.ElementType;
  badge?: string;
}

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen = false, onClose }) => {
  const navigation: NavItem[] = [
    { name: "Command Overview", path: "/", icon: Activity },
    { name: "Guardian Control", path: "/guardian", icon: ShieldAlert, badge: "AI" },
    { name: "Red AI Lab", path: "/lab", icon: Flame },
    { name: "Blue AI Defense", path: "/blue", icon: Shield },
    { name: "Evaluations & Benchmarks", path: "/evaluations", icon: CheckCircle2 },
    { name: "Security Releases", path: "/releases", icon: Package },
    { name: "Client Fleet", path: "/clients", icon: Smartphone },
    { name: "Threat Intelligence", path: "/intelligence", icon: Eye },
    { name: "Audit Trail", path: "/audit", icon: FileText },
    { name: "System Health", path: "/system", icon: Server },
  ];

  return (
    <aside
      className={clsx(
        "bg-[#0c0c0f] border-r border-[#27181c] flex flex-col shrink-0 min-h-screen z-50",
        // Desktop styles: static, fixed width 64
        "md:static md:translate-x-0 md:w-64",
        // Mobile styles: fixed drawer, width 72, transition
        "fixed inset-y-0 left-0 w-72 transition-transform duration-300 ease-in-out",
        isOpen ? "translate-x-0 shadow-2xl shadow-black/80" : "-translate-x-full"
      )}
    >
      {/* Brand Header */}
      <div className="h-16 flex items-center justify-between px-6 border-b border-[#27181c]">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-red-600 via-rose-600 to-amber-500 flex items-center justify-center shadow-lg shadow-red-500/30 text-white font-bold">
            <Zap className="w-5 h-5 fill-current" />
          </div>
          <div>
            <h1 className="font-bold text-sm tracking-wide text-white flex items-center gap-1.5 font-mono">
              CYBERDUEL <span className="text-red-400">AI</span>
            </h1>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest font-mono">
              COMMAND CENTER
            </p>
          </div>
        </div>

        {onClose && (
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-[#1c1215] md:hidden transition-colors"
            aria-label="Close navigation menu"
          >
            <X className="w-5 h-5" />
          </button>
        )}
      </div>

      {/* Navigation Links */}
      <div className="flex-1 py-6 px-3 space-y-1 overflow-y-auto">
        <div className="px-3 mb-2 text-[10px] font-semibold text-slate-500 uppercase tracking-wider font-mono">
          Security Operations
        </div>
        {navigation.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === "/"}
            onClick={() => {
              if (onClose) onClose();
            }}
            className={({ isActive }) =>
              clsx(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all group",
                isActive
                  ? "bg-red-600/15 text-red-400 border border-red-500/30 font-semibold"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              )
            }
          >
            <item.icon className="w-4 h-4 shrink-0 transition-transform group-hover:scale-110" />
            <span className="truncate">{item.name}</span>
            {item.badge && (
              <span className="ml-auto text-[10px] bg-red-500/20 text-red-300 px-1.5 py-0.5 rounded font-mono">
                {item.badge}
              </span>
            )}
          </NavLink>
        ))}
      </div>

      {/* Pipeline Status Indicator */}
      <div className="p-4 border-t border-[#27181c]">
        <div className="bg-[#131316] border border-[#27181c] rounded-xl p-3 text-xs">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="font-mono text-[11px]">DEFENSIVE CYCLE</span>
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
          </div>
          <div className="text-[11px] text-slate-300 font-mono flex items-center justify-between">
            <span>Red → Blue → Eval</span>
            <span className="text-red-400 font-semibold">ACTIVE</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
