import React, { useState } from "react";
import { useAuth } from "../../auth/AuthContext";
import { Badge } from "../common/Badge";
import { User, LogOut, ChevronDown, Check, ShieldCheck } from "lucide-react";
import { Role } from "../../types";

export const Header: React.FC = () => {
  const { user, availableOperators, switchOperator, logout } = useAuth();
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const getRoleBadgeVariant = (role?: Role) => {
    switch (role) {
      case "admin":
        return "purple";
      case "research_operator":
        return "danger";
      case "defense_reviewer":
        return "info";
      case "release_operator":
        return "warning";
      default:
        return "neutral";
    }
  };

  return (
    <header className="h-16 bg-[#0c0c0f]/80 backdrop-blur-md border-b border-[#27181c] px-8 flex items-center justify-between z-20 sticky top-0">
      {/* Left Status Bar */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-sm shadow-emerald-500/50"></span>
          <span className="text-xs font-mono font-medium text-slate-300">
            SEC-NODE: <span className="text-emerald-400 font-semibold">ONLINE</span>
          </span>
        </div>
        <span className="text-slate-700">|</span>
        <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
          <ShieldCheck className="w-3.5 h-3.5 text-red-400" />
          <span>AIR-GAPPED EXPERIMENT RANGE</span>
        </div>
      </div>

      {/* Right Controls: Role Switcher & Operator Profile */}
      <div className="flex items-center gap-4">
        {/* Operator Switcher Dropdown */}
        <div className="relative">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center gap-2.5 px-3 py-1.5 bg-[#131316] border border-[#27181c] hover:border-slate-600 rounded-lg text-xs font-medium text-slate-200 transition-colors shadow-sm"
          >
            <User className="w-3.5 h-3.5 text-red-400" />
            <span className="font-mono">{user?.display_name || user?.username || "Operator"}</span>
            <Badge variant={getRoleBadgeVariant(user?.role)} size="sm">
              {user?.role?.toUpperCase()}
            </Badge>
            <ChevronDown className="w-3.5 h-3.5 text-slate-500" />
          </button>

          {dropdownOpen && (
            <div className="absolute right-0 mt-2 w-72 bg-[#131316] border border-[#27181c] rounded-xl shadow-2xl p-2 z-50 animate-in fade-in zoom-in-95 duration-150">
              <div className="px-3 py-2 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                Simulate Operator Persona
              </div>
              <div className="py-1 space-y-1">
                {availableOperators.map((op) => {
                  const isCurrent = user?.username === op.username;
                  return (
                    <button
                      key={op.username}
                      onClick={async () => {
                        await switchOperator(op.username);
                        setDropdownOpen(false);
                      }}
                      className={`w-full text-left px-3 py-2 rounded-lg text-xs transition-colors flex items-start justify-between ${
                        isCurrent
                          ? "bg-red-600/15 border border-red-500/30 text-white"
                          : "hover:bg-slate-800/60 text-slate-300"
                      }`}
                    >
                      <div>
                        <div className="font-semibold flex items-center gap-1.5 font-mono">
                          {op.display_name}
                          {isCurrent && <Check className="w-3.5 h-3.5 text-red-400" />}
                        </div>
                        <div className="text-[10px] text-slate-400 line-clamp-1 mt-0.5">
                          {op.description}
                        </div>
                      </div>
                      <Badge variant={getRoleBadgeVariant(op.role)} size="sm">
                        {op.role}
                      </Badge>
                    </button>
                  );
                })}
              </div>
              <div className="pt-2 border-t border-slate-800 mt-1">
                <button
                  onClick={() => {
                    logout();
                    setDropdownOpen(false);
                  }}
                  className="w-full flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs text-rose-400 hover:bg-rose-950/40 transition-colors"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  Sign Out Session
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};

