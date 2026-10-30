import React from "react";
import clsx from "clsx";
import { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: "blue" | "red" | "emerald" | "amber" | "purple" | "slate";
  trend?: {
    value: string;
    isPositive?: boolean;
  };
  onClick?: () => void;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = "blue",
  trend,
  onClick,
}) => {
  const borderVariants = {
    blue: "hover:border-blue-500/50 focus:border-blue-500",
    red: "hover:border-rose-500/50 focus:border-rose-500",
    emerald: "hover:border-emerald-500/50 focus:border-emerald-500",
    amber: "hover:border-amber-500/50 focus:border-amber-500",
    purple: "hover:border-purple-500/50 focus:border-purple-500",
    slate: "hover:border-slate-500/50 focus:border-slate-500",
  };

  const iconColors = {
    blue: "text-blue-400 bg-blue-950/60 border-blue-800/40",
    red: "text-rose-400 bg-rose-950/60 border-rose-800/40",
    emerald: "text-emerald-400 bg-emerald-950/60 border-emerald-800/40",
    amber: "text-amber-400 bg-amber-950/60 border-amber-800/40",
    purple: "text-purple-400 bg-purple-950/60 border-purple-800/40",
    slate: "text-slate-400 bg-slate-900 border-slate-700/40",
  };

  return (
    <div
      onClick={onClick}
      className={clsx(
        "bg-[#111827] border border-[#1f293d] rounded-xl p-5 shadow-lg transition-all duration-200",
        onClick && "cursor-pointer",
        borderVariants[variant]
      )}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            {title}
          </p>
          <p className="text-2xl font-bold tracking-tight text-white font-mono">
            {value}
          </p>
        </div>
        <div className={clsx("p-2.5 rounded-lg border", iconColors[variant])}>
          <Icon className="w-5 h-5" />
        </div>
      </div>

      {(subtitle || trend) && (
        <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
          {subtitle && <span className="text-slate-400">{subtitle}</span>}
          {trend && (
            <span
              className={clsx(
                "font-mono font-medium",
                trend.isPositive ? "text-emerald-400" : "text-amber-400"
              )}
            >
              {trend.value}
            </span>
          )}
        </div>
      )}
    </div>
  );
};

