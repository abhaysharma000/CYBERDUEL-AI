import React from "react";
import clsx from "clsx";

export type BadgeVariant =
  | "success"
  | "danger"
  | "warning"
  | "info"
  | "neutral"
  | "purple"
  | "cyan";

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  size?: "sm" | "md";
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = "neutral",
  size = "md",
  className,
}) => {
  const variantStyles: Record<BadgeVariant, string> = {
    success: "bg-emerald-950/70 text-emerald-400 border-emerald-800/60",
    danger: "bg-rose-950/70 text-rose-400 border-rose-800/60",
    warning: "bg-amber-950/70 text-amber-400 border-amber-800/60",
    info: "bg-red-950/70 text-red-400 border-red-800/60",
    neutral: "bg-slate-800/70 text-slate-300 border-slate-700/60",
    purple: "bg-purple-950/70 text-purple-400 border-purple-800/60",
    cyan: "bg-cyan-950/70 text-red-400 border-cyan-800/60",
  };

  const sizeStyles = {
    sm: "px-2 py-0.5 text-xs",
    md: "px-2.5 py-1 text-xs font-medium",
  };

  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full border font-mono tracking-wide",
        variantStyles[variant],
        sizeStyles[size],
        className
      )}
    >
      {children}
    </span>
  );
};

