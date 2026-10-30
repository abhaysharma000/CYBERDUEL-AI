import React from "react";
import { Loader2 } from "lucide-react";

interface LoadingSpinnerProps {
  label?: string;
  size?: "sm" | "md" | "lg";
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  label = "Loading operational telemetry...",
  size = "md",
}) => {
  const sizeClasses = {
    sm: "w-4 h-4",
    md: "w-6 h-6",
    lg: "w-10 h-10",
  };

  return (
    <div className="flex flex-col items-center justify-center p-12 text-center text-slate-400">
      <Loader2 className={`${sizeClasses[size]} animate-spin text-blue-500 mb-3`} />
      <span className="text-sm font-medium">{label}</span>
    </div>
  );
};

