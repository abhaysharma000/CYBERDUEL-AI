import React from "react";
import { AlertCircle, RefreshCw } from "lucide-react";

interface ErrorBannerProps {
  message: string;
  onRetry?: () => void;
  className?: string;
}

export const ErrorBanner: React.FC<ErrorBannerProps> = ({
  message,
  onRetry,
  className = "",
}) => {
  return (
    <div
      className={`flex items-center justify-between p-4 bg-rose-950/60 border border-rose-900/60 rounded-xl text-rose-300 text-sm ${className}`}
    >
      <div className="flex items-center gap-3">
        <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
        <span>{message}</span>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-900/60 hover:bg-rose-850 text-rose-200 rounded-lg text-xs font-medium transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Retry
        </button>
      )}
    </div>
  );
};

