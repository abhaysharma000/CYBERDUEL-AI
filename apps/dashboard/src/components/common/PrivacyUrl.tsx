import React, { useState } from "react";
import { ShieldCheck, Copy, Check } from "lucide-react";
import { redactSensitiveUrl } from "../../api/client";

interface PrivacyUrlProps {
  url: string;
  className?: string;
  showIcon?: boolean;
}

export const PrivacyUrl: React.FC<PrivacyUrlProps> = ({
  url,
  className = "",
  showIcon = true,
}) => {
  const [copied, setCopied] = useState(false);
  const redacted = redactSensitiveUrl(url);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(redacted);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`inline-flex items-center gap-1.5 max-w-full font-mono text-xs ${className}`}>
      {showIcon && (
        <span title="Privacy Redacted URL: Sensitive credentials removed">
          <ShieldCheck className="w-3.5 h-3.5 text-red-400 shrink-0" />
        </span>
      )}
      <span
        className="truncate text-slate-300 hover:text-white transition-colors"
        title={redacted}
      >
        {redacted}
      </span>
      <button
        type="button"
        onClick={handleCopy}
        className="text-slate-500 hover:text-slate-300 transition-colors p-1 rounded"
        title="Copy redacted URL"
      >
        {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
      </button>
    </div>
  );
};
