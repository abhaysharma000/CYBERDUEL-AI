import React, { useEffect, useState } from "react";
import {
  Eye,
  ShieldAlert,
  RefreshCw,
  Database,
} from "lucide-react";
import { intelligenceApi } from "../api/client";
import { ThreatObservationItem } from "../types";
import { Badge } from "../components/common/Badge";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { ErrorBanner } from "../components/common/ErrorBanner";
import { EmptyState } from "../components/common/EmptyState";
import { PrivacyUrl } from "../components/common/PrivacyUrl";

export const IntelligencePage: React.FC = () => {
  const [indicators, setIndicators] = useState<any[]>([]);
  const [observations, setObservations] = useState<ThreatObservationItem[]>([]);
  const [activeTab, setActiveTab] = useState<"indicators" | "observations">("indicators");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [indList, obsList] = await Promise.all([
        intelligenceApi.getThreatIndicators(50).catch(() => []),
        intelligenceApi.getObservations(50).catch(() => []),
      ]);
      setIndicators(indList);
      setObservations(obsList);
    } catch (err: any) {
      setError(err.message || "Failed to load threat intelligence");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#27181c]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h2 className="text-2xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Eye className="w-6 h-6 text-red-400" />
              THREAT INTELLIGENCE & TELEMETRY
            </h2>
            <Badge variant="cyan" size="sm">PRIVACY PRESERVED</Badge>
          </div>
          <p className="text-sm text-slate-400">
            Indicators of Compromise (IOCs), live threat feed, and client observation pipeline with client credentials redacted.
          </p>
        </div>

        <button
          onClick={fetchData}
          className="flex items-center gap-2 px-3.5 py-2 bg-[#131316] hover:bg-slate-800 text-slate-200 border border-[#27181c] rounded-lg text-xs font-mono font-medium transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5 text-red-400" />
          Refresh Intelligence
        </button>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-6">
        <button
          onClick={() => setActiveTab("indicators")}
          className={`pb-3 text-sm font-mono font-semibold transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "indicators"
              ? "border-cyan-500 text-red-400"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Database className="w-4 h-4" />
          Threat Indicators ({indicators.length})
        </button>
        <button
          onClick={() => setActiveTab("observations")}
          className={`pb-3 text-sm font-mono font-semibold transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "observations"
              ? "border-cyan-500 text-red-400"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          Live Observations ({observations.length})
        </button>
      </div>

      {isLoading ? (
        <LoadingSpinner label="Ingesting threat intelligence and observations..." />
      ) : error ? (
        <ErrorBanner message={error} onRetry={fetchData} />
      ) : activeTab === "indicators" ? (
        indicators.length === 0 ? (
          <EmptyState
            icon={Eye}
            title="No Threat Indicators Cataloged"
            description="The intelligence repository has not cataloged any threat indicators yet."
          />
        ) : (
          <div className="overflow-x-auto bg-[#131316] border border-[#27181c] rounded-2xl shadow-xl">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">TYPE</th>
                  <th className="py-3 px-4">INDICATOR / PATTERN</th>
                  <th className="py-3 px-4">SEVERITY</th>
                  <th className="py-3 px-4">CONFIDENCE</th>
                  <th className="py-3 px-4">SOURCE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {indicators.map((ind, idx) => (
                  <tr key={ind.id || idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 text-red-400 font-bold uppercase">
                      {ind.indicator_type || "URL_PATTERN"}
                    </td>
                    <td className="py-3 px-4 text-slate-200 max-w-md">
                      <PrivacyUrl url={ind.value || ind.pattern || ""} />
                    </td>
                    <td className="py-3 px-4">
                      <Badge
                        variant={
                          ind.severity === "high" || ind.severity === "critical"
                            ? "danger"
                            : "warning"
                        }
                        size="sm"
                      >
                        {(ind.severity || "HIGH").toUpperCase()}
                      </Badge>
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      {ind.confidence ? `${(ind.confidence * 100).toFixed(0)}%` : "95%"}
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {ind.source || "ThreatEngine Pipeline"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      ) : observations.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="No Threat Observations Logged"
          description="Edge telemetry observations pipeline has not recorded any threat events yet."
        />
      ) : (
        <div className="overflow-x-auto bg-[#131316] border border-[#27181c] rounded-2xl shadow-xl">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">TARGET URL (REDACTED)</th>
                <th className="py-3 px-4">DECISION</th>
                <th className="py-3 px-4">CONFIDENCE</th>
                <th className="py-3 px-4">SOURCE</th>
                <th className="py-3 px-4">DETECTED AT</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {observations.map((obs) => (
                <tr key={obs.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4 max-w-sm">
                    <PrivacyUrl url={obs.raw_url || obs.redacted_url} />
                  </td>
                  <td className="py-3 px-4">
                    <Badge variant={obs.decision === "block" ? "danger" : "warning"} size="sm">
                      {obs.decision.toUpperCase()}
                    </Badge>
                  </td>
                  <td className="py-3 px-4 text-slate-300">
                    {(obs.confidence_score * 100).toFixed(1)}%
                  </td>
                  <td className="py-3 px-4 text-slate-400">{obs.source}</td>
                  <td className="py-3 px-4 text-slate-400">
                    {new Date(obs.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
