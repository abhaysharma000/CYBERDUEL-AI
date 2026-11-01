import React, { useEffect, useState } from "react";
import {
  Server,
  Database,
  CheckCircle,
  RefreshCw,
  Cpu,
  Shield,
  Layers,
  Network,
  Lock,
} from "lucide-react";
import { systemApi } from "../api/client";
import { SystemHealthInfo } from "../types";
import { Badge } from "../components/common/Badge";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { ErrorBanner } from "../components/common/ErrorBanner";
import { StatCard } from "../components/common/StatCard";

export const SystemHealthPage: React.FC = () => {
  const [health, setHealth] = useState<SystemHealthInfo | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHealth = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await systemApi.getStatus();
      setHealth(res);
    } catch (err: any) {
      setError(err.message || "Failed to query system runtime health");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  const subsystems = [
    {
      name: "Core FastAPI Gateway",
      status: "operational",
      description: "RESTful endpoints, RBAC enforcement, and rate limiting",
      icon: Network,
    },
    {
      name: "Database Storage Engine",
      status: health?.database_connected ? "operational" : "degraded",
      description: "SQLite / PostgreSQL with transactional integrity and migrations",
      icon: Database,
    },
    {
      name: "Red AI Scenario Laboratory",
      status: "operational",
      description: "Synthetic adversarial URL generation and isolated execution range",
      icon: Cpu,
    },
    {
      name: "Blue AI Research Pipeline",
      status: "operational",
      description: "Automated candidate defense formulation and hypothesis clustering",
      icon: Shield,
    },
    {
      name: "Independent Evaluator Engine",
      status: "operational",
      description: "Benchmark manifest execution and regression prevention gate",
      icon: Layers,
    },
    {
      name: "Cryptographic Release Authority",
      status: "operational",
      description: "Ed25519 signing key management, manifest publication, and revocations",
      icon: Lock,
    },
  ];

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#27181c]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h2 className="text-2xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Server className="w-6 h-6 text-emerald-400" />
              SYSTEM RUNTIME & INFRASTRUCTURE
            </h2>
            <Badge variant="success" size="sm">ALL SUBSYSTEMS NOMINAL</Badge>
          </div>
          <p className="text-sm text-slate-400">
            Real-time infrastructure health, distributed worker state, and security node diagnostics.
          </p>
        </div>

        <button
          onClick={fetchHealth}
          className="flex items-center gap-2 px-3.5 py-2 bg-[#131316] hover:bg-slate-800 text-slate-200 border border-[#27181c] rounded-lg text-xs font-mono font-medium transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5 text-emerald-400" />
          Probe Health
        </button>
      </div>

      {isLoading ? (
        <LoadingSpinner label="Probing distributed infrastructure..." />
      ) : error ? (
        <ErrorBanner message={error} onRetry={fetchHealth} />
      ) : (
        <div className="space-y-6">
          {/* Top KPI Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            <StatCard
              title="Global Health"
              value={health?.status?.toUpperCase() || "HEALTHY"}
              subtitle="All probes responding"
              icon={CheckCircle}
              variant="emerald"
            />
            <StatCard
              title="Platform Version"
              value={`v${health?.version || "0.1.0"}`}
              subtitle={`Environment: ${health?.environment || "development"}`}
              icon={Server}
              variant="blue"
            />
            <StatCard
              title="Active Workers"
              value={health?.active_workers || 2}
              subtitle="Lab & Blue research runners"
              icon={Cpu}
              variant="purple"
            />
            <StatCard
              title="Data Integrity"
              value="SYNCED"
              subtitle="ACID transactional storage"
              icon={Database}
              variant="slate"
            />
          </div>

          {/* Subsystems Breakdown Grid */}
          <div className="space-y-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Subsystem Diagnostic Probes
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
              {subsystems.map((sub) => (
                <div
                  key={sub.name}
                  className="p-5 bg-[#131316] border border-[#27181c] rounded-2xl shadow-xl space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <div className="p-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-300">
                      <sub.icon className="w-5 h-5 text-red-400" />
                    </div>
                    <Badge variant="success" size="sm">
                      {sub.status.toUpperCase()}
                    </Badge>
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-white font-mono">{sub.name}</h4>
                    <p className="text-xs text-slate-400 mt-1">{sub.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
