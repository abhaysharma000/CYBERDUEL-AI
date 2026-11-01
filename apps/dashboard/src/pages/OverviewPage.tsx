import React, { useEffect, useState } from "react";
import {
  Flame,
  Shield,
  CheckCircle2,
  Package,
  Smartphone,
  ArrowUpRight,
  RefreshCw,
  Clock,
  Layers,
  ChevronRight,
} from "lucide-react";
import { Link } from "react-router-dom";
import { dashboardApi } from "../api/client";
import { DashboardOverviewResponse } from "../types";
import { StatCard } from "../components/common/StatCard";
import { Badge } from "../components/common/Badge";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { ErrorBanner } from "../components/common/ErrorBanner";

export const OverviewPage: React.FC = () => {
  const [data, setData] = useState<DashboardOverviewResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchOverview = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await dashboardApi.getOverview();
      setData(res);
    } catch (err: any) {
      setError(err.message || "Failed to load dashboard overview telemetry");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchOverview();
  }, []);

  if (isLoading && !data) {
    return <LoadingSpinner label="Loading Command Center telemetry..." size="lg" />;
  }

  if (error && !data) {
    return <ErrorBanner message={error} onRetry={fetchOverview} className="my-8" />;
  }

  const { research, defense, evaluations, releases, clients, recent_events } = data!;

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Banner: Overview & Status */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#27181c]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h2 className="text-2xl font-bold tracking-tight text-white font-mono">
              SECURITY COMMAND CONSOLE
            </h2>
            <Badge variant="cyan" size="sm">LIVE METRICS</Badge>
          </div>
          <p className="text-sm text-slate-400">
            Real-time defensive intelligence, adversarial research pipelines, and release governance.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={fetchOverview}
            className="flex items-center gap-2 px-3.5 py-2 bg-[#131316] hover:bg-slate-800 text-slate-200 border border-[#27181c] rounded-lg text-xs font-mono font-medium transition-colors shadow-sm"
          >
            <RefreshCw className="w-3.5 h-3.5 text-red-400" />
            Refresh Telemetry
          </button>
          <Link
            to="/releases"
            className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-mono font-medium transition-colors shadow-lg shadow-red-900/40"
          >
            <Package className="w-3.5 h-3.5" />
            Active Release: v{releases.active_production_version || "1.0.0"}
          </Link>
        </div>
      </div>

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <StatCard
          title="Red AI Scenarios"
          value={research.total_experiments}
          subtitle={`${research.total_discrepancies} detection discrepancies recorded`}
          icon={Flame}
          variant="red"
        />
        <StatCard
          title="Blue AI Candidates"
          value={defense.total_candidates}
          subtitle={`${defense.approved_candidates} approved / ${defense.pending_review_candidates} pending`}
          icon={Shield}
          variant="blue"
        />
        <StatCard
          title="Evaluations Audited"
          value={evaluations.total_evaluations}
          subtitle={`${evaluations.regressions_prevented} regressions prevented`}
          icon={CheckCircle2}
          variant="emerald"
        />
        <StatCard
          title="Protected Fleet"
          value={clients.total_devices}
          subtitle={`${clients.fleet_adoption_rate}% on latest policy`}
          icon={Smartphone}
          variant="purple"
        />
      </div>

      {/* Staged Rollout Alert & Pipeline Lifecycle */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Release Status Card */}
        <div className="lg:col-span-2 bg-[#131316] border border-[#27181c] rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-5">
            <div className="flex flex-wrap items-center gap-3">
              <div className="p-2.5 rounded-xl bg-red-950/60 border border-red-800/40 text-red-400">
                <Package className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-white font-mono">
                  ACTIVE POLICY DISTRIBUTION
                </h3>
                <p className="text-xs text-slate-400">
                  Cryptographically signed Ed25519 policy deployment across browser & mobile edge
                </p>
              </div>
            </div>
            <Link
              to="/releases"
              className="text-xs font-mono text-red-400 hover:text-red-300 flex items-center gap-1 transition-colors"
            >
              Manage Releases <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                <span className="text-[11px] font-mono text-slate-400 block mb-1">
                  PRODUCTION CHANNEL
                </span>
                <span className="text-xl font-bold font-mono text-emerald-400">
                  v{releases.active_production_version || "1.0.0"}
                </span>
                <span className="text-[11px] text-slate-500 block mt-1">Signed Authority Manifest</span>
              </div>
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                <span className="text-[11px] font-mono text-slate-400 block mb-1">
                  STAGED CANDIDATE
                </span>
                <span className="text-xl font-bold font-mono text-red-400">
                  {releases.staged_version ? `v${releases.staged_version}` : "None Staged"}
                </span>
                <span className="text-[11px] text-slate-500 block mt-1">
                  {releases.rollout_state.toUpperCase()}
                </span>
              </div>
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                <span className="text-[11px] font-mono text-slate-400 block mb-1">
                  ROLLOUT PROGRESS
                </span>
                <span className="text-xl font-bold font-mono text-white">
                  {releases.current_rollout_percentage}%
                </span>
                <span className="text-[11px] text-slate-500 block mt-1">
                  Deterministic Hash Cohort
                </span>
              </div>
            </div>

            {/* Progress Bar */}
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono text-slate-400">
                <span>Deployment Progression</span>
                <span className="text-slate-200">{releases.current_rollout_percentage}% Complete</span>
              </div>
              <div className="h-2.5 w-full bg-slate-800/80 rounded-full overflow-hidden p-0.5">
                <div
                  className="h-full bg-gradient-to-r from-red-500 to-rose-400 rounded-full transition-all duration-500 shadow-sm shadow-cyan-500/50"
                  style={{ width: `${Math.max(releases.current_rollout_percentage, 5)}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Fleet Quick Status */}
        <div className="bg-[#131316] border border-[#27181c] rounded-2xl p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-5">
              <div className="flex items-center gap-2.5">
                <Smartphone className="w-5 h-5 text-purple-400" />
                <h3 className="text-base font-semibold text-white font-mono">CLIENT FLEET</h3>
              </div>
              <Badge variant="purple" size="sm">
                {clients.total_devices} TOTAL
              </Badge>
            </div>

            <div className="space-y-4">
              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-400 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-blue-400"></span>
                  PC Browser Extensions
                </span>
                <span className="font-mono font-bold text-white">{clients.browser_extensions}</span>
              </div>

              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-400 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                  Android Mobile Apps
                </span>
                <span className="font-mono font-bold text-white">{clients.mobile_devices}</span>
              </div>

              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-400 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-red-400"></span>
                  Active in Last 24 Hours
                </span>
                <span className="font-mono font-bold text-red-400">{clients.active_last_24h}</span>
              </div>

              <div className="flex items-center justify-between text-sm pt-3 border-t border-slate-800">
                <span className="text-slate-400">Fleet Policy Adoption</span>
                <span className="font-mono font-bold text-emerald-400">
                  {clients.fleet_adoption_rate}%
                </span>
              </div>
            </div>
          </div>

          <Link
            to="/clients"
            className="mt-6 w-full py-2.5 px-4 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-xl text-xs font-mono font-medium flex items-center justify-center gap-2 transition-colors"
          >
            Inspect Client Telemetry <ArrowUpRight className="w-4 h-4" />
          </Link>
        </div>
      </div>

      {/* Research Cycle & Recent Audit Log Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Research Pipeline Card */}
        <div className="bg-[#131316] border border-[#27181c] rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-5">
            <div className="flex items-center gap-2.5">
              <Layers className="w-5 h-5 text-indigo-400" />
              <h3 className="text-base font-semibold text-white font-mono">RESEARCH PIPELINE</h3>
            </div>
            <Link
              to="/lab"
              className="text-xs font-mono text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
            >
              Open Lab <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="space-y-4">
            <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex items-center justify-between">
              <div>
                <p className="text-xs font-mono text-slate-400">RED AI ADVERSARIAL EXPERIMENTS</p>
                <p className="text-lg font-bold text-white font-mono mt-0.5">
                  {research.completed_experiments} Completed / {research.active_experiments} Active
                </p>
              </div>
              <Link
                to="/lab"
                className="px-3 py-1.5 bg-rose-950/60 hover:bg-rose-900 text-rose-300 border border-rose-800/60 rounded-lg text-xs font-mono transition-colors"
              >
                Launch Test
              </Link>
            </div>

            <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex items-center justify-between">
              <div>
                <p className="text-xs font-mono text-slate-400">BLUE AI DEFENSIVE CANDIDATES</p>
                <p className="text-lg font-bold text-white font-mono mt-0.5">
                  {defense.total_candidates} Generated ({defense.pending_review_candidates} Pending Review)
                </p>
              </div>
              <Link
                to="/blue"
                className="px-3 py-1.5 bg-red-950/60 hover:bg-blue-900 text-red-300 border border-red-800/60 rounded-lg text-xs font-mono transition-colors"
              >
                Review
              </Link>
            </div>

            <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex items-center justify-between">
              <div>
                <p className="text-xs font-mono text-slate-400">INDEPENDENT EVALUATOR</p>
                <p className="text-lg font-bold text-white font-mono mt-0.5">
                  {evaluations.passed_evaluations} Benchmark Passes / {evaluations.failed_evaluations} Rejections
                </p>
              </div>
              <Link
                to="/evaluations"
                className="px-3 py-1.5 bg-emerald-950/60 hover:bg-emerald-900 text-emerald-300 border border-emerald-800/60 rounded-lg text-xs font-mono transition-colors"
              >
                Audit Reports
              </Link>
            </div>
          </div>
        </div>

        {/* Recent Audit Trail Feed */}
        <div className="bg-[#131316] border border-[#27181c] rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-5">
            <div className="flex items-center gap-2.5">
              <Clock className="w-5 h-5 text-amber-400" />
              <h3 className="text-base font-semibold text-white font-mono">
                SECURITY AUDIT STREAM
              </h3>
            </div>
            <Link
              to="/audit"
              className="text-xs font-mono text-amber-400 hover:text-amber-300 flex items-center gap-1"
            >
              Full Trail <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="space-y-3">
            {recent_events.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-8 font-mono">
                No recent security events recorded yet.
              </p>
            ) : (
              recent_events.slice(0, 5).map((evt) => (
                <div
                  key={evt.event_id}
                  className="p-3 bg-slate-900/40 border border-slate-800/80 rounded-xl flex items-center justify-between text-xs"
                >
                  <div className="space-y-0.5">
                    <p className="font-semibold text-slate-200 font-mono">{evt.title}</p>
                    <p className="text-[11px] text-slate-400">
                      Actor: <span className="text-slate-300 font-mono">{evt.actor}</span> •{" "}
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </p>
                  </div>
                  <Badge
                    variant={evt.outcome === "success" ? "success" : "danger"}
                    size="sm"
                  >
                    {evt.outcome.toUpperCase()}
                  </Badge>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
