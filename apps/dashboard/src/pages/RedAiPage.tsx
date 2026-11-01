import React, { useEffect, useState } from "react";
import {
  Flame,
  Plus,
  Play,
  RefreshCw,
  Database,
} from "lucide-react";
import { labApi } from "../api/client";
import { LabExperiment, ScenarioContract } from "../types";
import { Badge } from "../components/common/Badge";
import { Modal } from "../components/common/Modal";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { ErrorBanner } from "../components/common/ErrorBanner";
import { EmptyState } from "../components/common/EmptyState";
import { PrivacyUrl } from "../components/common/PrivacyUrl";
import { useAuth } from "../auth/AuthContext";

export const RedAiPage: React.FC = () => {
  const { hasPermission } = useAuth();
  const [experiments, setExperiments] = useState<LabExperiment[]>([]);
  const [scenarios, setScenarios] = useState<ScenarioContract[]>([]);
  const [selectedExp, setSelectedExp] = useState<LabExperiment | null>(null);
  const [activeTab, setActiveTab] = useState<"experiments" | "scenarios">("experiments");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Modal State
  const [isLaunchModalOpen, setIsLaunchModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [launchForm, setLaunchForm] = useState({
    experiment_name: "Adversarial Stress Test",
    goal: "Evaluate homograph obfuscation and credential-harvesting resilience",
    scenario_count: 50,
  });

  const fetchData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [expList, scnList] = await Promise.all([
        labApi.getExperiments({ limit: 50 }),
        labApi.getScenarios(undefined, 50),
      ]);
      setExperiments(expList);
      setScenarios(scnList);
    } catch (err: any) {
      setError(err.message || "Failed to load Red AI experiments and scenarios");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleLaunchExperiment = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      await labApi.runExperiment(launchForm);
      setIsLaunchModalOpen(false);
      fetchData();
    } catch (err: any) {
      alert(`Failed to launch experiment: ${err.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const canExecute = hasPermission("lab:execute");

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#27181c]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h2 className="text-2xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Flame className="w-6 h-6 text-rose-500" />
              RED AI RESEARCH LABORATORY
            </h2>
            <Badge variant="danger" size="sm">ADVERSARIAL RANGE</Badge>
          </div>
          <p className="text-sm text-slate-400">
            Automated generation of synthetic phishing, homoglyphs, and evasive threat scenarios in an isolated range.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            className="flex items-center gap-2 px-3.5 py-2 bg-[#131316] hover:bg-slate-800 text-slate-200 border border-[#27181c] rounded-lg text-xs font-mono font-medium transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 text-rose-400" />
            Refresh
          </button>
          {canExecute && (
            <button
              onClick={() => setIsLaunchModalOpen(true)}
              className="flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-mono font-medium transition-colors shadow-lg shadow-rose-900/30"
            >
              <Plus className="w-3.5 h-3.5" />
              New Experiment
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-6">
        <button
          onClick={() => setActiveTab("experiments")}
          className={`pb-3 text-sm font-mono font-semibold transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "experiments"
              ? "border-rose-500 text-rose-400"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Play className="w-4 h-4" />
          Experiment Runs ({experiments.length})
        </button>
        <button
          onClick={() => setActiveTab("scenarios")}
          className={`pb-3 text-sm font-mono font-semibold transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "scenarios"
              ? "border-rose-500 text-rose-400"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Database className="w-4 h-4" />
          Scenario Catalog ({scenarios.length})
        </button>
      </div>

      {isLoading ? (
        <LoadingSpinner label="Querying Red AI experimental data..." />
      ) : error ? (
        <ErrorBanner message={error} onRetry={fetchData} />
      ) : activeTab === "experiments" ? (
        experiments.length === 0 ? (
          <EmptyState
            icon={Flame}
            title="No Lab Experiments Executed"
            description="The Red AI laboratory hasn't executed any adversarial runs yet. Launch a new experiment to begin adversarial evaluations."
            action={canExecute ? { label: "Run Experiment", onClick: () => setIsLaunchModalOpen(true) } : undefined}
          />
        ) : (
          <div className="grid grid-cols-1 gap-4">
            {experiments.map((exp) => (
              <div
                key={exp.experiment_id}
                onClick={() => setSelectedExp(exp)}
                className="p-5 bg-[#131316] border border-[#27181c] hover:border-slate-700 rounded-xl cursor-pointer transition-all duration-200 shadow-md space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <Badge
                      variant={
                        exp.status === "completed"
                          ? "success"
                          : exp.status === "running"
                          ? "warning"
                          : "danger"
                      }
                    >
                      {exp.status.toUpperCase()}
                    </Badge>
                    <span className="font-bold text-white font-mono text-sm">{exp.experiment_name}</span>
                  </div>
                  <div className="text-xs font-mono text-slate-400">
                    ID: {exp.experiment_id.slice(0, 8)}... • Seed: {exp.seed}
                  </div>
                </div>

                <p className="text-xs text-slate-400">{exp.goal}</p>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800/80 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block">Scenarios</span>
                    <span className="text-slate-200 font-semibold">{exp.scenario_count}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Executed</span>
                    <span className="text-slate-200 font-semibold">{exp.executed_count}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Discrepancies</span>
                    <span className="text-rose-400 font-bold">{exp.discrepancy_count}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Findings</span>
                    <span className="text-amber-400 font-semibold">{exp.findings?.length || 0}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )
      ) : (
        <div className="overflow-x-auto bg-[#131316] border border-[#27181c] rounded-2xl shadow-xl">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">FAMILY</th>
                <th className="py-3 px-4">SCENARIO NAME</th>
                <th className="py-3 px-4">INPUT FIXTURE (REDACTED)</th>
                <th className="py-3 px-4">EXPECTED</th>
                <th className="py-3 px-4">DIFFICULTY</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {scenarios.map((s) => (
                <tr key={s.scenario_id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4 text-rose-400 font-semibold">{s.scenario_family}</td>
                  <td className="py-3 px-4 text-slate-200">{s.scenario_name}</td>
                  <td className="py-3 px-4 max-w-xs">
                    <PrivacyUrl url={s.input_fixture?.raw_url || ""} />
                  </td>
                  <td className="py-3 px-4">
                    <Badge variant={s.expected_decision === "block" ? "danger" : "success"} size="sm">
                      {s.expected_decision.toUpperCase()}
                    </Badge>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-slate-400 uppercase">{s.difficulty}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Launch Experiment Modal */}
      <Modal
        isOpen={isLaunchModalOpen}
        onClose={() => setIsLaunchModalOpen(false)}
        title="Launch Red AI Experiment"
        description="Configure parameters for synthetic adversarial scenario execution."
        variant="info"
      >
        <form onSubmit={handleLaunchExperiment} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Experiment Name</label>
            <input
              type="text"
              required
              value={launchForm.experiment_name}
              onChange={(e) => setLaunchForm({ ...launchForm, experiment_name: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-rose-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Research Goal</label>
            <textarea
              required
              rows={3}
              value={launchForm.goal}
              onChange={(e) => setLaunchForm({ ...launchForm, goal: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-rose-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Scenario Count</label>
            <input
              type="number"
              min={1}
              max={200}
              value={launchForm.scenario_count}
              onChange={(e) => setLaunchForm({ ...launchForm, scenario_count: parseInt(e.target.value) || 20 })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-rose-500 font-mono"
            />
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsLaunchModalOpen(false)}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-mono font-medium disabled:opacity-50"
            >
              {isSubmitting ? "Dispatching..." : "Execute Experiment"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Experiment Detail Modal */}
      {selectedExp && (
        <Modal
          isOpen={!!selectedExp}
          onClose={() => setSelectedExp(null)}
          title={selectedExp.experiment_name}
          description={`Executed against detector ${selectedExp.detector_version} (Seed: ${selectedExp.seed})`}
          maxWidth="lg"
        >
          <div className="space-y-4">
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
              <span className="text-xs font-mono text-slate-400 block">OBJECTIVE & GOAL</span>
              <p className="text-sm text-slate-200">{selectedExp.goal}</p>
            </div>

            <div>
              <h4 className="text-xs font-mono font-semibold text-slate-300 mb-2 uppercase">
                Failure Findings ({selectedExp.findings?.length || 0})
              </h4>
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {selectedExp.findings?.length === 0 ? (
                  <p className="text-xs font-mono text-slate-500 py-4 text-center">
                    Zero failure findings discovered. Detector demonstrated complete accuracy.
                  </p>
                ) : (
                  selectedExp.findings?.map((f) => (
                    <div
                      key={f.finding_id}
                      className="p-3 bg-slate-900/60 border border-rose-900/40 rounded-lg space-y-1 text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-rose-400">{f.failure_category}</span>
                        <Badge variant="danger" size="sm">
                          {f.severity.toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-slate-300">{f.hypothesis}</p>
                      {f.suggested_remedy && (
                        <p className="text-slate-400 text-[11px] font-mono">
                          Remedy: {f.suggested_remedy}
                        </p>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="flex justify-end pt-4 border-t border-slate-800">
              <button
                onClick={() => setSelectedExp(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono"
              >
                Close
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
