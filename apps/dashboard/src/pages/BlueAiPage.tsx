import React, { useEffect, useState } from "react";
import {
  Shield,
  Plus,
  GitBranch,
  Layers,
  RefreshCw,
  Eye,
} from "lucide-react";
import { blueApi } from "../api/client";
import { CandidateDefense, FailureGroupSummary } from "../types";
import { Badge } from "../components/common/Badge";
import { Modal } from "../components/common/Modal";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { ErrorBanner } from "../components/common/ErrorBanner";
import { EmptyState } from "../components/common/EmptyState";
import { useAuth } from "../auth/AuthContext";

export const BlueAiPage: React.FC = () => {
  const { hasPermission } = useAuth();
  const [candidates, setCandidates] = useState<CandidateDefense[]>([]);
  const [failureGroups, setFailureGroups] = useState<FailureGroupSummary[]>([]);
  const [selectedCandidate, setSelectedCandidate] = useState<CandidateDefense | null>(null);
  const [comparisonData, setComparisonData] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // New Candidate Modal
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [candidateForm, setCandidateForm] = useState({
    candidate_version: "1.1.0",
    defense_type: "rule_update",
    changes_summary: "Enhanced entropy threshold and homoglyph normalization for financial targets",
    target_findings: ["FIND-HOMOGLYPH-01"],
  });

  const fetchData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [candList, groups] = await Promise.all([
        blueApi.getHistory(),
        blueApi.getFailureGroups().catch(() => []),
      ]);
      setCandidates(candList);
      setFailureGroups(groups);
    } catch (err: any) {
      setError(err.message || "Failed to load Blue AI candidates");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleSelectCandidate = async (c: CandidateDefense) => {
    setSelectedCandidate(c);
    try {
      const comp = await blueApi.getCandidateComparison(c.id);
      setComparisonData(comp);
    } catch {
      setComparisonData(null);
    }
  };

  const handleCreateCandidate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      await blueApi.createCandidate(candidateForm);
      setIsCreateModalOpen(false);
      fetchData();
    } catch (err: any) {
      alert(`Failed to create candidate: ${err.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const canResearch = hasPermission("blue:research");

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#1f293d]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h2 className="text-2xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Shield className="w-6 h-6 text-blue-500" />
              BLUE AI DEFENSE ENGINE
            </h2>
            <Badge variant="info" size="sm">ADAPTIVE DEFENSE</Badge>
          </div>
          <p className="text-sm text-slate-400">
            Formulation of evidence-based defensive hypotheses, rule updates, and candidate detector configurations.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            className="flex items-center gap-2 px-3.5 py-2 bg-[#111827] hover:bg-slate-800 text-slate-200 border border-[#1f293d] rounded-lg text-xs font-mono font-medium transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 text-blue-400" />
            Refresh
          </button>
          {canResearch && (
            <button
              onClick={() => setIsCreateModalOpen(true)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-mono font-medium transition-colors shadow-lg shadow-blue-900/30"
            >
              <Plus className="w-3.5 h-3.5" />
              Propose Candidate
            </button>
          )}
        </div>
      </div>

      {isLoading ? (
        <LoadingSpinner label="Fetching Blue AI candidates and failure groups..." />
      ) : error ? (
        <ErrorBanner message={error} onRetry={fetchData} />
      ) : (
        <div className="space-y-6">
          {/* Failure Groups Summary */}
          {failureGroups.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Active Failure Groups ({failureGroups.length})
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {failureGroups.map((g) => (
                  <div
                    key={g.group_id}
                    className="p-4 bg-[#111827] border border-[#1f293d] rounded-xl space-y-2 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-cyan-400">{g.category}</span>
                      <Badge variant="danger" size="sm">
                        {g.total_failures} Failures
                      </Badge>
                    </div>
                    <p className="text-slate-300 font-sans text-xs">{g.primary_hypothesis}</p>
                    <div className="text-[11px] text-slate-500 pt-2 border-t border-slate-800">
                      Candidates: {g.candidates_proposed}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Candidates Table */}
          <div className="space-y-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-blue-400" />
              Proposed Candidate Defenses ({candidates.length})
            </h3>

            {candidates.length === 0 ? (
              <EmptyState
                icon={Shield}
                title="No Candidate Defenses"
                description="The Blue AI engine has not generated candidate defenses yet. Propose a new candidate defense to mitigate observed failure modes."
                action={canResearch ? { label: "Propose Candidate", onClick: () => setIsCreateModalOpen(true) } : undefined}
              />
            ) : (
              <div className="overflow-x-auto bg-[#111827] border border-[#1f293d] rounded-2xl shadow-xl">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-3 px-4">VERSION</th>
                      <th className="py-3 px-4">DEFENSE TYPE</th>
                      <th className="py-3 px-4">CHANGES SUMMARY</th>
                      <th className="py-3 px-4">STATUS</th>
                      <th className="py-3 px-4">CREATED</th>
                      <th className="py-3 px-4 text-right">ACTION</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {candidates.map((c) => (
                      <tr
                        key={c.id}
                        onClick={() => handleSelectCandidate(c)}
                        className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                      >
                        <td className="py-3.5 px-4 font-bold text-blue-400">v{c.candidate_version}</td>
                        <td className="py-3.5 px-4 text-slate-300 uppercase">{c.defense_type}</td>
                        <td className="py-3.5 px-4 text-slate-300 max-w-sm truncate">
                          {c.changes_summary}
                        </td>
                        <td className="py-3.5 px-4">
                          <Badge
                            variant={
                              c.status === "approved"
                                ? "success"
                                : c.status === "submitted" || c.status === "draft"
                                ? "info"
                                : "danger"
                            }
                            size="sm"
                          >
                            {c.status.toUpperCase()}
                          </Badge>
                        </td>
                        <td className="py-3.5 px-4 text-slate-400">
                          {new Date(c.created_at).toLocaleDateString()}
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleSelectCandidate(c);
                            }}
                            className="text-blue-400 hover:text-blue-300"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Propose Candidate Modal */}
      <Modal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        title="Propose Candidate Defense"
        description="Submit a new candidate policy or heuristic rule for independent verification."
      >
        <form onSubmit={handleCreateCandidate} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Candidate Version</label>
            <input
              type="text"
              required
              value={candidateForm.candidate_version}
              onChange={(e) => setCandidateForm({ ...candidateForm, candidate_version: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Defense Type</label>
            <select
              value={candidateForm.defense_type}
              onChange={(e) => setCandidateForm({ ...candidateForm, defense_type: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-blue-500"
            >
              <option value="rule_update">Rule Update (Heuristic / Regex)</option>
              <option value="heuristic_weights">Heuristic Scoring Weights</option>
              <option value="model_parameters">Model Parameters</option>
              <option value="hybrid">Hybrid</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Changes Summary</label>
            <textarea
              required
              rows={3}
              value={candidateForm.changes_summary}
              onChange={(e) => setCandidateForm({ ...candidateForm, changes_summary: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsCreateModalOpen(false)}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-mono font-medium disabled:opacity-50"
            >
              {isSubmitting ? "Submitting..." : "Submit Candidate"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Candidate Details & Comparison Modal */}
      {selectedCandidate && (
        <Modal
          isOpen={!!selectedCandidate}
          onClose={() => setSelectedCandidate(null)}
          title={`Candidate Defense v${selectedCandidate.candidate_version}`}
          description={`Status: ${selectedCandidate.status.toUpperCase()} • Type: ${selectedCandidate.defense_type}`}
          maxWidth="lg"
        >
          <div className="space-y-4">
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
              <span className="text-xs font-mono text-slate-400">CHANGES SPECIFICATION</span>
              <p className="text-sm text-slate-200">{selectedCandidate.changes_summary}</p>
            </div>

            {selectedCandidate.review_notes && (
              <div className="p-3 bg-blue-950/40 border border-blue-900/60 rounded-xl text-xs font-mono text-blue-300">
                Review Notes: {selectedCandidate.review_notes}
              </div>
            )}

            {comparisonData && (
              <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-2 text-xs font-mono">
                <span className="text-slate-400 font-semibold block">BENCHMARK COMPARISON</span>
                <pre className="text-slate-300 overflow-x-auto p-2 bg-black/40 rounded">
                  {JSON.stringify(comparisonData, null, 2)}
                </pre>
              </div>
            )}

            <div className="flex justify-end pt-4 border-t border-slate-800">
              <button
                onClick={() => setSelectedCandidate(null)}
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
