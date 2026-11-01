import React, { useEffect, useState } from "react";
import {
  Package,
  ArrowRight,
  RotateCcw,
  Play,
  Pause,
  Key,
  RefreshCw,
  Plus,
  ShieldAlert,
} from "lucide-react";
import { releasesApi } from "../api/client";
import { ReleaseSummary } from "../types";
import { Badge } from "../components/common/Badge";
import { Modal } from "../components/common/Modal";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { ErrorBanner } from "../components/common/ErrorBanner";
import { EmptyState } from "../components/common/EmptyState";
import { useAuth } from "../auth/AuthContext";

export const ReleasesPage: React.FC = () => {
  const { hasPermission } = useAuth();
  const [releases, setReleases] = useState<ReleaseSummary[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Authorize Modal
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [authForm, setAuthForm] = useState({
    candidate_id: "",
    policy_version: "1.1.0",
    target_channel: "stable",
    initial_rollout_percentage: 10,
    key_id: "sec_key_2026_primary",
  });

  // Rollback Modal
  const [isRollbackModalOpen, setIsRollbackModalOpen] = useState(false);
  const [rollbackForm, setRollbackForm] = useState({
    active_release_id: "",
    target_previous_release_id: "",
    rationale: "Unanticipated edge client false-positive anomaly detected",
    key_id: "sec_key_2026_primary",
  });

  const [isSubmitting, setIsSubmitting] = useState(false);

  const fetchData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await releasesApi.getReleases({ limit: 50 });
      setReleases(res);
    } catch (err: any) {
      setError(err.message || "Failed to load security releases");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleAuthorizeRelease = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      await releasesApi.authorizeRelease(authForm);
      setIsAuthModalOpen(false);
      fetchData();
    } catch (err: any) {
      alert(`Authorization failed: ${err.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAdvanceRollout = async (releaseId: string, currentPct: number) => {
    const nextPct = currentPct < 25 ? 25 : currentPct < 50 ? 50 : 100;
    if (!confirm(`Advance rollout to ${nextPct}% for release ${releaseId}?`)) return;
    try {
      await releasesApi.advanceRollout(releaseId, nextPct, "Gradual staged rollout progression");
      fetchData();
    } catch (err: any) {
      alert(`Advance failed: ${err.message}`);
    }
  };

  const handlePauseRollout = async (releaseId: string) => {
    const reason = prompt("Enter rationale for pausing rollout:", "Telemetry anomaly investigation");
    if (!reason) return;
    try {
      await releasesApi.pauseRollout(releaseId, reason);
      fetchData();
    } catch (err: any) {
      alert(`Pause failed: ${err.message}`);
    }
  };

  const handleResumeRollout = async (releaseId: string) => {
    if (!confirm("Resume rollout?")) return;
    try {
      await releasesApi.resumeRollout(releaseId);
      fetchData();
    } catch (err: any) {
      alert(`Resume failed: ${err.message}`);
    }
  };

  const handleRollback = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      await releasesApi.rollbackRelease(rollbackForm);
      setIsRollbackModalOpen(false);
      fetchData();
    } catch (err: any) {
      alert(`Rollback failed: ${err.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const canManageReleases = hasPermission("releases:manage");

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#27181c]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h2 className="text-2xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Package className="w-6 h-6 text-red-500" />
              SECURITY RELEASE MANAGEMENT
            </h2>
            <Badge variant="cyan" size="sm">CRYPTOGRAPHIC ED25519</Badge>
          </div>
          <p className="text-sm text-slate-400">
            Digitally signed policy manifest authorizations, staged percentage rollouts, and instant signed rollbacks.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            className="flex items-center gap-2 px-3.5 py-2 bg-[#131316] hover:bg-slate-800 text-slate-200 border border-[#27181c] rounded-lg text-xs font-mono font-medium transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 text-red-400" />
            Refresh
          </button>
          {canManageReleases && (
            <>
              <button
                onClick={() => setIsRollbackModalOpen(true)}
                className="flex items-center gap-2 px-3.5 py-2 bg-rose-950/60 hover:bg-rose-900 text-rose-300 border border-rose-800/60 rounded-lg text-xs font-mono font-medium transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                Emergency Rollback
              </button>
              <button
                onClick={() => setIsAuthModalOpen(true)}
                className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-mono font-medium transition-colors shadow-lg shadow-red-900/40"
              >
                <Plus className="w-3.5 h-3.5" />
                Authorize Release
              </button>
            </>
          )}
        </div>
      </div>

      {isLoading ? (
        <LoadingSpinner label="Auditing security releases and digital signatures..." />
      ) : error ? (
        <ErrorBanner message={error} onRetry={fetchData} />
      ) : (
        <div className="space-y-6">
          {releases.length === 0 ? (
            <EmptyState
              icon={Package}
              title="No Security Releases Found"
              description="No signed policy releases have been staged or published yet. Authorize an evaluated candidate defense to stage the first release."
              action={canManageReleases ? { label: "Authorize Release", onClick: () => setIsAuthModalOpen(true) } : undefined}
            />
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {releases.map((rel) => (
                <div
                  key={rel.release_id}
                  className="p-6 bg-[#131316] border border-[#27181c] rounded-2xl shadow-xl space-y-4"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
                    <div className="flex items-center gap-3">
                      <span className="text-xl font-bold font-mono text-white">
                        Release v{rel.policy_version}
                      </span>
                      <Badge
                        variant={
                          rel.status === "published" || rel.status === "active"
                            ? "success"
                            : rel.status === "staged" || rel.status === "approved"
                            ? "info"
                            : rel.status === "paused"
                            ? "warning"
                            : "danger"
                        }
                      >
                        {rel.status.toUpperCase()}
                      </Badge>
                      <span className="text-xs font-mono text-slate-400 uppercase">
                        Channel: <span className="text-red-400">{rel.channel}</span>
                      </span>
                    </div>

                    <div className="text-xs font-mono text-slate-400 flex items-center gap-2">
                      <Key className="w-3.5 h-3.5 text-red-400" />
                      Key: <span className="text-slate-300">{rel.publisher_key_id}</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                    <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl">
                      <span className="text-slate-500 block mb-1">SHA-256 ARTIFACT DIGEST</span>
                      <span className="text-slate-300 truncate block">{rel.artifact_digest}</span>
                    </div>
                    <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl">
                      <span className="text-slate-500 block mb-1">BUNDLE SIZE</span>
                      <span className="text-slate-200">
                        {(rel.artifact_size_bytes / 1024).toFixed(1)} KB (Immutable Policy Bundle)
                      </span>
                    </div>
                    <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl">
                      <span className="text-slate-500 block mb-1">ROLLOUT STAGE</span>
                      <span className="text-emerald-400 font-bold">
                        {rel.current_rollout_percentage}% • {rel.rollout_phase?.toUpperCase() || "ACTIVE"}
                      </span>
                    </div>
                  </div>

                  {/* Staged Rollout Actions */}
                  {canManageReleases && (
                    <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800/80">
                      <div className="flex items-center gap-2">
                        {rel.current_rollout_percentage < 100 && rel.status !== "paused" && (
                          <button
                            onClick={() => handleAdvanceRollout(rel.release_id, rel.current_rollout_percentage)}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 rounded-lg text-xs font-mono transition-colors"
                          >
                            <ArrowRight className="w-3.5 h-3.5" />
                            Advance Rollout Stage
                          </button>
                        )}
                        {rel.status === "paused" ? (
                          <button
                            onClick={() => handleResumeRollout(rel.release_id)}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-mono transition-colors"
                          >
                            <Play className="w-3.5 h-3.5" />
                            Resume Rollout
                          </button>
                        ) : (
                          <button
                            onClick={() => handlePauseRollout(rel.release_id)}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 border border-amber-500/30 rounded-lg text-xs font-mono transition-colors"
                          >
                            <Pause className="w-3.5 h-3.5" />
                            Pause Rollout
                          </button>
                        )}
                      </div>

                      <div className="text-[11px] font-mono text-slate-500">
                        Created: {new Date(rel.created_at).toLocaleString()}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Authorize Release Modal */}
      <Modal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        title="Authorize Security Release"
        description="Digitally sign and stage an evaluated candidate policy for fleet deployment."
      >
        <form onSubmit={handleAuthorizeRelease} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Policy Version</label>
            <input
              type="text"
              required
              value={authForm.policy_version}
              onChange={(e) => setAuthForm({ ...authForm, policy_version: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-red-500"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Target Channel</label>
            <select
              value={authForm.target_channel}
              onChange={(e) => setAuthForm({ ...authForm, target_channel: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-red-500"
            >
              <option value="stable">Stable (Global Fleet)</option>
              <option value="canary">Canary (10% Pre-release)</option>
              <option value="emergency">Emergency Immediate Patch</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Initial Rollout Percentage (%)
            </label>
            <input
              type="number"
              min={1}
              max={100}
              value={authForm.initial_rollout_percentage}
              onChange={(e) =>
                setAuthForm({ ...authForm, initial_rollout_percentage: parseInt(e.target.value) || 10 })
              }
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-red-500"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Authority Key ID</label>
            <input
              type="text"
              required
              value={authForm.key_id}
              onChange={(e) => setAuthForm({ ...authForm, key_id: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-red-500"
            />
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsAuthModalOpen(false)}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-mono font-medium disabled:opacity-50"
            >
              {isSubmitting ? "Signing & Staging..." : "Sign & Stage Release"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Emergency Rollback Modal */}
      <Modal
        isOpen={isRollbackModalOpen}
        onClose={() => setIsRollbackModalOpen(false)}
        title="Emergency Security Rollback"
        description="Instantly revert connected edge devices to a cryptographically verified prior policy."
        variant="danger"
      >
        <form onSubmit={handleRollback} className="space-y-4">
          <div className="p-3 bg-rose-950/40 border border-rose-900/60 rounded-xl text-xs text-rose-300 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
            <span>
              Rollback will generate a signed revocation token forcing clients to immediately fall back to the selected target policy.
            </span>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Active Release to Revoke
            </label>
            <input
              type="text"
              required
              placeholder="UUID of active release"
              value={rollbackForm.active_release_id}
              onChange={(e) => setRollbackForm({ ...rollbackForm, active_release_id: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-rose-500"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Target Previous Release (Safe Baseline)
            </label>
            <input
              type="text"
              required
              placeholder="UUID of verified prior release"
              value={rollbackForm.target_previous_release_id}
              onChange={(e) =>
                setRollbackForm({ ...rollbackForm, target_previous_release_id: e.target.value })
              }
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-rose-500"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Mandatory Rollback Rationale
            </label>
            <textarea
              required
              rows={3}
              value={rollbackForm.rationale}
              onChange={(e) => setRollbackForm({ ...rollbackForm, rationale: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-rose-500"
            />
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsRollbackModalOpen(false)}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-mono font-medium disabled:opacity-50"
            >
              {isSubmitting ? "Executing Rollback..." : "Execute Emergency Rollback"}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
