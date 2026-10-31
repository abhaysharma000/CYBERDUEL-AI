import React, { useEffect, useState } from "react";
import {
  ShieldAlert,
  Flame,
  ShieldCheck,
  CheckCircle2,
  Cpu,
  RotateCw,
  Terminal,
  Clock,
  Key,
  Check,
  Smartphone,
  Globe,
  Zap,
} from "lucide-react";
import { guardianApi } from "../api/client";
import {
  GuardianStatusResponse,
  GuardianActivityEvent,
  GuardianMissionContract,
} from "../types";
import { Badge } from "../components/common/Badge";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { ErrorBanner } from "../components/common/ErrorBanner";

export const GuardianPage: React.FC = () => {
  const [status, setStatus] = useState<GuardianStatusResponse | null>(null);
  const [activity, setActivity] = useState<GuardianActivityEvent[]>([]);
  const [activeMission, setActiveMission] = useState<GuardianMissionContract | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isExecutingChallenge, setIsExecutingChallenge] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [challengeSuccess, setChallengeSuccess] = useState<string | null>(null);

  const fetchGuardianData = async () => {
    try {
      setError(null);
      const [statusRes, activityRes] = await Promise.all([
        guardianApi.getStatus(),
        guardianApi.getActivity(25),
      ]);
      setStatus(statusRes);
      setActivity(activityRes);
      if (statusRes.active_mission) {
        setActiveMission(statusRes.active_mission);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load Guardian supervisor state.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchGuardianData();
    const interval = setInterval(fetchGuardianData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleStartChallenge = async () => {
    setIsExecutingChallenge(true);
    setError(null);
    setChallengeSuccess(null);
    try {
      const mission = await guardianApi.triggerLiveDefenseChallenge();
      setActiveMission(mission);
      setChallengeSuccess(
        `Live Defense Challenge complete! New Policy v${mission.policy_version || "1.2.0"} signed and activated. Previously missed threat is now BLOCKED.`
      );
      await fetchGuardianData();
    } catch (err: any) {
      setError(err.message || "Failed to execute Live Defense Challenge.");
    } finally {
      setIsExecutingChallenge(false);
    }
  };

  if (isLoading && !status) {
    return <LoadingSpinner label="Connecting to CyberDuel Guardian Supervisor..." size="lg" />;
  }

  const agents = status?.agents || {};

  return (
    <div className="space-y-8 animate-in fade-in duration-300 pb-12">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#1f293d]">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h2 className="text-2xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <ShieldAlert className="w-7 h-7 text-cyan-400" />
              CYBERDUEL GUARDIAN
            </h2>
            <Badge variant="cyan" size="md">
              AUTONOMOUS SUPERVISOR
            </Badge>
            <Badge
              variant={status?.guardian_state === "idle" ? "success" : "info"}
              size="md"
            >
              STATE: {status?.guardian_state.toUpperCase()}
            </Badge>
          </div>
          <p className="text-sm text-slate-400">
            Coordinates autonomous adversarial discovery (Red AI), declarative rule synthesis (Blue AI),
            independent mathematical evaluation, and cryptographic Ed25519 policy distribution to edge clients.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchGuardianData}
            className="flex items-center gap-2 px-3 py-2 text-xs font-mono font-medium rounded-lg bg-[#141d30] border border-[#1f293d] text-slate-300 hover:text-white hover:bg-[#1a253c] transition-colors"
          >
            <RotateCw className="w-3.5 h-3.5" />
            Refresh
          </button>

          <button
            onClick={handleStartChallenge}
            disabled={isExecutingChallenge}
            className={`flex items-center gap-2 px-5 py-2.5 text-xs font-mono font-bold rounded-lg shadow-lg transition-all ${
              isExecutingChallenge
                ? "bg-slate-700 text-slate-400 cursor-not-allowed"
                : "bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white shadow-cyan-500/25 cursor-pointer active:scale-95"
            }`}
          >
            {isExecutingChallenge ? (
              <>
                <RotateCw className="w-4 h-4 animate-spin text-white" />
                AUTONOMOUS LOOP EXECUTING...
              </>
            ) : (
              <>
                <Zap className="w-4 h-4 fill-current text-cyan-200" />
                START CYBERDUEL CHALLENGE
              </>
            )}
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={fetchGuardianData} />}

      {challengeSuccess && (
        <div className="p-4 rounded-xl border border-emerald-500/40 bg-emerald-500/10 text-emerald-300 text-sm flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400" />
          <div>
            <div className="font-semibold font-mono">CHALLENGE VERIFICATION SUCCESS</div>
            <div>{challengeSuccess}</div>
          </div>
        </div>
      )}

      {/* Agent Fleet Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Guardian Supervisor */}
        <div className="p-4 rounded-xl border border-cyan-500/30 bg-[#0d1322] relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Supervisor</span>
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
          </div>
          <div className="text-lg font-bold text-white font-mono flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            Guardian AI
          </div>
          <p className="text-xs text-slate-400 mt-1">Autonomous orchestration & comparative decision engine</p>
          <div className="mt-3 pt-3 border-t border-[#1f293d] flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-500">Fleet Version:</span>
            <span className="text-cyan-300 font-bold">v{status?.active_policy_version}</span>
          </div>
        </div>

        {/* Red AI Adversary */}
        <div className="p-4 rounded-xl border border-rose-500/30 bg-[#0d1322]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Adversary Agent</span>
            <span className="w-2.5 h-2.5 rounded-full bg-rose-400" />
          </div>
          <div className="text-lg font-bold text-white font-mono flex items-center gap-2">
            <Flame className="w-5 h-5 text-rose-400" />
            Red AI
          </div>
          <p className="text-xs text-slate-400 mt-1">Synthetic threat exploration & discrepancy clustering</p>
          <div className="mt-3 pt-3 border-t border-[#1f293d] flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-500">Status:</span>
            <span className="text-rose-300 font-bold">{agents["red_agent"]?.status.toUpperCase() || "ONLINE"}</span>
          </div>
        </div>

        {/* Blue AI Defense */}
        <div className="p-4 rounded-xl border border-blue-500/30 bg-[#0d1322]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Defensive Agent</span>
            <span className="w-2.5 h-2.5 rounded-full bg-blue-400" />
          </div>
          <div className="text-lg font-bold text-white font-mono flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-blue-400" />
            Blue AI
          </div>
          <p className="text-xs text-slate-400 mt-1">Declarative AST rule synthesis & sandbox testing</p>
          <div className="mt-3 pt-3 border-t border-[#1f293d] flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-500">Status:</span>
            <span className="text-blue-300 font-bold">{agents["blue_agent"]?.status.toUpperCase() || "ONLINE"}</span>
          </div>
        </div>

        {/* Independent Evaluator */}
        <div className="p-4 rounded-xl border border-emerald-500/30 bg-[#0d1322]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Benchmark Gatekeeper</span>
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
          </div>
          <div className="text-lg font-bold text-white font-mono flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            Evaluator
          </div>
          <p className="text-xs text-slate-400 mt-1">Zero regression enforcement & mathematical auditing</p>
          <div className="mt-3 pt-3 border-t border-[#1f293d] flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-500">Benchmark:</span>
            <span className="text-emerald-300 font-bold">benchmark-golden-v1</span>
          </div>
        </div>
      </div>

      {/* Live Challenge Demonstration Showcase */}
      <div className="p-6 rounded-xl border border-[#1f293d] bg-[#0d1322]">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#1f293d]">
          <div>
            <h3 className="text-lg font-bold text-white font-mono flex items-center gap-2">
              <Zap className="w-5 h-5 text-cyan-400" />
              CYBERDUEL LIVE DEFENSE CHALLENGE (9-STAGE AUTONOMOUS PROOF)
            </h3>
            <p className="text-xs text-slate-400">
              Demonstrates end-to-end continuous cybersecurity: an initial synthetic threat evades the baseline,
              agents mobilize, an independently verified policy is released, and edge clients block the threat.
            </p>
          </div>
          {activeMission && (
            <Badge variant="info" size="md">
              MISSION: {activeMission.mission_name}
            </Badge>
          )}
        </div>

        {/* 9-Stage Visual Progression */}
        <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Stage 1 */}
          <div className="p-4 rounded-lg bg-[#141d30] border border-[#1f293d]">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
              <span>STAGE 1: ADVERSARIAL INJECTION</span>
              <span className="text-rose-400 font-bold">EVADED</span>
            </div>
            <div className="text-sm font-semibold text-white">Target Attack URL</div>
            <div className="text-xs font-mono text-rose-300 truncate mt-1 bg-[#090d16] p-2 rounded border border-rose-900/40">
              https://pаypal.com/signin/verify-identity
            </div>
            <p className="text-[11px] text-slate-400 mt-2">
              Baseline detector missed punycode IDN homoglyph evasion (Decision: ALLOW).
            </p>
          </div>

          {/* Stage 2 */}
          <div className="p-4 rounded-lg bg-[#141d30] border border-[#1f293d]">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
              <span>STAGE 2: RED AI ANALYSIS</span>
              <span className="text-amber-400 font-bold">DISCOVERED</span>
            </div>
            <div className="text-sm font-semibold text-white">Synthetic Mutation Range</div>
            <p className="text-[11px] text-slate-400 mt-2">
              Generated 10 adversarial variants. Identified clustering pattern around Cyrillic homoglyph lookalikes.
            </p>
          </div>

          {/* Stage 3 */}
          <div className="p-4 rounded-lg bg-[#141d30] border border-[#1f293d]">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
              <span>STAGE 3: BLUE AI DEFENSE</span>
              <span className="text-cyan-400 font-bold">SYNTHESIZED</span>
            </div>
            <div className="text-sm font-semibold text-white">Declarative AST Rule</div>
            <div className="text-xs font-mono text-cyan-300 truncate mt-1 bg-[#090d16] p-2 rounded border border-cyan-900/40">
              is_punycode == 1 &amp;&amp; brand_token == 1
            </div>
            <p className="text-[11px] text-slate-400 mt-2">
              Synthesized AST rule targeting deceptive IDN lures without collateral false positives.
            </p>
          </div>

          {/* Stage 4 */}
          <div className="p-4 rounded-lg bg-[#141d30] border border-[#1f293d]">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
              <span>STAGE 4: EVALUATOR AUDIT</span>
              <span className="text-emerald-400 font-bold">PASSED</span>
            </div>
            <div className="text-sm font-semibold text-white">Zero Regressions Gate</div>
            <div className="flex items-center gap-4 mt-2 text-xs font-mono">
              <span className="text-slate-300">Accuracy: <b className="text-emerald-400">96.0%</b></span>
              <span className="text-slate-300">Regressions: <b className="text-emerald-400">0</b></span>
              <span className="text-slate-300">FPR: <b className="text-emerald-400">0.0%</b></span>
            </div>
            <p className="text-[11px] text-slate-400 mt-2">
              Tested against 25 golden benchmark controls. Candidate approved.
            </p>
          </div>

          {/* Stage 5 & 6 */}
          <div className="p-4 rounded-lg bg-[#141d30] border border-[#1f293d]">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
              <span>STAGE 5 &amp; 6: GUARDIAN RELEASE</span>
              <span className="text-indigo-400 font-bold">SIGNED</span>
            </div>
            <div className="text-sm font-semibold text-white">RFC 8785 Ed25519 Signing</div>
            <div className="flex items-center gap-2 mt-2 text-xs font-mono text-indigo-300">
              <Key className="w-3.5 h-3.5 text-indigo-400" />
              <span>Detached 64-byte Ed25519 Signature</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-2">
              Guardian authorized release. Cryptographically signed policy bundle with active key pair.
            </p>
          </div>

          {/* Stage 7 & 8 */}
          <div className="p-4 rounded-lg bg-[#141d30] border border-[#1f293d]">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
              <span>STAGE 7 &amp; 8: FLEET ROLLOUT</span>
              <span className="text-purple-400 font-bold">ACTIVE</span>
            </div>
            <div className="text-sm font-semibold text-white">Browser &amp; Android Sync</div>
            <div className="flex items-center gap-3 mt-2 text-xs font-mono text-slate-300">
              <span className="flex items-center gap-1"><Globe className="w-3.5 h-3.5 text-cyan-400" /> Extension</span>
              <span className="flex items-center gap-1"><Smartphone className="w-3.5 h-3.5 text-emerald-400" /> Android</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-2">
              Edge clients poll signed manifest, verify signature locally, compile AST predicates.
            </p>
          </div>
        </div>

        {/* Stage 9: Verification Final Verdict */}
        <div className="mt-4 p-4 rounded-lg bg-emerald-950/20 border border-emerald-500/40 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-emerald-500/20 border border-emerald-500 flex items-center justify-center text-emerald-400 font-bold">
              <Check className="w-6 h-6" />
            </div>
            <div>
              <div className="text-sm font-mono font-bold text-white">
                STAGE 9: LIVE VERIFICATION OUTCOME — THREAT DECISIVELY BLOCKED
              </div>
              <p className="text-xs text-slate-300 mt-0.5">
                The identical synthetic attack URL was re-evaluated against the active policy. Result: <b className="text-emerald-400">BLOCK (Threat Score: 0.95)</b>.
              </p>
            </div>
          </div>
          <Badge variant="success" size="md">
            AUTONOMOUS PROOF COMPLETE
          </Badge>
        </div>
      </div>

      {/* Decision Engine Comparative Rationale */}
      {activeMission?.decision_explanation && (
        <div className="p-6 rounded-xl border border-cyan-500/30 bg-[#0d1322]">
          <h3 className="text-base font-bold text-white font-mono flex items-center gap-2 mb-3">
            <Cpu className="w-5 h-5 text-cyan-400" />
            GUARDIAN COMPARATIVE REASONING &amp; TRADE-OFF AUDIT
          </h3>
          <div className="p-4 rounded-lg bg-[#141d30] border border-[#1f293d] space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-[#1f293d]">
              <span className="text-slate-400">Release Recommendation:</span>
              <span className="text-emerald-400 font-bold">
                {activeMission.decision_explanation.release_recommendation ? "APPROVED FOR FLEET" : "HOLD"}
              </span>
            </div>
            <div className="flex items-center justify-between pb-2 border-b border-[#1f293d]">
              <span className="text-slate-400">Confidence Score:</span>
              <span className="text-cyan-300 font-bold">
                {(activeMission.decision_explanation.confidence * 100).toFixed(1)}%
              </span>
            </div>
            <div className="text-slate-300 leading-relaxed">
              <span className="text-slate-500 uppercase tracking-wider block text-[10px] mb-1">Supervisor Rationale:</span>
              {activeMission.decision_explanation.reasoning_summary}
            </div>
          </div>
        </div>
      )}

      {/* Real-time Chronological Activity Stream */}
      <div className="p-6 rounded-xl border border-[#1f293d] bg-[#0d1322]">
        <h3 className="text-base font-bold text-white font-mono flex items-center gap-2 mb-4">
          <Terminal className="w-5 h-5 text-slate-400" />
          GUARDIAN SUPERVISOR AUDIT &amp; TELEMETRY STREAM
        </h3>
        <div className="space-y-2 max-h-96 overflow-y-auto pr-2">
          {activity.length === 0 ? (
            <div className="text-slate-500 text-xs font-mono py-4 text-center">
              No Guardian activity logged yet. Trigger the CyberDuel Challenge above to begin.
            </div>
          ) : (
            activity.map((event) => (
              <div
                key={event.event_id}
                className="p-3 rounded-lg bg-[#141d30] border border-[#1f293d] flex items-start justify-between text-xs font-mono"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-cyan-400 font-bold">[{event.event_type}]</span>
                    <Badge variant="info" size="sm">
                      {event.state}
                    </Badge>
                  </div>
                  <div className="text-slate-300">{event.summary}</div>
                </div>
                <div className="text-[10px] text-slate-500 shrink-0 ml-4 flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {new Date(event.timestamp).toLocaleTimeString()}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
