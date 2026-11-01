import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { Zap, Lock, User, ArrowRight } from "lucide-react";

export const LoginPage: React.FC = () => {
  const { login, availableOperators, switchOperator } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      await login(username, password);
      navigate("/");
    } catch (err: any) {
      setError(err.message || "Invalid operator credentials");
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickLogin = async (uname: string) => {
    setIsLoading(true);
    try {
      await switchOperator(uname);
      navigate("/");
    } catch (err: any) {
      setError(err.message || "Failed to switch operator");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#08080a] flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-6">
        {/* Logo and Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex w-12 h-12 rounded-2xl bg-gradient-to-tr from-red-600 to-rose-500 items-center justify-center shadow-xl shadow-red-500/30 text-white font-bold mb-2">
            <Zap className="w-7 h-7 fill-current" />
          </div>
          <h1 className="text-xl font-bold font-mono tracking-wider text-white">
            CYBERDUEL <span className="text-red-400">AI</span>
          </h1>
          <p className="text-xs font-mono text-slate-400 uppercase tracking-widest">
            OPERATIONAL COMMAND CENTER ACCESS
          </p>
        </div>

        {/* Login Card */}
        <div className="bg-[#131316] border border-[#27181c] rounded-2xl p-8 shadow-2xl space-y-6">
          {error && (
            <div className="p-3 bg-rose-950/60 border border-rose-900/60 rounded-xl text-xs text-rose-300 font-mono">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">OPERATOR ID</label>
              <div className="relative">
                <input
                  type="text"
                  required
                  placeholder="admin, researcher, releaser..."
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-red-500"
                />
                <User className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">CREDENTIAL KEY</label>
              <div className="relative">
                <input
                  type="password"
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-red-500"
                />
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 px-4 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-mono font-medium transition-colors shadow-lg shadow-red-900/40 flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {isLoading ? "Authenticating..." : "Authorize Session"}
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          {/* Quick Demo Operator Personas */}
          <div className="pt-4 border-t border-slate-800 space-y-2">
            <span className="text-[11px] font-mono text-slate-500 block uppercase tracking-wider text-center">
              Quick Role Simulation
            </span>
            <div className="grid grid-cols-2 gap-2">
              {availableOperators.map((op) => (
                <button
                  key={op.username}
                  type="button"
                  onClick={() => handleQuickLogin(op.username)}
                  className="p-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 rounded-lg text-left text-xs transition-colors font-mono"
                >
                  <span className="font-semibold text-slate-200 block truncate">{op.display_name}</span>
                  <span className="text-[10px] text-red-400 uppercase">{op.role}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
