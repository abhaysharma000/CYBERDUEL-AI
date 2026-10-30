import React, { useEffect, useState } from "react";
import {
  Smartphone,
  Globe,
  RefreshCw,
  Clock,
  Eye,
  SlidersHorizontal,
} from "lucide-react";
import { clientsApi } from "../api/client";
import { ClientDevice, ClientMetrics } from "../types";
import { Badge } from "../components/common/Badge";
import { Modal } from "../components/common/Modal";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { ErrorBanner } from "../components/common/ErrorBanner";
import { EmptyState } from "../components/common/EmptyState";
import { StatCard } from "../components/common/StatCard";

export const ClientsPage: React.FC = () => {
  const [clients, setClients] = useState<ClientDevice[]>([]);
  const [metrics, setMetrics] = useState<ClientMetrics | null>(null);
  const [selectedClient, setSelectedClient] = useState<any | null>(null);
  const [filterType, setFilterType] = useState<string>("");
  const [filterChannel, setFilterChannel] = useState<string>("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [list, m] = await Promise.all([
        clientsApi.getClients({
          client_type: filterType || undefined,
          channel: filterChannel || undefined,
          limit: 100,
        }),
        clientsApi.getClientMetrics(),
      ]);
      setClients(list);
      setMetrics(m);
    } catch (err: any) {
      setError(err.message || "Failed to load client fleet telemetry");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [filterType, filterChannel]);

  const handleInspectClient = async (clientId: string) => {
    try {
      const details = await clientsApi.getClient(clientId);
      setSelectedClient(details);
    } catch (err: any) {
      alert(`Could not fetch device details: ${err.message}`);
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#1f293d]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h2 className="text-2xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Smartphone className="w-6 h-6 text-purple-400" />
              CLIENT FLEET MONITORING
            </h2>
            <Badge variant="purple" size="sm">EDGE ENDPOINTS</Badge>
          </div>
          <p className="text-sm text-slate-400">
            Real-time telemetry and cryptographic acknowledgement tracking across PC browser extensions and Android devices.
          </p>
        </div>

        <button
          onClick={fetchData}
          className="flex items-center gap-2 px-3.5 py-2 bg-[#111827] hover:bg-slate-800 text-slate-200 border border-[#1f293d] rounded-lg text-xs font-mono font-medium transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5 text-purple-400" />
          Refresh Fleet
        </button>
      </div>

      {/* Fleet KPIs */}
      {metrics && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          <StatCard
            title="Total Endpoints"
            value={metrics.total_registered}
            subtitle="Registered and heartbeat active"
            icon={Smartphone}
            variant="purple"
          />
          <StatCard
            title="Active in 24h"
            value={metrics.active_last_24h}
            subtitle="Recent heartbeat check-in"
            icon={Clock}
            variant="emerald"
          />
          <StatCard
            title="Browser Extensions"
            value={metrics.by_type?.browser_extension || 0}
            subtitle="Chrome & Edge Manifest V3"
            icon={Globe}
            variant="blue"
          />
          <StatCard
            title="Android Devices"
            value={metrics.by_type?.android_app || 0}
            subtitle="Mobile Background Engine"
            icon={Smartphone}
            variant="slate"
          />
        </div>
      )}

      {/* Filters Bar */}
      <div className="p-4 bg-[#111827] border border-[#1f293d] rounded-xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <SlidersHorizontal className="w-4 h-4 text-slate-400" />
          <span className="text-xs font-mono text-slate-400 uppercase">Filters:</span>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-purple-500"
          >
            <option value="">All Client Types</option>
            <option value="browser_extension">Browser Extension</option>
            <option value="android_app">Android Mobile App</option>
          </select>

          <select
            value={filterChannel}
            onChange={(e) => setFilterChannel(e.target.value)}
            className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-purple-500"
          >
            <option value="">All Channels</option>
            <option value="stable">Stable</option>
            <option value="canary">Canary</option>
            <option value="emergency">Emergency</option>
          </select>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-white font-bold">{clients.length}</span> registered devices
        </div>
      </div>

      {isLoading ? (
        <LoadingSpinner label="Querying connected edge devices..." />
      ) : error ? (
        <ErrorBanner message={error} onRetry={fetchData} />
      ) : clients.length === 0 ? (
        <EmptyState
          icon={Smartphone}
          title="No Devices Registered"
          description="No client endpoints have registered with the backend yet. Launch the browser extension or Android application to register edge devices."
        />
      ) : (
        <div className="overflow-x-auto bg-[#111827] border border-[#1f293d] rounded-2xl shadow-xl">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3.5 px-4">CLIENT ID</th>
                <th className="py-3.5 px-4">TYPE</th>
                <th className="py-3.5 px-4">PLATFORM</th>
                <th className="py-3.5 px-4">ENGINE VER</th>
                <th className="py-3.5 px-4">POLICY VER</th>
                <th className="py-3.5 px-4">COHORT</th>
                <th className="py-3.5 px-4">LAST SEEN</th>
                <th className="py-3.5 px-4">STATUS</th>
                <th className="py-3.5 px-4 text-right">DETAILS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {clients.map((c) => (
                <tr
                  key={c.client_id}
                  onClick={() => handleInspectClient(c.client_id)}
                  className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                >
                  <td className="py-3.5 px-4 font-bold text-slate-200">
                    {c.client_id.slice(0, 16)}...
                  </td>
                  <td className="py-3.5 px-4 text-purple-400">
                    {c.client_type === "browser_extension" ? "Extension" : "Android App"}
                  </td>
                  <td className="py-3.5 px-4 text-slate-400">{c.platform}</td>
                  <td className="py-3.5 px-4 text-slate-300">v{c.engine_version}</td>
                  <td className="py-3.5 px-4 font-bold text-emerald-400">
                    v{c.current_policy_version}
                  </td>
                  <td className="py-3.5 px-4 text-cyan-400 font-bold">Bucket #{c.cohort_bucket}</td>
                  <td className="py-3.5 px-4 text-slate-400">
                    {new Date(c.last_seen_at).toLocaleTimeString()}
                  </td>
                  <td className="py-3.5 px-4">
                    <Badge
                      variant={
                        c.latest_status === "nominal" || c.latest_status === "updated"
                          ? "success"
                          : c.latest_status === "rolled_back"
                          ? "warning"
                          : "danger"
                      }
                      size="sm"
                    >
                      {c.latest_status.toUpperCase()}
                    </Badge>
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleInspectClient(c.client_id);
                      }}
                      className="text-purple-400 hover:text-purple-300"
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

      {/* Device Details Modal */}
      {selectedClient && (
        <Modal
          isOpen={!!selectedClient}
          onClose={() => setSelectedClient(null)}
          title={`Device: ${selectedClient.client_id.slice(0, 18)}...`}
          description={`Platform: ${selectedClient.platform} • Type: ${selectedClient.client_type}`}
          maxWidth="lg"
        >
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                <span className="text-slate-500 block mb-0.5">CURRENT POLICY</span>
                <span className="text-emerald-400 font-bold text-sm">
                  v{selectedClient.current_policy_version}
                </span>
              </div>
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                <span className="text-slate-500 block mb-0.5">ENGINE VERSION</span>
                <span className="text-slate-200 font-bold text-sm">
                  v{selectedClient.engine_version}
                </span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-mono font-semibold text-slate-300 mb-2 uppercase">
                Acknowledgement History ({selectedClient.acknowledgements?.length || 0})
              </h4>
              <div className="space-y-2 max-h-56 overflow-y-auto">
                {selectedClient.acknowledgements?.length === 0 ? (
                  <p className="text-xs font-mono text-slate-500 py-4 text-center">
                    No update acknowledgement reports received yet.
                  </p>
                ) : (
                  selectedClient.acknowledgements?.map((ack: any) => (
                    <div
                      key={ack.id}
                      className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between text-xs font-mono"
                    >
                      <div>
                        <span className="font-bold text-white">Policy v{ack.policy_version}</span>
                        {ack.error_message && (
                          <p className="text-rose-400 text-[11px] mt-0.5">{ack.error_message}</p>
                        )}
                      </div>
                      <Badge
                        variant={ack.status === "applied" ? "success" : "danger"}
                        size="sm"
                      >
                        {ack.status.toUpperCase()}
                      </Badge>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="flex justify-end pt-4 border-t border-slate-800">
              <button
                onClick={() => setSelectedClient(null)}
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
