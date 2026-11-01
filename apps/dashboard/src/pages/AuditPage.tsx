import React, { useEffect, useState } from "react";
import {
  FileText,
  Search,
  RefreshCw,
  Eye,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { auditApi } from "../api/client";
import { AuditEventItem } from "../types";
import { Badge } from "../components/common/Badge";
import { Modal } from "../components/common/Modal";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { ErrorBanner } from "../components/common/ErrorBanner";
import { EmptyState } from "../components/common/EmptyState";

export const AuditPage: React.FC = () => {
  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const limit = 25;

  const [filterActor, setFilterActor] = useState("");
  const [filterAction, setFilterAction] = useState("");
  const [filterOutcome, setFilterOutcome] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<AuditEventItem | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchEvents = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await auditApi.getEvents({
        actor: filterActor || undefined,
        action: filterAction || undefined,
        outcome: filterOutcome || undefined,
        limit,
        offset: page * limit,
      });
      setEvents(res.events);
      setTotal(res.total);
    } catch (err: any) {
      setError(err.message || "Failed to load audit logs");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [page, filterOutcome]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(0);
    fetchEvents();
  };

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#27181c]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h2 className="text-2xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <FileText className="w-6 h-6 text-amber-400" />
              SECURITY AUDIT TRAIL
            </h2>
            <Badge variant="warning" size="sm">APPEND-ONLY IMMUTABLE</Badge>
          </div>
          <p className="text-sm text-slate-400">
            Cryptographically accounted record of all administrative logins, research experiments, candidate reviews, release authorizations, and emergency rollbacks.
          </p>
        </div>

        <button
          onClick={fetchEvents}
          className="flex items-center gap-2 px-3.5 py-2 bg-[#131316] hover:bg-slate-800 text-slate-200 border border-[#27181c] rounded-lg text-xs font-mono font-medium transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5 text-amber-400" />
          Refresh Log
        </button>
      </div>

      {/* Filter and Search Bar */}
      <form
        onSubmit={handleSearch}
        className="p-4 bg-[#131316] border border-[#27181c] rounded-xl flex flex-wrap items-center justify-between gap-4"
      >
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="text"
            placeholder="Filter by Actor (e.g. admin)..."
            value={filterActor}
            onChange={(e) => setFilterActor(e.target.value)}
            className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500 w-48"
          />
          <input
            type="text"
            placeholder="Filter by Action (e.g. release)..."
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500 w-48"
          />
          <select
            value={filterOutcome}
            onChange={(e) => {
              setFilterOutcome(e.target.value);
              setPage(0);
            }}
            className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500"
          >
            <option value="">All Outcomes</option>
            <option value="success">Success</option>
            <option value="denied">Denied</option>
            <option value="failure">Failure</option>
          </select>

          <button
            type="submit"
            className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono transition-colors flex items-center gap-1.5"
          >
            <Search className="w-3.5 h-3.5" />
            Apply Filters
          </button>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-white font-bold">{events.length}</span> of{" "}
          <span className="text-amber-400 font-bold">{total}</span> immutable events
        </div>
      </form>

      {isLoading ? (
        <LoadingSpinner label="Querying append-only security logs..." />
      ) : error ? (
        <ErrorBanner message={error} onRetry={fetchEvents} />
      ) : events.length === 0 ? (
        <EmptyState
          icon={FileText}
          title="No Audit Records Found"
          description="No audit records match the current filter criteria."
        />
      ) : (
        <div className="space-y-4">
          <div className="overflow-x-auto bg-[#131316] border border-[#27181c] rounded-2xl shadow-xl">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">TIMESTAMP</th>
                  <th className="py-3 px-4">ACTOR</th>
                  <th className="py-3 px-4">ACTION</th>
                  <th className="py-3 px-4">TARGET</th>
                  <th className="py-3 px-4">OUTCOME</th>
                  <th className="py-3 px-4">CLIENT IP</th>
                  <th className="py-3 px-4 text-right">DETAILS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {events.map((evt) => (
                  <tr
                    key={evt.event_id}
                    onClick={() => setSelectedEvent(evt)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 text-slate-400">
                      {new Date(evt.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 font-bold text-slate-200">{evt.actor}</td>
                    <td className="py-3 px-4 text-amber-400 font-semibold">{evt.action}</td>
                    <td className="py-3 px-4 text-slate-300">
                      {evt.target_type}
                      {evt.target_id && `: ${evt.target_id.slice(0, 8)}...`}
                    </td>
                    <td className="py-3 px-4">
                      <Badge
                        variant={
                          evt.outcome === "success"
                            ? "success"
                            : evt.outcome === "denied"
                            ? "danger"
                            : "warning"
                        }
                        size="sm"
                      >
                        {evt.outcome.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="py-3 px-4 text-slate-400">{evt.client_ip || "local"}</td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(evt);
                        }}
                        className="text-amber-400 hover:text-amber-300"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between py-2 text-xs font-mono text-slate-400">
              <div>
                Page {page + 1} of {totalPages}
              </div>
              <div className="flex items-center gap-2">
                <button
                  disabled={page === 0}
                  onClick={() => setPage(page - 1)}
                  className="px-3 py-1.5 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-200 rounded-lg disabled:opacity-40 transition-colors flex items-center gap-1"
                >
                  <ChevronLeft className="w-3.5 h-3.5" /> Previous
                </button>
                <button
                  disabled={page + 1 >= totalPages}
                  onClick={() => setPage(page + 1)}
                  className="px-3 py-1.5 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-200 rounded-lg disabled:opacity-40 transition-colors flex items-center gap-1"
                >
                  Next <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Audit Detail Modal */}
      {selectedEvent && (
        <Modal
          isOpen={!!selectedEvent}
          onClose={() => setSelectedEvent(null)}
          title={`Audit Event: ${selectedEvent.action}`}
          description={`Recorded by actor '${selectedEvent.actor}' at ${new Date(
            selectedEvent.created_at
          ).toLocaleString()}`}
          maxWidth="lg"
        >
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                <span className="text-slate-500 block mb-0.5">EVENT ID</span>
                <span className="text-slate-200 font-bold">{selectedEvent.event_id}</span>
              </div>
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                <span className="text-slate-500 block mb-0.5">OUTCOME</span>
                <span className="text-emerald-400 font-bold uppercase">{selectedEvent.outcome}</span>
              </div>
            </div>

            {selectedEvent.reason && (
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg text-xs font-mono">
                <span className="text-slate-500 block mb-1">REASON / NOTES</span>
                <p className="text-slate-300">{selectedEvent.reason}</p>
              </div>
            )}

            {selectedEvent.metadata && (
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-1 text-xs font-mono">
                <span className="text-slate-400 font-semibold block">STRUCTURED METADATA</span>
                <pre className="text-slate-300 overflow-x-auto p-2 bg-black/40 rounded">
                  {JSON.stringify(selectedEvent.metadata, null, 2)}
                </pre>
              </div>
            )}

            <div className="flex justify-end pt-4 border-t border-slate-800">
              <button
                onClick={() => setSelectedEvent(null)}
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
