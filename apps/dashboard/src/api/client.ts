import {
  AuditQueryResponse,
  CandidateDefense,
  ClientDevice,
  ClientMetrics,
  DashboardOverviewResponse,
  EvaluationReport,
  FailureGroupSummary,
  ImprovementCycle,
  LabExperiment,
  OperatorOption,
  ReleaseSummary,
  ScenarioContract,
  ScenarioExecutionResult,
  SystemHealthInfo,
  ThreatObservationItem,
  UserProfile,
} from "../types";

const API_BASE = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL.replace(/\/$/, "")}/api/v1`
  : "/api/v1";

/**
 * Utility to redact sensitive parameters and query arguments from URLs.
 * Ensures user tokens, auth codes, and secrets are never displayed in plaintext.
 */
export function redactSensitiveUrl(rawUrl: string): string {
  if (!rawUrl) return "";
  try {
    const parsed = new URL(rawUrl);
    const sensitiveKeys = new Set([
      "token",
      "auth",
      "password",
      "pass",
      "secret",
      "key",
      "apikey",
      "session",
      "sid",
      "code",
      "jwt",
      "bearer",
      "credential",
    ]);

    const params = new URLSearchParams(parsed.search);
    let changed = false;
    for (const key of Array.from(params.keys())) {
      if (sensitiveKeys.has(key.toLowerCase()) || key.toLowerCase().includes("token") || key.toLowerCase().includes("secret")) {
        params.set(key, "[REDACTED]");
        changed = true;
      }
    }

    if (changed) {
      const cleanSearch = params.toString().replace(/%5BREDACTED%5D/g, "[REDACTED]");
      return `${parsed.origin}${parsed.pathname}?${cleanSearch}${parsed.hash}`;
    }
    return parsed.toString();
  } catch {
    // If not a valid absolute URL, sanitize query parameters using regex
    return rawUrl.replace(/([?&](?:token|auth|pass|password|key|secret|code)=)[^&]*/gi, "$1[REDACTED]");
  }
}

class ApiError extends Error {
  status: number;
  data: any;

  constructor(message: string, status: number, data?: any) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem("cyberduel_auth_token");
  const headers = new Headers(options.headers || {});
  headers.set("Content-Type", "application/json");

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const url = `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorData: any = {};
    try {
      errorData = await response.json();
    } catch {
      errorData = { detail: response.statusText };
    }
    const message = errorData.detail || `Request failed with status ${response.status}`;
    throw new ApiError(message, response.status, errorData);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

// ---------------- API SERVICES ----------------

export const authApi = {
  login: async (username: string, password: string = "") => {
    return request<{ token: string; user: UserProfile }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
  },

  getMe: async () => {
    return request<UserProfile>("/auth/me");
  },

  logout: async () => {
    return request<{ status: string }>("/auth/logout", {
      method: "POST",
    });
  },

  getOperators: async () => {
    return request<OperatorOption[]>("/auth/operators");
  },
};

export const dashboardApi = {
  getOverview: async () => {
    return request<DashboardOverviewResponse>("/dashboard/overview");
  },
};

export const labApi = {
  getExperiments: async (params?: { status?: string; limit?: number; offset?: number }) => {
    const q = new URLSearchParams();
    if (params?.status) q.set("status", params.status);
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    return request<LabExperiment[]>(`/lab/experiments?${q.toString()}`);
  },

  getExperiment: async (id: string) => {
    return request<LabExperiment>(`/lab/experiments/${id}`);
  },

  getExperimentResults: async (id: string, limit: number = 100) => {
    return request<ScenarioExecutionResult[]>(`/lab/experiments/${id}/results?limit=${limit}`);
  },

  runExperiment: async (config: {
    experiment_name: string;
    goal: string;
    scenario_count: number;
    families?: string[];
  }) => {
    return request<LabExperiment>("/lab/experiments", {
      method: "POST",
      body: JSON.stringify(config),
    });
  },

  cancelExperiment: async (id: string) => {
    return request<{ status: string }>(`/lab/experiments/${id}/cancel`, {
      method: "POST",
    });
  },

  getScenarios: async (family?: string, limit: number = 50) => {
    const q = new URLSearchParams({ limit: String(limit) });
    if (family) q.set("family", family);
    return request<ScenarioContract[]>(`/lab/scenarios?${q.toString()}`);
  },
};

export const blueApi = {
  getStatus: async () => {
    return request<any>("/blue/status");
  },

  getFailureGroups: async () => {
    return request<FailureGroupSummary[]>("/blue/failure-groups");
  },

  getHistory: async () => {
    return request<CandidateDefense[]>("/blue/history");
  },

  getCandidate: async (id: string) => {
    return request<CandidateDefense>(`/blue/candidates/${id}`);
  },

  getCandidateComparison: async (id: string) => {
    return request<any>(`/blue/candidates/${id}/comparison`);
  },

  launchResearch: async (experimentId: string, hypothesis?: string) => {
    return request<any>("/blue/research", {
      method: "POST",
      body: JSON.stringify({ experiment_id: experimentId, hypothesis }),
    });
  },

  createCandidate: async (data: {
    candidate_version: string;
    defense_type: string;
    target_findings: string[];
    changes_summary: string;
  }) => {
    return request<CandidateDefense>("/blue/candidates", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },
};

export const evaluationsApi = {
  getEvaluations: async (limit: number = 20) => {
    return request<any[]>(`/evaluations?limit=${limit}`);
  },

  getEvaluationReport: async (id: string) => {
    return request<EvaluationReport>(`/evaluations/${id}/report`);
  },

  getBenchmarks: async () => {
    return request<any[]>("/benchmarks");
  },
};

export const improvementApi = {
  getCycles: async (limit: number = 10) => {
    return request<ImprovementCycle[]>(`/improvement/cycles?limit=${limit}`);
  },

  getControllerStatus: async () => {
    return request<any>("/improvement/status");
  },

  triggerCycle: async (triggerReason: string) => {
    return request<ImprovementCycle>("/improvement/cycles", {
      method: "POST",
      body: JSON.stringify({ trigger_reason: triggerReason }),
    });
  },
};

export const releasesApi = {
  getReleases: async (params?: { channel?: string; status?: string; limit?: number }) => {
    const q = new URLSearchParams();
    if (params?.channel) q.set("channel", params.channel);
    if (params?.status) q.set("status", params.status);
    if (params?.limit) q.set("limit", String(params.limit));
    return request<ReleaseSummary[]>(`/releases?${q.toString()}`);
  },

  getRelease: async (id: string) => {
    return request<any>(`/releases/${id}`);
  },

  checkEligibility: async (candidateId: string) => {
    return request<any>("/releases/eligibility", {
      method: "POST",
      body: JSON.stringify({ candidate_id: candidateId }),
    });
  },

  authorizeRelease: async (data: {
    candidate_id: string;
    policy_version: string;
    target_channel: string;
    initial_rollout_percentage: number;
    key_id: string;
  }) => {
    return request<any>("/releases/authorize", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  advanceRollout: async (releaseId: string, targetPercentage: number, reason?: string) => {
    return request<any>(`/releases/${releaseId}/advance`, {
      method: "POST",
      body: JSON.stringify({ target_percentage: targetPercentage, reason }),
    });
  },

  pauseRollout: async (releaseId: string, reason: string) => {
    return request<any>(`/releases/${releaseId}/pause`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  },

  resumeRollout: async (releaseId: string) => {
    return request<any>(`/releases/${releaseId}/resume`, {
      method: "POST",
    });
  },

  revokeRelease: async (releaseId: string, revocationReason: string) => {
    return request<any>(`/releases/${releaseId}/revoke`, {
      method: "POST",
      body: JSON.stringify({ reason: revocationReason }),
    });
  },

  rollbackRelease: async (data: {
    active_release_id: string;
    target_previous_release_id: string;
    rationale: string;
    key_id: string;
  }) => {
    return request<any>("/releases/rollback", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },
};

export const clientsApi = {
  getClients: async (params?: { client_type?: string; channel?: string; limit?: number }) => {
    const q = new URLSearchParams();
    if (params?.client_type) q.set("client_type", params.client_type);
    if (params?.channel) q.set("channel", params.channel);
    if (params?.limit) q.set("limit", String(params.limit));
    return request<ClientDevice[]>(`/clients?${q.toString()}`);
  },

  getClientMetrics: async () => {
    return request<ClientMetrics>("/clients/metrics");
  },

  getClient: async (id: string) => {
    return request<any>(`/clients/${id}`);
  },
};

export const auditApi = {
  getEvents: async (params?: {
    actor?: string;
    action?: string;
    target_type?: string;
    outcome?: string;
    limit?: number;
    offset?: number;
  }) => {
    const q = new URLSearchParams();
    if (params?.actor) q.set("actor", params.actor);
    if (params?.action) q.set("action", params.action);
    if (params?.target_type) q.set("target_type", params.target_type);
    if (params?.outcome) q.set("outcome", params.outcome);
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    return request<AuditQueryResponse>(`/audit/events?${q.toString()}`);
  },
};

export const intelligenceApi = {
  getThreatIndicators: async (limit: number = 50) => {
    return request<any[]>(`/intelligence/indicators?limit=${limit}`);
  },

  getObservations: async (limit: number = 50) => {
    return request<ThreatObservationItem[]>(`/telemetry/observations?limit=${limit}`);
  },
};

export const systemApi = {
  getStatus: async () => {
    return request<SystemHealthInfo>("/system/status");
  },
};
