import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { redactSensitiveUrl } from "../api/client";
import { Badge } from "../components/common/Badge";
import { StatCard } from "../components/common/StatCard";
import { PrivacyUrl } from "../components/common/PrivacyUrl";
import { Activity } from "lucide-react";
import { App } from "../App";

describe("Privacy & Redaction Utilities", () => {
  it("redacts sensitive authentication tokens and passwords from URLs", () => {
    const raw = "https://phish.target.com/login?token=secret_12345&user=john";
    const redacted = redactSensitiveUrl(raw);
    expect(redacted).not.toContain("secret_12345");
    expect(redacted).toContain("[REDACTED]");
    expect(redacted).toContain("user=john");
  });

  it("redacts API keys and secret query parameters", () => {
    const raw = "https://cdn.malicious.net/payload?apikey=master_key_xyz&format=exe";
    const redacted = redactSensitiveUrl(raw);
    expect(redacted).not.toContain("master_key_xyz");
    expect(redacted).toContain("[REDACTED]");
  });

  it("leaves clean URLs unchanged", () => {
    const clean = "https://example.com/about/us?page=1&sort=asc";
    const result = redactSensitiveUrl(clean);
    expect(result).toBe(clean);
  });
});

describe("UI Components", () => {
  it("renders Badge component with correct variant style", () => {
    render(<Badge variant="success">ACTIVE</Badge>);
    expect(screen.getByText("ACTIVE")).toBeInTheDocument();
  });

  it("renders StatCard with title, value, and subtitle", () => {
    render(
      <StatCard
        title="Active Rollouts"
        value={42}
        subtitle="100% stable fleet"
        icon={Activity}
        variant="emerald"
      />
    );
    expect(screen.getByText("Active Rollouts")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("100% stable fleet")).toBeInTheDocument();
  });

  it("renders PrivacyUrl component with copy button and redacted content", () => {
    render(
      <PrivacyUrl url="https://malicious.org/auth?password=super_secret_password" />
    );
    expect(screen.getByText(/\[REDACTED\]/)).toBeInTheDocument();
  });
});

describe("Dashboard App Shell", () => {
  beforeEach(() => {
    // Mock global fetch for API calls in tests
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes("/auth/operators")) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => [
            {
              username: "admin",
              display_name: "Lead System Administrator",
              role: "admin",
              description: "Full system authority",
            },
          ],
        });
      }
      if (url.includes("/auth/me")) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            username: "admin",
            display_name: "Lead System Administrator",
            role: "admin",
            permissions: ["admin", "read", "releases:manage"],
          }),
        });
      }
      if (url.includes("/auth/login")) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            token: "mock.token",
            user: {
              username: "admin",
              display_name: "Lead System Administrator",
              role: "admin",
              permissions: ["admin", "read"],
            },
          }),
        });
      }
      if (url.includes("/dashboard/overview")) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            health: {
              status: "healthy",
              version: "0.1.0",
              environment: "test",
              database_connected: true,
              active_workers: 2,
              timestamp: new Date().toISOString(),
            },
            research: {
              total_experiments: 10,
              completed_experiments: 8,
              active_experiments: 2,
              total_discrepancies: 5,
              failure_finding_count: 5,
            },
            defense: {
              total_candidates: 4,
              approved_candidates: 3,
              pending_review_candidates: 1,
              rejected_candidates: 0,
              total_hypotheses: 4,
            },
            evaluations: {
              total_evaluations: 6,
              passed_evaluations: 5,
              failed_evaluations: 1,
              regressions_prevented: 1,
            },
            releases: {
              total_releases: 2,
              active_production_version: "1.0.0",
              staged_version: "1.1.0",
              current_rollout_percentage: 25,
              rollout_state: "canary",
              active_signing_keys: 2,
            },
            clients: {
              total_devices: 15,
              browser_extensions: 10,
              mobile_devices: 5,
              active_last_24h: 12,
              fleet_adoption_rate: 80.0,
            },
            recent_events: [],
          }),
        });
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({}),
      });
    });
  });

  it("renders Command Center navigation shell successfully", async () => {
    render(<App />);
    expect(screen.getByText(/CYBERDUEL/i)).toBeInTheDocument();
    expect(screen.getAllByText(/COMMAND CENTER/i).length).toBeGreaterThan(0);
    expect(screen.getByText("Red AI Lab")).toBeInTheDocument();
    expect(screen.getByText("Blue AI Defense")).toBeInTheDocument();
    expect(screen.getByText("Security Releases")).toBeInTheDocument();
    expect(screen.getByText("Client Fleet")).toBeInTheDocument();
  });
});
