# CyberDuel AI — Security Command Center

## Status: Fully Implemented (Phase 9 Complete)

The **CyberDuel AI Command Center** (`apps/dashboard`) is the central operational interface and research observability console for security analysts, researchers, reviewers, and release authorities. It connects directly to the CyberDuel AI backend API (`apps/api`) to visualize defensive intelligence, inspect adversarial scenario experiments, review candidate defenses, audit regression reports, manage cryptographic policy releases, and monitor protected client devices.

---

## 1. Architectural Architecture & Key Capabilities

- **Strict Non-Fabrication:** All displayed metrics (experiment counts, candidate queues, evaluation reports, release rollouts, connected client counts, audit logs) reflect real SQLite/PostgreSQL database records. No fabricated attack maps, fake counters, or synthetic tickers.
- **Role-Based Access Control (RBAC):** Privileged actions are cryptographically and server-side authorized.
  - `viewer`: Read-only access across telemetry, research, releases, and fleet status.
  - `research_operator`: Authority to launch Red AI scenario suites and research experiments.
  - `defense_reviewer`: Authority to review failure clusters and approve/reject Blue AI defense proposals.
  - `release_operator`: Authority to verify release eligibility, stage rollouts, advance percentages, pause/resume, and execute rollbacks.
  - `admin`: Complete administrative, research, and release authority.
- **Zero Secrets in Frontend Assets:** Private signing keys, database passwords, and master secrets remain strictly in backend enclaves.
- **Privacy-Preserving Telemetry Display:** Client URLs with sensitive authentication tokens, passwords, session IDs, and API keys are automatically redacted in the UI (`[REDACTED]`).
- **Cryptographic Release Governance:** Operators can inspect Ed25519 digital signatures, SHA-256 artifact digests, deterministic cohort hash buckets, and execute signed rollbacks with mandatory justification.

---

## 2. Views & Modules

| Route | Page | Description |
| :--- | :--- | :--- |
| `/` | `OverviewPage` | Consolidated operational KPIs, active policy version, rollout progression bar, client fleet summary, recent audit feed. |
| `/lab` | `RedAiPage` | Adversarial experiment list, failure findings drill-down, and interactive synthetic scenario catalog with redaction. |
| `/blue` | `BlueAiPage` | Failure groups clustering, proposed candidate defenses, specification diffs, and proposal creation. |
| `/evaluations` | `EvaluationsPage` | Independent benchmark evaluation audits, precision/recall/F1 metrics, regression prevention gates, and autonomous improvement loop history. |
| `/releases` | `ReleasesPage` | Cryptographically signed Ed25519 policy releases, staged rollout controls (10% → 25% → 50% → 100%), pause/resume, and signed rollbacks. |
| `/clients` | `ClientsPage` | Connected PC browser extensions (Manifest V3) and Android mobile apps, fleet version distribution, and client acknowledgement reports. |
| `/intelligence` | `IntelligencePage` | Indicators of Compromise (IOCs), live threat feed, and privacy-sanitized URL observations. |
| `/audit` | `AuditPage` | Searchable, paginated, immutable audit trail of all operational logins, research executions, and release decisions. |
| `/system` | `SystemHealthPage` | Distributed runtime health, probe readiness, database connection state, and worker diagnostics. |
| `/login` | `LoginPage` | Operator session authentication with one-click persona switching (Admin, Researcher, Reviewer, Releaser, Analyst). |

---

## 3. Technology Stack

- **Framework:** React 18 + Vite 6 + TypeScript (Strict)
- **Styling & Design System:** Tailwind CSS + custom cyber security design tokens
- **Routing:** React Router v6
- **Icons:** Lucide React
- **Testing:** Vitest + React Testing Library + JSDOM

---

## 4. Local Execution & Testing

### Running the Dashboard Locally

```bash
# In apps/dashboard
npm install
npm run dev
# Dashboard launches on http://localhost:5173 and proxies /api to http://127.0.0.1:8000
```

### Running Automated Frontend Tests

```bash
cd apps/dashboard
npm test         # Runs 7 Vitest unit & component tests
npm run build    # Validates TypeScript types and generates production bundle
```

### End-to-End Integration Demo

```bash
# From workspace root
.venv\Scripts\python scripts/demo_command_center.py
```
