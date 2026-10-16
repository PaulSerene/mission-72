# Mission 72 — Suspicious Login & Activity Detector

> A cybersecurity hackathon application providing real-time detection of
> suspicious authentication events and anomalous user behaviour.

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Start the development server
npm run dev
```

Open **http://localhost:5173** in your browser.

---

## Available Scripts

| Command | Description |
|---|---|
| `npm run dev` | Start dev server with HMR at `http://localhost:5173` |
| `npm run build` | TypeScript type-check + production bundle (`dist/`) |
| `npm run preview` | Serve the production bundle locally |
| `npm test` | Run all unit tests (single-pass) |
| `npm run test:watch` | Run tests in watch mode |
| `npm run test:coverage` | Run tests and generate a coverage report |
| `npm run lint` | Lint `src/` with oxlint |
| `npm run typecheck` | Type-check only (no emit) |

---

## Project Structure

```
missionathon/
├── index.html               # App HTML entry point
├── vite.config.ts           # Vite (build/dev) configuration
├── vitest.config.ts         # Vitest (test) configuration — separated from Vite
├── tsconfig.app.json        # TypeScript config for app source
├── tsconfig.node.json       # TypeScript config for Node tooling
│
└── src/
    ├── main.tsx             # React mount point
    ├── App.tsx              # App root — routes to pages
    ├── index.css            # Global design system (tokens, reset, utilities)
    ├── App.css              # Top-level layout styles
    │
    ├── types/
    │   └── index.ts         # Core domain types (LogEntry, Alert, Severity…)
    │
    ├── engine/
    │   ├── DetectionEngine.ts       # Detection engine class
    │   ├── DetectionEngine.test.ts  # Unit tests (16 tests)
    │   └── index.ts                 # Barrel export
    │
    ├── data/
    │   └── index.ts         # Data layer placeholder (parsers, sources)
    │
    ├── components/
    │   ├── TopNav/          # Navigation bar with clock and engine status
    │   ├── StatCard/        # Dashboard metric card
    │   └── SeverityBadge/   # Colour-coded severity label
    │
    ├── pages/
    │   └── DashboardPage/   # Main SOC dashboard shell
    │
    └── test/
        └── setup.ts         # Vitest global setup
```

---

## Technology Stack

| Layer | Choice | Reason |
|---|---|---|
| UI framework | React 19 + TypeScript | Component model; strong typing for complex domain logic |
| Build tool | Vite 8 | Sub-second dev start; native ESM; zero config |
| Testing | Vitest 3 + jsdom | Same transform pipeline as Vite; fast with globals API |
| Styling | Vanilla CSS (CSS Modules + design tokens) | No runtime overhead; full control; premium dark theme |
| Linting | oxlint | Written in Rust; extremely fast |

This is a **fully offline, client-side application** — no backend, no database, no paid APIs.

---

## Design System

The application uses a deep navy / electric cyan SOC theme defined entirely in
[`src/index.css`](src/index.css) as CSS custom properties:

- **Typography**: Inter (UI) + JetBrains Mono (data/code)
- **Severity colours**: Critical → red · High → orange · Medium · amber · Low → green · Info → blue
- **Animations**: `fadeInUp`, `pulse-ring`, `blink`

---

## Architecture Notes

### Detection Engine (`src/engine/`)

The engine is **framework-agnostic** — no React imports. It:

1. Accepts a list of `RuleEvaluator` registrations.
2. Ingests batches of `LogEntry` objects.
3. Evaluates each registered rule against the batch + rolling history window.
4. Returns `Alert[]` produced by the current batch.

Rules are pure functions (`(entries, history) => Alert[]`), making them trivially unit-testable.

### Domain Types (`src/types/`)

All types flow from a single source of truth. Key types:

- `LogEntry` — a single structured event (auth, network, file, process…)
- `Alert` — a rule match tied to one or more source events
- `DetectionRule` — metadata for a rule (ID, name, severity, MITRE tactic)
- `DashboardStats` — aggregate counters for the dashboard

---

## Planned Milestones

1. **Milestone 2 — Log Ingestion**: Parse JSON/CSV/syslog files; `data/` layer
2. **Milestone 3 — Detection Rules**: Brute-force, impossible travel, off-hours login, privilege escalation
3. **Milestone 4 — Live Dashboard**: Alert feed table, severity charts, IP map
4. **Milestone 5 — Baseline Learning**: Per-user normal behaviour profiling
5. **Milestone 6 — Export**: Alert export to JSON/CSV

---

## Environment

- Node.js ≥ 20
- npm ≥ 10
- No environment variables required — runs entirely in the browser

---

## Mission 02 — Context-Aware Alert Detection

Complete documentation, configuration schemas, scenario evaluation matrices, and operational limitations for Mission 02 are documented in:
👉 [docs/MISSION_02_CONTEXT_AWARE_DETECTION.md](docs/MISSION_02_CONTEXT_AWARE_DETECTION.md)

### Key Capabilities:
- **Authorized Helpdesk Scoping**: Exempts multi-host traversals during declared maintenance windows for authorized accounts.
- **Corporate VPN Integration**: CIDR bit-arithmetic matching suppresses false-positive new-IP alerts for travelling employees.
- **Contextual Risk De-escalation**: Bounded heuristic scoring [0–100] with score multipliers and transparent incident explanations.
- **Audit Logging**: Suppressed signals are recorded with operational rationale and preserved evidence.
