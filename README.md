# SignalForge

**From raw logs to clear action.**

SignalForge is a context-aware security log analysis and incident investigation platform. It ingests authentication CSV logs, builds behavioral baselines, evaluates six detection rules, correlates incidents, and surfaces actionable investigations — all processed locally in the browser.

---

## What SignalForge Does

SignalForge is a client-side SOC analysis prototype. It does not connect to any external services, backend APIs, or real-time data feeds. All processing runs in your browser.

**Core capabilities:**

- **CSV ingestion** — parses authentication logs with flexible field aliases (`destination_host`, `location`, etc.) and normalises timestamps across time zones.
- **Behavioral baselines** — builds per-user profiles of normal working hours, known source IPs, and typical destination hosts from a configurable training window.
- **Six detection rules** — evaluates each user against brute force, password spray, impossible travel, unusual-hours access, unfamiliar host access, and concurrent session rules.
- **Incident correlation** — groups rule matches by user and time window into correlated incidents with aggregated risk scores.
- **Context-aware suppression** — reduces or suppresses risk scores for flagged helpdesk accounts operating during declared maintenance windows, employees connecting through approved VPN ranges, and roles with elevated access grants.
- **Audit logging** — records every context exception with the suppressing policy, reason, and preserved evidence.
- **Investigation workspace** — displays evidence events, MITRE ATT&CK tactic tags, and recommended triage steps for each incident.
- **Acknowledgement workflow** — analysts can acknowledge incidents and reopen them.
- **Exports** — CSV and self-contained HTML exports of the full incident list.

---

## What SignalForge Is Not

- Not a production SIEM.
- Not connected to any log source, SIEM backend, or authentication provider.
- Does not perform real-time monitoring.
- Does not persist data between sessions (except the selected UI theme).
- Does not guarantee detection of any real attack.

---

## Quick Start

```bash
# Clone and install
npm install

# Start the development server
npm run dev

# Run the full test suite
npm test -- --run

# Production build
npm run build
```

Open `http://localhost:5173` in your browser.

---

## Loading Data

### Synthetic demo

Click **Load Synthetic Demo Dataset** on the import screen. This loads 280 pre-generated events across 10 detection scenarios without prompting for a file.

### Custom CSV

Click the dropzone (or the browse button) to select your own authentication log CSV. The expected column names are:

| Column | Aliases accepted |
|--------|-----------------|
| `timestamp` | — |
| `user` | `username`, `user_id` |
| `source_ip` | `src_ip`, `ip`, `source` |
| `destination_host` | `dest_host`, `host`, `hostname`, `target`, `resource` |
| `status` | `result`, `outcome` |
| `service` | `application`, `app` |
| `failure_reason` | `reason`, `error` |
| `location` | `geo`, `city`, `country` |

Select the source timezone, optionally upload an asset inventory CSV and an IP-to-location CSV, then click **Run Analysis**.

---

## Architecture

```
src/
├── components/           # All UI components (CSS Modules)
│   ├── ConfigPanel/      # Detection threshold and policy configuration
│   ├── ContextExceptions/# Context-exception audit log
│   ├── ErrorBoundary/    # Top-level error recovery
│   ├── ExportBar/        # CSV + HTML export controls
│   ├── IncidentDetail/   # Investigation modal
│   ├── IncidentFeed/     # Incident table and filter bar
│   ├── IngestionSummary/ # Data quality and parse-result summary
│   ├── LoadDataPanel/    # CSV upload and demo-load controls
│   ├── StatCard/         # KPI metric cards
│   ├── TopNav/           # Application shell and theme toggle
│   └── Visualizations/  # Severity distribution and activity charts
│
├── engine/               # Detection engine (pure TypeScript, no React)
│   ├── assets.ts         # Asset/IP-location CSV parsing and CIDR matching
│   ├── baseline.ts       # Behavioral baseline builder
│   ├── DetectionEngine.ts# Core detection utilities and risk scoring
│   ├── incidents.ts      # Incident correlator
│   ├── ingest.ts         # CSV parser and timestamp normalizer
│   ├── pipeline.ts       # runDetectionPipeline orchestrator
│   └── rules.ts          # Six detection rules
│
├── hooks/
│   ├── usePipeline.ts    # Async pipeline execution hook
│   └── useTheme.ts       # Dark/light theme with localStorage persistence
│
├── pages/
│   └── DashboardPage/    # Main application page and tab layout
│
├── state/
│   └── AppState.tsx      # React Context + useReducer application state
│
├── test/                 # Integration and regression tests
├── types/                # Shared TypeScript type definitions
├── utils/                # Export utilities
└── data/
    └── generate.ts       # Synthetic dataset generator (seeded PRNG)
```

---

## Design System

SignalForge uses a CSS custom properties design system with genuine dark and light themes.

### Themes

- **Dark** (default): Deep navy base (`#0b0f1a`) with layered charcoal surfaces.
- **Light**: Soft cool-gray base (`#f2f4f8`) with white surfaces.

The active theme is toggled via the sun/moon button in the top navigation bar. The selection persists in `localStorage` under the key `sf-theme`. On first visit, the system color scheme preference (`prefers-color-scheme`) is respected.

### Color tokens

All colors are defined as CSS custom properties in `src/index.css` under `[data-theme="dark"]` and `[data-theme="light"]` selectors. Severity-semantic colors (`--color-critical`, `--color-high`, `--color-medium`, `--color-low`, `--color-info`) are consistent across both themes.

### Components

All components use CSS Modules (`*.module.css`) and reference design tokens via `var(--color-*)`. No component has hardcoded dark-mode colors.

---

## Testing

```bash
npm test -- --run          # Run all tests once
npm run test:watch         # Watch mode
npm run test:coverage      # Coverage report
```

**Test suite: 154 tests across 13 files.**

| Suite | Tests |
|-------|-------|
| Detection engine unit tests | 23 |
| Baseline builder | 7 |
| Ingestion / timestamp normalisation | 17 |
| Asset and CIDR matching | 13 |
| Incident correlation | 10 |
| Configuration validation | 15 |
| Pipeline + synthetic generator | 17 |
| Export utilities | 3 |
| Application state reducer | 13 |
| DetectionEngine utilities | 16 |
| Integration tests | 8 |
| File-picker regression | 7 |
| Custom CSV regression | 5 |

---

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start Vite development server |
| `npm run build` | TypeScript check + production build |
| `npm run preview` | Serve the production build locally |
| `npm test -- --run` | Run the full test suite once |
| `npm run test:watch` | Vitest watch mode |
| `npm run test:coverage` | Coverage report |
| `npm run lint` | Run oxlint on `src/` |
| `npm run typecheck` | TypeScript type-check without emit |
| `npm run generate-data` | Regenerate synthetic fixture data |

---

## Technology

| Layer | Technology |
|-------|-----------|
| UI | React 19 + TypeScript |
| Build | Vite 8 |
| Styling | CSS Modules + CSS custom properties |
| CSV parsing | PapaParse |
| Tests | Vitest 5 + jsdom + React Testing Library |
| Linting | oxlint |
