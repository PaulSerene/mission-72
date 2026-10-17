<div align="center">

# 🛡️ SignalForge
### Context-Aware Security Log Analysis & Incident Correlation Engine
**Autonomous Client-Side SOC Investigation • Spherical Physics Impossible-Travel • Zero Telemetry Egress**

*Built for Missionathon — Problem Statement 2 (PS-02)*

<br />

[![Missionathon PS-02](https://img.shields.io/badge/Missionathon-PS--02-FF6B6B?style=for-the-badge&logo=target&logoColor=white)](https://github.com/PaulSerene/mission-72)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19.2-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8.3-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)
[![Tests](https://img.shields.io/badge/Tests-264%20Passing-2ECC71?style=for-the-badge&logo=vitest&logoColor=white)](https://vitest.dev/)
[![Zero Telemetry](https://img.shields.io/badge/Privacy-100%25%20Client--Side-9B59B6?style=for-the-badge&logo=shield)](https://github.com/PaulSerene/mission-72)

<br />

[Core Purpose](#-project-purpose--problem-statement) •
[Key Features](#-key-features--detection-engine) •
[MITRE ATT&CK Matrix](#-detection-rules--mitre-attck-matrix) •
[Architecture](#-system-architecture--data-flow) •
[Quick Start](#-quick-start--installation) •
[Official Validation](#-official-dataset-validation-tc01tc11) •
[Team](#-team-information)

---

</div>

<br />

<div align="center">

| ⚡ Sub-Second Pipeline | 🎯 Official Benchmark | 🧪 Complete Test Suite | 🔒 Zero Data Egress |
| :---: | :---: | :---: | :---: |
| **< 400ms** correlation | **100% Precision / Recall** on official scenarios | **264 / 264 Tests Passing** across 20 files | **100% Browser-Native** execution |

</div>

<br />

## 📋 Project Purpose & Problem Statement

Modern Security Operations Centers (SOCs) face acute alert fatigue caused by massive volumes of isolated authentication events. Basic threshold-based alerting often misidentifies benign operational activity—such as scheduled IT maintenance, employees roaming through enterprise VPN gateways, or transient single-sign-on (SSO) outages—generating disruptive false positives.

**SignalForge** resolves this challenge with an **autonomous, browser-native authentication log analysis platform**. It ingests raw authentication CSV logs, constructs statistical behavioral baselines from historical training activity, evaluates multi-stage correlation rules, and contextualizes detections against asset inventories, corporate maintenance windows, and approved VPN networks.

> [!NOTE]
> **Zero Telemetry Egress**: All parsing, normalization, baseline learning, correlation, and visualization execute **100% locally in the browser**. No credentials, tokens, or security logs ever leave the user's workstation.

---

## ⚡ Key Features & Detection Engine

### 🔍 Context-Aware Behavioral Analytics
* **Automated Profile Detection**: Automatically detects whether ingested telemetry matches Variant A (IST `+05:30`), Variant B (UTC `Z`), or Synthetic profiles.
* **Autonomous Baseline Learning**: Learns normal user working hours, familiar source IPs, and typical destination hosts from Days 1–5 baseline telemetry.
* **Contextual Policy Suppression**: Distinguishes genuine attacks from benign lookalikes through approved VPN routing, scheduled maintenance windows, and typo-tolerant thresholds.
* **Audit Trail Accountability**: Every suppressed event is preserved in an immutable Context Exceptions audit log with policy tags, rationale, and evidence IDs.

### 🔬 Investigation Studio (Mission 03)
* **Chronological Timeline**: Step-by-step visual progression of failed and compromised attempts leading up to account takeovers.
* **User-to-Host Graph**: Interactive canvas displaying destination workstations, servers, and domain controllers accessed during an incident.
* **Per-User Risk Breakdown**: Granular scoring contribution breakdown by detection rule with MITRE ATT&CK mappings.
* **Plain-English Explanations**: Contextual evidence summaries with supporting raw event citations and confidence ratings.
* **Forensic Export**: One-click export to structured CSV and self-contained HTML forensic reports.

---

## 🎯 Detection Rules & MITRE ATT&CK Matrix

SignalForge evaluates eight specialized rules calibrated to the organizer's operational specifications:

| Rule Name | MITRE ATT&CK | Threshold & Window | Detection Logic | Benign Lookalike Handling |
| :--- | :---: | :---: | :--- | :--- |
| **Brute Force** | `T1110.001` | $\ge 5$ failures in **10 min** | Repeated authentication failures targeting a single account | 3 typos followed by success from user's known workstation is tolerated |
| **Burst Success** | `T1110` | $\ge 3$ failures $\to$ success in **15 min** | Authentication success immediately following multiple failed attempts | Flags high-risk credential compromise |
| **Password Spraying** | `T1110.003` | $\ge 10$ accounts in **30 min** | Single external source IP attempting logins across multiple accounts | SSO outage (many accounts failing from separate IPs) is isolated |
| **Impossible Travel** | `T1078` | Velocity $> 900\text{ km/h}$ | Haversine distance divided by elapsed time between consecutive logins | **Suppressed** if either IP belongs to approved corporate VPN CIDRs |
| **New IP / Location** | `T1078` | Anomaly | Login from an IP or city/country absent from user's Days 1–5 baseline | Cross-referenced against baseline profiles |
| **Host Fan-Out** | `T1021` | $\ge 3$ hosts in **1 hour** | Rapid movement across distinct destination workstations/servers | **Suppressed** for `helpdesk.svc` inside maintenance windows |
| **Unusual Hours** | `T1078` | Anomaly | Logins outside established working shifts evaluated in local timezone | Accommodates night-shift profiles learned during training |
| **Concurrent Sessions**| `T1185` | Overlapping | Active sessions originating simultaneously from distinct subnets | Evaluated across non-routable boundaries |

### 🌐 Impossible-Travel Physics Model

SignalForge computes spherical surface distance using the Haversine formula:

$$\Delta\phi = \phi_2 - \phi_1, \quad \Delta\lambda = \lambda_2 - \lambda_1$$

$$a = \sin^2\left(\frac{\Delta\phi}{2}\right) + \cos(\phi_1)\cos(\phi_2)\sin^2\left(\frac{\Delta\lambda}{2}\right)$$

$$d = 2R \cdot \text{atan2}\left(\sqrt{a}, \sqrt{1-a}\right) \quad (\text{where } R = 6,371\text{ km})$$

$$\text{Velocity} = \frac{d}{\Delta t} \quad (\text{km/h})$$

* **Aviation Threshold**: Flags transitions exceeding commercial cruising speeds ($> 900\text{ km/h}$).
* **CGNAT Jitter Floor**: Enforces a 100 km distance floor to prevent false alerts from metropolitan cellular handovers.
* **Coordinate Validation**: Rejects invalid, out-of-range, or unmapped subnets without fabricating distance claims.

---

## 🏗️ System Architecture & Data Flow

```
                      ┌──────────────────────────────────────┐
                      │    Raw Authentication CSV Telemetry   │
                      │  (TC01-TC11, Multi-day Logs, Custom) │
                      └──────────────────┬───────────────────┘
                                         │
                                         ▼
                      ┌──────────────────────────────────────┐
                      │    Ingestion & Normalization Layer   │
                      │  - PapaParse Stream Parsing          │
                      │  - Schema Normalization & Aliases    │
                      │  - ISO-8601 & Timezone Conversion    │
                      │  - FNV-1a Event Deduplication        │
                      └──────────────────┬───────────────────┘
                                         │
                                         ▼
                      ┌──────────────────────────────────────┐
                      │    Profile Detection & Context Prep  │
                      │  - Auto-Detect Variant A / B / Synth │
                      │  - CIDR Geo Lookup & Asset Inventory │
                      │  - Fallback Baseline Learning (D1-5) │
                      └──────────────────┬───────────────────┘
                                         │
                                         ▼
                      ┌──────────────────────────────────────┐
                      │    Detection Engine Core (8 Rules)   │
                      │  - Sliding Window Temporal Counters  │
                      │  - Haversine Velocity Calculations   │
                      │  - Policy & Maintenance Evaluator    │
                      └──────────────────┬───────────────────┘
                                         │
                                         ▼
                      ┌──────────────────────────────────────┐
                      │    Correlation & Scoring Layer       │
                      │  - Incident Grouping (Account/Window)│
                      │  - Risk Scoring & Severity Weighting │
                      │  - Policy Exception Audit Trail      │
                      └──────────────────┬───────────────────┘
                                         │
                                         ▼
                      ┌──────────────────────────────────────┐
                      │   React 19 UI & Investigation Studio │
                      │  - Executive KPI StatCards           │
                      │  - Filterable Incident Feed          │
                      │  - Interactive User-Host Graph       │
                      │  - Evidence Timeline & Audit Modal   │
                      │  - CSV / Standalone HTML Export      │
                      └──────────────────────────────────────┘
```

---

## 🚀 Quick Start & Installation

### Prerequisites
* **Node.js**: v20.x or v22.x LTS
* **Package Manager**: `npm` v10+

### Installation & Launch

```bash
# 1. Clone the repository
git clone https://github.com/PaulSerene/mission-72.git
cd mission-72

# 2. Install dependencies
npm install

# 3. Start development server
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## 🛠️ Verification & Build Commands

| Command | Description | Verified Status |
| :--- | :--- | :---: |
| `npm test -- --run` | Execute complete test suite (264 tests across 20 files) | **264 / 264 PASS** |
| `npm run build` | Compile TypeScript (`tsc -b`) and bundle for production (`vite build`) | **377ms (Clean)** |
| `npm run lint` | Run linter (`oxlint src`) across all source files | **0 Errors** |
| `npm run preview` | Locally preview production bundle from `dist/` | **Ready** |
| `npm run test:coverage` | Generate unit test code coverage report | **Ready** |
| `npm run typecheck` | Perform strict TypeScript type checking without emit | **Clean** |

---

## 📊 Official Dataset Validation (TC01–TC11)

SignalForge was validated against the organizer's authoritative **`PS2_Suspicious_Login_Detector`** official dataset:

| Test ID | Variant | Official Source File | Scenario Description | Expected Incident | Actual Result | Status |
| :---: | :---: | :--- | :--- | :--- | :--- | :---: |
| **TC01** | **A / B** | `TC01_normal_logins_*.csv` | Normal user logins during business hours | 0 attack alerts | 0 alerts fired | **PASS** |
| **TC02** | **A / B** | `TC02_repeated_failures_*.csv` | 7 failed logins spaced 50s apart | `brute_force` incident | 1 incident (Score 45) | **PASS** |
| **TC03** | **A / B** | `TC03_failure_then_success_*.csv` | 6 failures followed by 1 success in 6m | `burst_success` incident | 1 incident (Score 75) | **PASS** |
| **TC04** | **A / B** | `TC04_password_spraying_*.csv` | Single IP spraying 15 user accounts | 15 `password_spray` incidents | 15 incidents | **PASS** |
| **TC05** | **A / B** | `TC05_impossible_travel_vs_vpn_*.csv`| Distant login vs. corporate VPN login | 1 `impossible_travel` incident | Attack flagged; VPN suppressed | **PASS** |
| **TC06** | **A / B** | `TC06_fan_out_vs_maintenance_*.csv` | `helpdesk.svc` patching during `MW-01` | Suppression inside MW | Helpdesk suppressed; user flagged | **PASS** |
| **TC07** | **A / B** | `TC07_duplicated_rows_*.csv` | Duplicate rows with identical event data | 8 duplicate rows stripped | 0 false attacks / 0 score inflation | **PASS** |
| **TC08** | **A / B** | `TC08_out_of_order_*.csv` | Out-of-order logs & invalid timestamps | Chronologically sorted | 1 invalid row skipped; 29 sorted | **PASS** |
| **TC09** | **A / B** | `TC09_missing_ips_*.csv` | Missing / empty IP rows | Clean diagnostics | 4 malformed rows safely rejected | **PASS** |
| **TC10** | **A / B** | `TC10_malformed_columns_*.csv` | Extra commas / malformed CSV headers | Safe row rejection | 3 malformed rows safely rejected | **PASS** |
| **TC11** | **A / B** | `TC11_empty_file_*.csv` | Empty file with header row only | Zero crashes | 0 events, 0 alerts | **PASS** |

<br />

### Audited Confusion Matrix (Official Labeled Scenarios)

```
                        ┌────────────────────────┬────────────────────────┐
                        │    Predicted Threat    │    Predicted Benign    │
┌───────────────────────┼────────────────────────┼────────────────────────┤
│ Actual Threat (6)     │   True Positive (TP): 6│  False Negative (FN): 0│
├───────────────────────┼────────────────────────┼────────────────────────┤
│ Actual Benign (4)     │  False Positive (FP): 0│   True Negative (TN): 4│
└───────────────────────┴────────────────────────┴────────────────────────┘
```

* **Precision**: **1.0000 (100.0%)**
* **Recall**: **1.0000 (100.0%)**
* **Accuracy**: **1.0000 (100.0%)**

> [!IMPORTANT]
> **Operational Disclaimer**: This 100% metric is bounded to the organizer's provided evaluation scenarios. Real-world enterprise networks encounter residential proxy botnets, unannounced SaaS egress proxies, and cellular CGNAT jitter that will not yield 100% precision in unconstrained environments.

---

## 📁 Repository Layout

```
mission-72/
├── docs/                             # Mission technical documentation & validation reports
│   ├── MISSION_02_CONTEXT_AWARE_DETECTION.md
│   ├── MISSION_03_VISUALIZATION_AND_RISK_ANALYSIS.md
│   └── MISSION_04_TESTING_AND_VALIDATION.md
├── PS2_Suspicious_Login_Detector/    # Official organizer dataset & reference telemetry
│   ├── config/                       # detector_config_A.yaml, detector_config_B.yaml
│   ├── data/                         # TC01..TC11, training_auth_logs, mission01..02
│   ├── labels/                       # Mission 01 event & scenario ground truth
│   └── reference/                    # asset_list, ip_locations, privileged_accounts
├── src/
│   ├── components/                   # UI components & investigation modules
│   │   ├── IncidentFeed/             # Incident table, search, filters & export
│   │   ├── InvestigationStudio/      # UserHostGraph, Timeline, RiskBreakdown, Evidence
│   │   ├── LoadDataPanel/            # Drag-and-drop ingestion & demo loading
│   │   └── TopNav/                   # Header, KPI summary & theme toggle
│   ├── engine/                       # Pure TypeScript detection core (zero UI dependencies)
│   │   ├── assets.ts                 # Asset inventory & CIDR subnet matcher
│   │   ├── baseline.ts               # Behavioral profiling & working hours model
│   │   ├── geo.ts                    # Haversine distance & velocity physics
│   │   ├── incidents.ts              # Incident correlation & risk scoring
│   │   ├── ingest.ts                 # PapaParse CSV parser, alias mapping & FNV-1a dedup
│   │   ├── pipeline.ts               # Detection pipeline orchestrator & profile detection
│   │   └── rules.ts                  # Eight MITRE-aligned detection rules
│   ├── data/
│   │   └── referenceData.ts          # Inlined official reference tables for zero-network execution
│   ├── state/                        # Application state reducer & context
│   └── test/                         # Comprehensive Vitest suite (264 tests)
├── package.json                      # Project dependencies & npm scripts
├── tsconfig.json                     # TypeScript strict configuration
└── vite.config.ts                    # Vite build configuration & path aliases
```

---

## 🛡️ Limitations & Operational Roadmap

1. **Distributed Residential Proxy Sprays**: `password_spray` groups by source IP. Attackers using botnets with 1 attempt per IP evade single-IP grouping. Future roadmap: domain-wide failure velocity tracking.
2. **Missing Geolocation Data**: Private unmapped subnets or external IPs without lookup records produce no velocity alerts. SignalForge conservatively avoids hallucinating coordinates.
3. **Plausible-Interval Credential Replay**: Adversaries delaying credential replay past commercial flight travel times evade speed thresholds.
4. **Session Duration Tracking**: Authentication logs capture logon timestamps, but logoff events are frequently omitted in standard auth telemetry.

---

## 🤖 AI Assistance Disclosure

In the development of SignalForge, AI coding assistants (including Anthropic Claude and Google Antigravity / DeepMind agentic tools) were used in accordance with hackathon guidelines:
* **AI Contributions**:
  * Accelerated generation of UI component boilerplate and CSS Modules layout styles.
  * Formulated the spherical Haversine trigonometric distance formula in TypeScript.
  * Assisted in designing test suites and parametric edge-case tests.
  * Accelerated troubleshooting of timezone boundary offsets (+05:30 IST vs. UTC Z).
* **Human Governance**:
  * The architectural design, pipeline orchestration, threshold tuning, security suppression policies, test assertions, and audit validation were completely designed, reviewed, and verified by the team.

---

## 👥 Team Information

* **Jay Vardhan Surepally (Team Lead)**
* **Rohith Madanala (Team Member)**

---

## 🌐 Deployment

* **Platform**: Vercel (Single-Page Application)
* **Framework Preset**: `Vite`
* **Build Command**: `npm run build`
* **Output Directory**: `dist`
* **Node Version**: `20.x` or `22.x`
