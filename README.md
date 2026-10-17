# SignalForge — Suspicious Login and Activity Detector

> **Autonomous Client-Side SOC Analysis, Behavioral Baselines & Incident Correlation Platform**
> *Built for Missionathon / Problem Statement 2 (PS-02)*

---

## 1. Project Purpose & Problem Statement

Modern Security Operations Centers (SOCs) face alert fatigue from high-volume, isolated authentication events. Basic threshold rules often generate excessive false positives on benign edge cases—such as scheduled IT maintenance, employees roaming through enterprise VPN gateways, or temporary single-sign-on (SSO) outages.

**SignalForge** solves this problem by providing a **context-aware, browser-native authentication log analysis platform**. It ingests raw authentication CSV logs, constructs statistical behavioral baselines from historical training activity, evaluates multi-stage correlation rules, and contextualizes detections against asset inventories, corporate maintenance windows, and approved VPN networks.

All processing executes **100% locally in the browser** using client-side TypeScript—guaranteeing zero telemetry leakage, sub-second correlation, and instant investigation without external backend dependencies.

---

## 2. Core Features & Detection Rules

### Context-Aware Detection Engine
SignalForge evaluates authentication streams against eight specialized detection rules aligned with the MITRE ATT&CK framework:

1. **Brute Force (`brute_force`) [T1110.001]**:
   - Detects repeated authentication failures against a single user account ($\ge 5$ failures within a 10-minute sliding window).
2. **Burst Success / Account Compromise (`burst_success`) [T1110]**:
   - Detects authentication success following multiple recent failures ($\ge 3$ failures followed by a success within 15 minutes).
3. **Password Spraying (`password_spray`) [T1110.003]**:
   - Detects a single source IP attempting logins across $\ge 10$ distinct accounts within a 30-minute window.
4. **Impossible Travel (`impossible_travel`) [T1078]**:
   - Calculates geographic distance and elapsed velocity between consecutive successful logins for an account using spherical Haversine trigonometry:
     $$d = 2R \cdot \arcsin\left(\sqrt{\sin^2\left(\frac{\Delta\phi}{2}\right) + \cos\phi_1\cos\phi_2\sin^2\left(\frac{\Delta\lambda}{2}\right)}\right)$$
   - Flags transitions exceeding commercial aviation limits ($> 900\text{ km/h}$) with a 100 km metropolitan CGNAT jitter floor.
5. **New IP or Geographic Location (`new_ip_location`) [T1078]**:
   - Identifies logins originating from an IP address or city/country not present in the user's learned baseline profile.
6. **Host Fan-Out / Lateral Movement (`new_hosts`) [T1021]**:
   - Detects rapid authentication attempts across $\ge 3$ distinct destination hosts within a 1-hour window.
7. **Privileged Off-Hours Access (`unusual_hours`) [T1078]**:
   - Flags administrative or privileged account access outside normal operational shift hours in the configured timezone.
8. **Concurrent Active Sessions (`concurrent_sessions`) [T1185]**:
   - Detects overlapping active sessions originating from distinct, non-routable IP subnets.

### Benign Lookalike Suppression & Policy Auditing
SignalForge distinguishes genuine threats from legitimate operational anomalies:
- **Approved Corporate VPN Suppression**: Logins originating from declared corporate VPN CIDRs (e.g. `172.16.50.0/24` or `172.16.60.0/24`) do not trigger false impossible-travel alerts. Independent attack signatures (brute-force or spraying from VPN IPs) are **never suppressed**.
- **Scheduled Maintenance Scoping**: Rapid host access by designated IT service accounts (e.g. `helpdesk.svc`) during pre-declared maintenance windows (`MW-A-01`, `MW-B-01`) targeting workstations (`WS-*`) is suppressed with a full audit log entry.
- **SSO Outage Isolation**: High failure volumes during SSO outages originating from distinct user IPs are correctly distinguished from single-IP password spraying.
- **Typo Tolerance**: 3 or fewer failed attempts followed by success from a known user workstation do not generate alert noise.

### Mission 03 Investigation Studio
- **Chronological Timeline**: Visual step-by-step audit of suspicious attempts, successes, and policy events.
- **User-to-Host Graph**: Interactive canvas displaying destination workstations, servers, and domain controllers accessed by compromised accounts.
- **Per-User Risk Breakdown**: Granular scoring contribution breakdown by detection rule with MITRE ATT&CK mappings.
- **Evidence Explanations**: Plain-English rationale with supporting event IDs and evidence confidence indicators.

---

## 3. Architecture & Data Flow

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

## 4. Prerequisites & Installation

### Prerequisites
- **Node.js**: v20.x or v22.x LTS
- **Package Manager**: `npm` v10+

### Installation
```bash
# Clone the repository
git clone https://github.com/PaulSerene/mission-72.git
cd mission-72

# Install dependencies
npm install
```

---

## 5. Build & Execution Commands

| Command | Description |
| :--- | :--- |
| `npm run dev` | Start Vite development server (default: `http://localhost:5173`) |
| `npm run build` | Compile TypeScript (`tsc -b`) and bundle for production (`vite build`) |
| `npm run preview` | Locally preview production build bundle from `dist/` |
| `npm test -- --run` | Execute complete test suite (264 tests across 20 files) |
| `npm run test:watch` | Run tests in interactive Vitest watch mode |
| `npm run test:coverage`| Generate unit test code coverage report |
| `npm run lint` | Run linter (`oxlint src`) across all source files |
| `npm run typecheck` | Perform strict TypeScript type checking without emitting files |

---

## 6. Configuration & Input Data Requirements

### Authentication Log Schema
The parser accepts standard headers and common SIEM aliases:

| Canonical Field | Recognized Aliases | Required | Description |
| :--- | :--- | :---: | :--- |
| `event_id` | `eventid`, `id` | Optional | Unique event identifier (auto-hashed if missing) |
| `timestamp` | `time`, `datetime`, `@timestamp` | **Yes** | ISO-8601 with offset (`+05:30`) or UTC (`Z`) |
| `username` | `user`, `account`, `user_id` | **Yes** | User account name |
| `source_ip` | `src_ip`, `ip`, `client_ip` | **Yes** | IPv4 or IPv6 address |
| `destination_host` | `host`, `hostname`, `target`, `resource` | **Yes** | Target workstation or server |
| `result` | `status`, `outcome` | **Yes** | `success` / `failure` |
| `logon_type` | `type`, `logon_method` | Optional | `interactive`, `remote_interactive` (RDP), `network` |
| `failure_reason` | `reason`, `error`, `sub_status` | Optional | Failure code (e.g. `bad_password`, `account_locked`) |

### Reference Telemetry & Baseline Configuration
- **Variant A**: Timestamps in Indian Standard Time (`+05:30`). Uses `ip_locations_A.csv`, `asset_list_A.csv`, and corporate VPN CIDR `172.16.50.0/24`.
- **Variant B**: Timestamps in UTC (`Z`). Uses `ip_locations_B.csv`, `asset_list_B.csv`, and corporate VPN CIDR `172.16.60.0/24`.
- **Automatic Fallback**: If a user uploads an isolated test CSV (e.g., `TC02_repeated_failures_A.csv`) without uploading manual reference tables, SignalForge automatically identifies the dataset variant and loads official reference lookups and baseline profiles.

---

## 7. Sample Datasets & Verified Results

### Official Organizer Dataset Validation (`PS2_Suspicious_Login_Detector`)
Executed in `src/test/officialDatasetValidation.test.ts` and `src/test/uploadWorkflowAudit.test.ts`:

| Test Case | Scenario Description | Expected Incident | Test Result |
| :--- | :--- | :--- | :---: |
| **TC01 (A/B)** | Normal user logins during business hours | 0 attack alerts / 0 incidents | **PASS** |
| **TC02 (A/B)** | 7 failed logins spaced 50s apart | `brute_force` incident ($\ge 5$ failures in 10m) | **PASS** |
| **TC03 (A/B)** | 6 failures followed by 1 success | `burst_success` incident ($\ge 3$ fails + success in 15m) | **PASS** |
| **TC04 (A/B)** | 1 IP attempting 15 distinct user accounts | 15 `password_spray` incidents (1 per victim account) | **PASS** |
| **TC05 (A/B)** | Distant login vs. corporate VPN transition | 1 `impossible_travel` incident; corporate VPN suppressed | **PASS** |
| **TC06 (A/B)** | `helpdesk.svc` patching during `MW-01` vs. user | `helpdesk.svc` suppressed in MW; user flagged outside MW | **PASS** |
| **TC07 (A/B)** | Duplicate rows with identical event content | 8 duplicate rows stripped; 0 false attack alerts | **PASS** |
| **TC08 (A/B)** | Out-of-order logs & invalid timestamp strings | Chronologically sorted; invalid timestamp row safely skipped | **PASS** |
| **TC09 (A/B)** | Missing / empty IP rows | Malformed rows rejected with diagnostics; 0 crashes | **PASS** |
| **TC10 (A/B)** | Extra comma columns / malformed headers | Malformed rows rejected with diagnostics; 0 crashes | **PASS** |
| **TC11 (A/B)** | Empty file with header only | 0 events, 0 alerts, clean UI handling | **PASS** |

### Verified Test Suite Counts
- **Total Test Files**: 20 files
- **Total Tests Passing**: **264 tests passed (0 failures, 0 skipped)**
- **Build Status**: Clean production bundle in ~550ms (`tsc -b && vite build`)
- **Linter Status**: 0 errors (`oxlint src`)

---

## 8. Limitations & Future Roadmap

1. **Distributed Residential Proxy Sprays**:
   - `password_spray` groups failures by source IP address. Adversaries routing attacks through botnets where each IP only attempts 1 account will evade single-IP grouping. Future improvement: aggregate failure velocity across target domains.
2. **Missing Geolocation Data**:
   - For private unmapped subnets or external IPs without lookup records, coordinates are unavailable. SignalForge conservatively emits no travel claim rather than hallucinating coordinates.
3. **Plausible-Interval Credential Replay**:
   - Attackers delaying replay of stolen credentials until the duration of a commercial flight has elapsed will evade velocity threshold alerting.
4. **Session Duration Tracking**:
   - Authentication events capture logon timestamps, but logoff telemetry is frequently omitted in standard auth logs.

---

## 9. AI Assistance Disclosure

In the development of SignalForge, AI coding assistants (including Anthropic Claude and Google Antigravity / DeepMind agentic tools) were used in accordance with hackathon guidelines:
- **Assisted Areas**:
  - Drafting initial boilerplate for CSS custom property tokens and UI layout components.
  - Formulating mathematical equations for spherical Haversine trigonometry in TypeScript.
  - Generating synthetic test fixtures and parametric test permutations.
  - Assisting in debugging sliding window boundary conditions across timezone offsets.
- **Human Governance**:
  - All architecture, detection logic, threshold tuning, test assertions, security policies, and code reviews were directed, validated, and verified by the development team.

---

## 10. Team Information & Contributions


- **Jay Vardhan Surepally (Team Lead)**
- **Rohith Madanala (Team Member)**

---

## 11. Deployment

- **Deployment URL**: *[PENDING FINAL VERCEL DEPLOYMENT BY TEAM]*
- **Deployment Platform**: Vercel (Single-Page Application)
- **Vercel Settings**:
  - Framework Preset: `Vite`
  - Build Command: `npm run build`
  - Output Directory: `dist`
  - Node.js Version: `20.x`
