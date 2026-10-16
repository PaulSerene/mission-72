# SignalForge — Mission 04: Testing, Validation & Impossible-Travel Detection Report

> **Official Organizer Dataset Validation, Operational Specification, Comprehensive Validation Suite, Detection Accuracy Evaluation & Impossible-Travel Implementation**  
> *SignalForge Suspicious Login and Activity Detector — Mission 04*  
> **Authoritative Test Source**: `PS2_Suspicious_Login_Detector`

---

## 1. Executive Summary

Mission 04 validates the **SignalForge Suspicious Login and Activity Detector** against the organizer's authoritative **`PS2_Suspicious_Login_Detector`** official dataset, implementing real, tested **Impossible-Travel Detection** using the spherical Haversine formula and velocity estimation.

Rather than relying primarily on synthetic tests, the core detection pipeline was rigorously evaluated against:
1. **The Official Configuration Schemas**: `detector_config_A.yaml` (IST $+05:30$) and `detector_config_B.yaml` (UTC $Z$).
2. **Official Reference Datasets**: `asset_list_{A,B}.csv`, `ip_locations_{A,B}.csv`, `privileged_accounts_{A,B}.csv`, `user_directory_{A,B}.csv`.
3. **Official Baseline Training Telemetry**: `training_auth_logs_days1-5_{A,B}.csv` (learning per-user baselines strictly from Days 1–5).
4. **All Official Mission 04 Test Cases**: `TC01` through `TC11` across both `_A` and `_B` variants (22 test files total).
5. **Official Mission 01 & Mission 02 Datasets**: Full multi-day logs and ground-truth scenario labels (`mission01_scenarios_{A,B}.csv`, `mission01_event_labels_{A,B}.csv`, `mission02_auth_logs_days6-7_{A,B}.csv`).

### Key Deliverables & Validation Results
- **26/26 Official Dataset Tests Passing**: 100% pass rate across all 11 Mission 04 test scenarios for both Variant A and Variant B, plus full Mission 01 and Mission 02 ground-truth evaluations (`src/test/officialDatasetValidation.test.ts`).
- **Full Workspace Regression**: **249/249 tests passing** across 18 test files (`npm test -- --run`).
- **Production Compilation**: Clean `tsc -b && vite build` bundle output in ~389ms.
- **Code Quality & Security**: 0 lint errors (`oxlint`), 0 audit vulnerabilities (`npm audit`).
- **Non-Destructive Integrity**: Zero organizer CSV files modified, overwritten, or renamed. The application's ingestion engine was adapted to respect the organizer's exact data contract.

---

## 2. Respecting the Organizer's Data Contract

### 2.1 Column Schemas & Field Mappings
The organizer's source data defines the following column schemas:
- **Authentication Logs**: `event_id, timestamp, username, source_ip, destination_host, event_type, result, logon_type, failure_reason`
- **IP Location Lookups**: `ip_range_cidr, city, country, latitude, longitude, network_type`
- **Asset Inventories**: `host, ip_address, host_role, primary_user, zone`
- **Privileged Accounts**: `username, account_type, allowed_hosts, notes`
- **User Directory**: `username, role, assigned_workstation, normal_shift`

### 2.2 Telemetry Ingestion Adaptations (`src/engine/ingest.ts`, `src/engine/assets.ts`)
To adhere to the contract without altering source CSVs:
1. **Event ID Preservation**: Added `EVENT_ID_ALIASES = ['event_id', 'eventid']`. When present in the source CSV, the original event ID (e.g. `A-E001815`, `B-E001799`) is preserved on `AuthEvent.id` and `AuthEvent.rawEventId`. For legacy or synthetic logs lacking an ID column, the FNV-1a stable content hash (`ev-[0-9a-f]{8}`) is generated deterministically.
2. **Logon Type Normalization**: Extended `normalizeLogonType` to map `remote` (Windows Remote Desktop / Remote Interactive logon type 10) to `remote_interactive`.
3. **Failure Reason**: Captured `failure_reason` (e.g. `bad_password`) onto `AuthEvent.failureReason`.
4. **Malformed Row Safety**: Updated `normalizeKeys` to safely handle PapaParse overflow arrays (`__parsed_extra`), preventing `(v ?? '').trim is not a function` exceptions when rows have extra commas.
5. **IP Location Enrichment**: Enhanced `parseIpLocations` to accept `ip_range_cidr` alongside `cidr`, synthesize `location` from `city` and `country` (e.g. `"Campus-Hyderabad, IN"`), and parse `network_type` (`internal`, `vpn`, `external`).
6. **Asset Role Mapping**: Added `host_role` alias to `parseAssets`.

### 2.3 Timezone Normalization Across A/B Variants
- **Variant A**: Timestamps specify IST with explicit offset `+05:30` (e.g. `2026-11-07T10:00:00+05:30`).
- **Variant B**: Timestamps specify UTC with `Z` suffix (e.g. `2026-11-14T04:30:00Z`).
- **Crucial Boundary Finding**: The analysis and reporting timezone for both variants is `Asia/Kolkata` (`+05:30`). Consequently, Day 6 in Asia/Kolkata (starting at `2026-11-14T00:00:00+05:30`) corresponds to `2026-11-13T18:30:00Z` in UTC. Test events occurring at `2026-11-13T22:30:00Z` fall at `04:00:00 IST` on Day 6. Aligning the UTC analysis window to `[2026-11-13T18:30:00Z, 2026-11-15T18:30:00Z]` correctly ingested all Day 6–7 Variant B events.

---

## 3. Impossible-Travel Detection Architecture & Physics Model

### 3.1 Physics & Anomaly Rationale
Physical human travel across the Earth's surface is bounded by the speed of commercial aviation (~850–920 km/h cruising speed for wide-body jetliners). When two consecutive successful logins for the same account occur at distant locations within an elapsed time that requires supersonic or physically impossible speed, it strongly indicates credential sharing, session token hijacking, or proxy egress.

### 3.2 Mathematical Formulation (Haversine Formula)
Implemented in [`src/engine/geo.ts`](file:///c:/Users/Jayva/Downloads/missionathon/src/engine/geo.ts):

$$\Delta\phi = \text{lat}_2 - \text{lat}_1, \quad \Delta\lambda = \text{lon}_2 - \text{lon}_1$$

$$a = \sin^2\left(\frac{\Delta\phi}{2}\right) + \cos(\text{lat}_1)\cos(\text{lat}_2)\sin^2\left(\frac{\Delta\lambda}{2}\right)$$

$$c = 2 \times \text{atan2}\left(\sqrt{a}, \sqrt{1-a}\right)$$

$$d = 6371 \times c \quad (\text{kilometers})$$

$$v = \frac{d}{\Delta t / (1000 \times 3600)} \quad (\text{km/h})$$

### 3.3 Configured Thresholds & Operational Assumptions

| Parameter | Configuration Key | Configured Value | Operational Rationale |
| :--- | :--- | :--- | :--- |
| **Max Plausible Speed** | `rules.impossible_travel.max_speed_kmh` | **900 km/h** | Aligned with `detector_config_{A,B}.yaml` threshold. Standard commercial airliners cruise at 850–900 km/h. Exceeding 900 km/h flags physically impossible transit. |
| **Min Distance Floor** | `rules.impossibleTravel.minDistanceKm` | **100 km** | Metropolitan ISP transitions and cellular CGNAT handovers frequently shift public IPs within a 20–70 km radius. Setting a 100 km floor avoids false alerts on local telecommuters. |
| **Minimum Elapsed Time** | `elapsedMs > 0` | **> 0 ms** | Simultaneous ($\Delta t = 0$) or out-of-order events are skipped to avoid division by zero or negative velocities. |
| **Coordinate Bounds** | `isValidCoordinate` | **$[-90, 90], [-180, 180]$** | Invalid, out-of-bounds, NaN, or null coordinates are rejected. Coordinates are **never guessed or inferred**. |
| **Account Isolation** | `username` grouping | **Same account only** | Consecutive logins are strictly grouped by normalized username. Cross-account travel is never computed. |
| **Login Outcome** | `outcome === 'success'` | **Successful logins only** | Failed logins alone do not indicate user physical presence at a location. |

### 3.4 VPN & Proxy Context Handling
- **Gateway Location vs. User Location**: An approved corporate VPN gateway's egress IP represents VPN datacenter infrastructure, not verified user physical presence.
- **Suppression Policy**: If either login in a transition originates from a configured approved VPN CIDR (`172.16.50.0/24` in A, `172.16.60.0/24` in B), the impossible-travel inference is suppressed with a detailed audit log entry in `suppressedAlerts`.
- **Attack Non-Suppression**: Approved VPN status does **not** suppress independent brute-force, burst-success, or password-spraying rules originating from VPN IPs.

---

## 4. Official Test Cases Validation Matrix (TC01–TC11)

Executed directly from `PS2_Suspicious_Login_Detector/data/mission04_tests/` in [`src/test/officialDatasetValidation.test.ts`](file:///c:/Users/Jayva/Downloads/missionathon/src/test/officialDatasetValidation.test.ts):

| Test ID | Variant | Source File | Expected Behavior | Actual Application Result | Affected Accounts | Relevant Alerts | Status |
| :---: | :---: | :--- | :--- | :--- | :--- | :--- | :---: |
| **TC01** | **A** | `TC01_normal_logins_A.csv` | Normal activity; 0 attack alerts | 0 alerts fired | - | None | **PASS** |
| **TC01** | **B** | `TC01_normal_logins_B.csv` | Normal activity; 0 attack alerts | 0 alerts fired | - | None | **PASS** |
| **TC02** | **A** | `TC02_repeated_failures_A.csv` | Repeated auth failures ($\ge 5$ in 10m) | 1 rule match (7 failures linked) | `pooja.reddy` | `brute_force` | **PASS** |
| **TC02** | **B** | `TC02_repeated_failures_B.csv` | Repeated auth failures ($\ge 5$ in 10m) | 1 rule match (7 failures linked) | `leela_pillai` | `brute_force` | **PASS** |
| **TC03** | **A** | `TC03_failure_then_success_A.csv` | $\ge 4$ failures then success within 15m | 1 rule match (6 fails + 1 succ) | `rahul.gupta` | `burst_success` | **PASS** |
| **TC03** | **B** | `TC03_failure_then_success_B.csv` | $\ge 4$ failures then success within 15m | 1 rule match (6 fails + 1 succ) | `mohan_das` | `burst_success` | **PASS** |
| **TC04** | **A** | `TC04_password_spraying_A.csv` | Single IP targeting $\ge 10$ accounts in 30m | 15 rule matches (1 per victim) | 15 accounts | `password_spray` | **PASS** |
| **TC04** | **B** | `TC04_password_spraying_B.csv` | Single IP targeting $\ge 10$ accounts in 30m | 15 rule matches (1 per victim) | 15 accounts | `password_spray` | **PASS** |
| **TC05** | **A** | `TC05_impossible_travel_vs_vpn_A.csv` | Impossible travel for distant login; VPN login clean | 1 travel alert; 0 false VPN alerts | `sneha.nair` | `impossible_travel` | **PASS** |
| **TC05** | **B** | `TC05_impossible_travel_vs_vpn_B.csv` | Impossible travel for distant login; VPN login clean | 1 travel alert; 0 false VPN alerts | `neha_das` | `impossible_travel` | **PASS** |
| **TC06** | **A** | `TC06_fan_out_vs_maintenance_A.csv` | Helpdesk suppressed in MW; user alerted outside MW | Helpdesk suppressed; kavya alerted | `kavya.reddy` | `new_hosts` | **PASS** |
| **TC06** | **B** | `TC06_fan_out_vs_maintenance_B.csv` | Helpdesk suppressed in MW; user alerted outside MW | Helpdesk suppressed; priya alerted | `priya_das` | `new_hosts` | **PASS** |
| **TC07** | **A** | `TC07_duplicated_rows_A.csv` | 8 duplicate rows deduplicated; no false brute force | 8 duplicates flagged; 0 false attacks | `nikhil.verma` | None (deduped) | **PASS** |
| **TC07** | **B** | `TC07_duplicated_rows_B.csv` | 8 duplicate rows deduplicated; no false brute force | 8 duplicates flagged; 0 false attacks | `qasim_bose` | None (deduped) | **PASS** |
| **TC08** | **A** | `TC08_out_of_order_and_invalid_timestamps_A.csv` | 1 invalid timestamp rejected; 29 sorted | 1 row rejected; 29 sorted | `varun.rao` | Ingestion diagnostic | **PASS** |
| **TC08** | **B** | `TC08_out_of_order_and_invalid_timestamps_B.csv` | 1 invalid timestamp rejected; 29 sorted | 1 row rejected; 29 sorted | `sameer_khan` | Ingestion diagnostic | **PASS** |
| **TC09** | **A** | `TC09_missing_ips_A.csv` | 4 empty IP rows rejected; remaining processed | 4 rows rejected; 0 crashes | `farhan.nair` | Ingestion diagnostic | **PASS** |
| **TC09** | **B** | `TC09_missing_ips_B.csv` | 4 empty IP rows rejected; remaining processed | 4 rows rejected; 0 crashes | `fatima_bose` | Ingestion diagnostic | **PASS** |
| **TC10** | **A** | `TC10_malformed_columns_A.csv` | Extra commas / bad headers handled safely | Malformed rows rejected; 0 crashes | - | Ingestion diagnostic | **PASS** |
| **TC10** | **B** | `TC10_malformed_columns_B.csv` | Extra commas / bad headers handled safely | Malformed rows rejected; 0 crashes | - | Ingestion diagnostic | **PASS** |
| **TC11** | **A** | `TC11_empty_file_A.csv` | Header-only file produces 0 events and 0 alerts | 0 events, 0 alerts, 0 incidents | - | None | **PASS** |
| **TC11** | **B** | `TC11_empty_file_B.csv` | Header-only file produces 0 events and 0 alerts | 0 events, 0 alerts, 0 incidents | - | None | **PASS** |

---

## 5. Ground-Truth Validation: Mission 01 & Mission 02 Datasets

### 5.1 Mission 01 Official Scenarios (`mission01_scenarios_{A,B}.csv`)

| Scenario ID | Variant | Entity | Description | Ground Truth | Expected Rule | Actual Application Result | Pass/Fail |
| :---: | :---: | :--- | :--- | :---: | :--- | :--- | :---: |
| **M1-S01** | **A** | `meera.sharma` | 8 failed logins in ~6m, no success | Suspicious | `failure_burst` | `brute_force` match generated (8 events linked) | **PASS** |
| **M1-S01** | **B** | `chetan_bose` | 8 failed logins in ~6m, no success | Suspicious | `failure_burst` | `brute_force` match generated (8 events linked) | **PASS** |
| **M1-S02** | **A** | `rahul.gupta` | Failure-then-success from unfamiliar IP | Suspicious | `failure_then_success; new_ip_or_location` | `burst_success` & `new_ip_location` matches generated | **PASS** |
| **M1-S02** | **B** | `tara_singh` | Failure-then-success from unfamiliar IP | Suspicious | `failure_then_success; new_ip_or_location` | `burst_success` & `new_ip_location` matches generated | **PASS** |
| **M1-S03** | **A** | `198.51.100.62` | External IP fails against 14 accounts in ~20m | Suspicious | `password_spraying` | `password_spray` matches generated for all 14 victims | **PASS** |
| **M1-S03** | **B** | `198.51.100.62` | External IP fails against 14 accounts in ~20m | Suspicious | `password_spraying` | `password_spray` matches generated for all 14 victims | **PASS** |
| **M1-S04** | **A** | `gauri.reddy` | Benign lookalike: 3 typos then success from usual IP | **Benign** | **None** | **0 alerts fired** (3 typos correctly below threshold 4) | **PASS** |
| **M1-S04** | **B** | `yamini_das` | Benign lookalike: 3 typos then success from usual IP | **Benign** | **None** | **0 alerts fired** (3 typos correctly below threshold 4) | **PASS** |
| **M1-S05** | **A** | 12 users | SSO outage: many users fail once from OWN IPs | **Benign** | **None** (many IPs) | **0 spray alerts** (source IPs are isolated, not spray) | **PASS** |
| **M1-S05** | **B** | 12 users | SSO outage: many users fail once from OWN IPs | **Benign** | **None** (many IPs) | **0 spray alerts** (source IPs are isolated, not spray) | **PASS** |
| **M1-DATA** | **A** | 6 rows | 6 duplicate rows (`A-E001247`, `1141`, `1122`, etc.) | Data Quality | `deduplicate` | `duplicateCount: 6` flagged; unique events preserved | **PASS** |
| **M1-DATA** | **B** | 6 rows | 6 duplicate rows (`B-E001031`, `1025`, `1289`, etc.) | Data Quality | `deduplicate` | `duplicateCount: 6` flagged; unique events preserved | **PASS** |

### 5.2 Mission 02 Official Datasets (`mission02_auth_logs_days6-7_{A,B}.csv`)
- **Variant A Impossible Travel**: `sneha.nair` logged in from `10.10.10.33` (Campus-Hyderabad) at `09:24:00+05:30` and then from `198.51.100.82` (Frankfurt, DE) at `09:37:00+05:30`.
  - Great-circle distance: **~7,200 km**.
  - Elapsed time: **13 minutes**.
  - Inferred speed: **~33,230 km/h** ($> 900\text{ km/h}$ threshold).
  - Result: **Detected `impossible_travel`** alert linking both events.
- **Variant A Benign VPN**: `diya.rao` logged in from `172.16.50.53` and `172.16.50.132` (Company-VPN-Gateway).
  - Result: **Suppressed** under approved corporate VPN policy; zero false impossible-travel alerts.
- **Variant B Impossible Travel**: `kunal_patel` logged in from `10.20.10.30` (Campus-Bengaluru) at `04:45:00Z` and from `198.51.100.50` (Frankfurt, DE) at `05:07:00Z`.
  - Great-circle distance: **~7,400 km**.
  - Elapsed time: **22 minutes**.
  - Inferred speed: **~20,180 km/h** ($> 900\text{ km/h}$ threshold).
  - Result: **Detected `impossible_travel`** alert linking both events.

---

## 6. Confusion Matrix & Accuracy Metrics

Metrics computed strictly from the executed official ground-truth scenarios (Mission 01 labeled scenarios M1-S01 through M1-S05 across Variants A and B):

```
                        ┌────────────────────────┬────────────────────────┐
                        │    Predicted Threat    │    Predicted Benign    │
┌───────────────────────┼────────────────────────┼────────────────────────┤
│ Actual Threat (6)     │   True Positive (TP): 6│  False Negative (FN): 0│
├───────────────────────┼────────────────────────┼────────────────────────┤
│ Actual Benign (4)     │  False Positive (FP): 0│   True Negative (TN): 4│
└───────────────────────┴────────────────────────┴────────────────────────┘
```

### Metrics:
- **Precision**: $\frac{\text{TP}}{\text{TP} + \text{FP}} = \frac{6}{6 + 0} = \mathbf{1.0000\ (100.0\%)}$
- **Recall**: $\frac{\text{TP}}{\text{TP} + \text{FN}} = \frac{6}{6 + 0} = \mathbf{1.0000\ (100.0\%)}$
- **Specificity**: $\frac{\text{TN}}{\text{TN} + \text{FP}} = \frac{4}{4 + 0} = \mathbf{1.0000\ (100.0\%)}$
- **F1 Score**: $2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = \mathbf{1.0000}$
- **Accuracy**: $\frac{6 + 4}{10} = \mathbf{1.0000\ (100.0\%)}$

> **SOC Evaluation Note**: While the detector achieved 100% precision and recall on the organizer's provided test suite, **real-world production detection accuracy is not 100%**. Production environments encounter unannounced consumer VPNs, multi-IP residential proxy sprays, and cellular CGNAT geo-jitter that inevitably produce false positives and false negatives (see Section 8).

---

## 7. Mismatches Discovered & Engineering Fixes Made

During validation against the official datasets, 5 concrete mismatches/edge cases were uncovered and resolved:

| # | Component | Root Cause / Mismatch | Responsible Fix |
| :-: | :--- | :--- | :--- |
| **1** | `normalizeKeys` (`src/engine/ingest.ts`) | `TC10_malformed_columns_A.csv` row 4 contained extra commas (`extra,extra`). PapaParse placed these into an array under `__parsed_extra`. Calling `(v ?? '').trim()` caused a `TypeError`. | Handled array and non-string values safely: `typeof v === 'string' ? v : Array.isArray(v) ? v.join(',') : String(v ?? '')`. |
| **2** | `parseIpLocations` (`src/engine/assets.ts`) | Official lookup files use `ip_range_cidr, city, country, latitude, longitude, network_type` rather than `cidr, location`. Missing columns led to rejected rows. | Expanded parser to accept `ip_range_cidr`, synthesize `location` from `city` + `country`, and record `network_type`. |
| **3** | `normalizeLogonType` (`src/engine/ingest.ts`) | Official logs use `remote` for RDP sessions. Previously only matched `remote_interact` or `10`, normalizing `remote` to `unknown`. | Updated regex to `v === '10' \|\| v.includes('remote') \|\| v.includes('rdp')` $\rightarrow$ `remote_interactive`. |
| **4** | Maintenance Windows (`src/engine/rules.ts`, `configValidation.ts`) | Organizer config defines concrete ISO windows (`start: "2026-11-07T13:00:00+05:30"`, `approved_accounts`, `scope: "All workstations"`). SignalForge previously only supported hour integers (`startHour: 13`). | Extended `MaintenanceWindow` to support concrete ISO timestamps (`start`, `end`), `approvedAccounts`, and workstation scope matching (`WS-*`). |
| **5** | Variant B Timezone Offset (`officialDatasetValidation.test.ts`) | Variant B logs use UTC timestamps (`Z`), but the organizer defines Days 1–5 and 6–7 in `Asia/Kolkata` (`+05:30`). Day 6 starts at `2026-11-13T18:30:00Z`. A naive `2026-11-14T00:00:00Z` analysis window was clipping 04:00 IST events. | Aligned Variant B UTC analysis window to `2026-11-13T18:30:00Z` to `2026-11-15T18:30:00Z`, capturing all Day 6–7 events. |

---

## 8. Remaining Limitations & Production Operational Risks

1. **Distributed / Residential Proxy Sprays**:
   - `detectPasswordSpray` groups failures strictly by `sourceIp`. Attackers rotating through residential proxies with 1 attempt per IP evade this rule.
2. **Missing Geolocation Data**:
   - For private unmapped subnets or external IPs without lookup records, coordinates are unavailable. The engine conservatively emits no travel claim rather than hallucinating coordinates.
3. **Plausible-Interval Credential Replay**:
   - Adversaries delaying replay of stolen credentials until the duration of a commercial flight has elapsed will evade velocity threshold alerting.
4. **Consumer Privacy Proxies (iCloud Private Relay, WARP)**:
   - When users enable device-level privacy proxies without registering CIDRs in enterprise VPN lists, egress IP transitions trigger false-positive `impossible_travel` signals.

---

## 9. Verification & Command Reproducibility

Execute all tests and builds using standard commands:

```bash
# 1. Run full test suite (249 tests passing)
npm test -- --run

# 2. Run specifically the official organizer dataset test suite (26 tests)
npm test -- src/test/officialDatasetValidation.test.ts

# 3. Run impossible travel tests (16 tests)
npm test -- src/test/impossibleTravel.test.ts

# 4. Verify TypeScript compilation and production bundle build
npm run build

# 5. Verify linter (0 errors)
npm run lint

# 6. Audit dependencies (0 vulnerabilities)
npm audit
```

### Git Status Summary
- **Working Tree**: Preserved on branch `main` without committing, pushing, resetting, or discarding user files.
- **Modified Core Files**:
  - `src/types/index.ts`
  - `src/engine/ingest.ts`
  - `src/engine/assets.ts`
  - `src/engine/pipeline.ts`
  - `src/engine/rules.ts`
  - `src/engine/configValidation.ts`
  - `src/engine/incidents.ts`
  - `src/engine/investigation.ts`
- **New Core & Test Files**:
  - `src/engine/geo.ts`
  - `src/test/impossibleTravel.test.ts`
  - `src/test/mission04Validation.test.ts`
  - `src/test/officialDatasetValidation.test.ts`
- **Documentation**:
  - `docs/MISSION_04_TESTING_AND_VALIDATION.md`
