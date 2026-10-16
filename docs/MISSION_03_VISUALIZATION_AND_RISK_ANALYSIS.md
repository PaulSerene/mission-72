# Mission 72 — Mission 03: Incident Visualization & Risk Analysis

> **Operational Specification, Architecture Guide, and Verification Report**  
> *Suspicious Login and Activity Detector — Incident Visualization & Risk Analysis*

---

## 1. Executive Summary

In security operations center (SOC) triage, raw alerts and isolated log entries fail to convey the broader narrative of a compromise. Security analysts require intuitive, interactive tools to explore:
1. **How events unfold over time** (chronological event progression and failure-to-success transitions).
2. **Where the adversary moved** (lateral traversal across internal host infrastructure).
3. **Why an incident carries a specific risk rating** (mathematically faithful score decomposition).
4. **How strong the underlying evidence is** (deterministic, explainable confidence indicators rather than uncalibrated black-box probabilities).

**Mission 03** implements the **Investigation Studio & Risk Analysis Engine** in SignalForge:
- **Interactive User-to-Host Topology Graph**: Lightweight, accessible SVG rendering of account-to-endpoint relationships with volume-weighted edges, failure/success distinctions, asset inventory role awareness, and a complete text table alternative.
- **Chronological Suspicious Event Timeline**: Strict time-ordered sequence with normalized UTC timestamps, outcome tags, rule badges, and a deep-dive Event Inspector.
- **Faithful Risk Score Decomposition**: Exact mathematical breakdown of base weights, repetition diminishing multipliers, burst/brute-force overlap discounts, contextual reductions, and multi-rule synergy bonuses.
- **Deterministic Evidence-Strength Evaluation**: Transparent categorical classification (`Strong`, `Moderate`, `Weak`) with auditable criteria, full telemetry traceability metrics, and context-suppression transparency.
- **Bidirectional Cross-Filtering**: Unified investigation state where selecting an incident, rule, host, or timeline event dynamically filters connected evidence.

---

## 2. Visualization Design & User Experience

The visualization architecture prioritizes high cognitive efficiency, deterministic performance, and SOC operational workflow:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       INVESTIGATION STUDIO TOOLBAR                          │
│  [Correlated Incident Selector]   [Active Filter Tags]   [Reset Filters]   │
└─────────────────────────────────────────────────────────────────────────────┘
                     │                                     │
                     ▼                                     ▼
┌──────────────────────────────────────┐  ┌───────────────────────────────────┐
│     USER-TO-HOST TOPOLOGY GRAPH      │  │        RISK SCORE BREAKDOWN       │
│  • Account center node               │  │  • Composite score [0–100]        │
│  • Radial host endpoint nodes        │  │  • Diminishing repetition table   │
│  • Volume & failure-weighted edges   │  │  • Overlap discount indicator     │
│  • Table view toggle (Accessible)    │  │  • +15 multi-rule synergy bonus   │
└──────────────────────────────────────┘  └───────────────────────────────────┘
                     │                                     │
                     ▼                                     ▼
┌──────────────────────────────────────┐  ┌───────────────────────────────────┐
│      ALERT EXPLANATIONS & EVIDENCE   │  │    CHRONOLOGICAL EVENT TIMELINE   │
│  • Rule match descriptions           │  │  • UTC ISO timestamps (asc/desc)  │
│  • Evidence Strength: Strong/Mod/Weak│  │  • Outcome & LogonType badges     │
│  • Deterministic evaluation criteria │  │  • Filter by outcome / host / rule│
│  • Traceability verification count   │  │  • Click to open Event Inspector  │
└──────────────────────────────────────┘  └───────────────────────────────────┘
```

### 2.1 User-to-Host Graph (`UserHostGraph.tsx`)
- **Visual Encoding**: Account identity rendered as central focal node in cyber electric blue; destination host endpoints arranged radially with role labels (`domain-controller`, `database`, `web-server`) and privileged status indicators (`★ Privileged`).
- **Edge Weighting**: Connecting lines scale dynamically with log volume ($\min(5, \max(2, 1.5 + \log_2(N + 1)))$), colored amber/red for failure patterns and cyber blue on selection. Midpoint badges indicate exact event counts.
- **Empty State**: Perimeter-only attacks (where target destination host is null/unspecified) display an explicit empty state explaining that authentications were external.
- **Accessibility & Textual Alternative**: Includes `role="graphics-document"`, keyboard navigation (`tabIndex={0}`, Enter/Space key triggers), and an instant toggle button to switch to an accessible HTML relationship table.

### 2.2 Chronological Timeline (`Timeline.tsx`)
- **Ordering Guarantee**: Strict UTC ascending/descending ordering via `sortEventsChronologically()`. Invalid or malformed timestamps are handled safely without crashing and placed deterministically at the end of the stream.
- **Context Badges**: Displays timestamp, outcome (Success / Failure), user, source IP with enriched location, destination host, logon method, and rule badges.
- **Interactive Event Inspector**: Clicking any timeline item opens a slide-down drawer showing full telemetry attributes (event ID, source IP, enriched location, destination, raw CSV row number, duplicate status).

---

## 3. Mathematical Risk Scoring & Faithful Decomposition

SignalForge's risk scoring is **bounded [0, 100]** and **heuristic**—it measures statistical and behavioral deviation from baseline, NOT a probability of compromise.

### 3.1 Mathematical Formulation

$$\text{RawScore} = \sum_{i=1}^{M} \left( \text{RawContrib}_i \times \text{CtxMultiplier}_i \right) + \text{SynergyBonus}$$

$$\text{FinalRiskScore} = \min(100, \max(0, \operatorname{round}(\text{RawScore})))$$

Where:
1. **Base Rule Weights** (`RULE_SCORES`):
   - `burst_success`: 55
   - `brute_force`: 40
   - `new_hosts`: 40
   - `password_spray`: 35
   - `new_ip_location`: 35
   - `unusual_hours`: 25
2. **Diminishing Returns on Repetitions**:
   Repeated firings of the same rule for the same user inside an incident yield decreasing marginal risk:
   - 1st firing: $\times 1.0$ (100% of base weight)
   - 2nd firing: $\times 0.4$ (40% of base weight)
   - 3rd+ firings: $\times 0.2$ (20% of base weight)
3. **Burst/Brute-Force Overlap Deduction**:
   When `burst_success` and `brute_force` fire on the same underlying authentication sequence, `burst_success` carries full weight (55) while `brute_force` is discounted to 15 (1st firing) or 5 (subsequent firings) to prevent double-counting shared failures.
4. **Context Multiplier** ($\text{CtxMultiplier}_i \in [0.0, 1.0]$):
   Partial de-escalations applied by security policies (e.g. 0.5 for authorized VPN or role policies) directly scale the contribution.
5. **Multi-Rule Synergy Bonus**:
   Observing $\ge 3$ distinct rule types in an incident adds $+15$ points to account for multi-vector or coordinated attacker progression.
6. **Strict Cap**:
   The final risk score is strictly capped at $100$.

### 3.2 Faithful Decomposition Interface

The `decomposeIncidentRiskScore` function exposes this exact calculation without mock metrics:

```typescript
export interface RuleScoreContribution {
  ruleId: string
  ruleName: string
  matchIndex: number
  repetitionCount: number
  baseScore: number
  repetitionMultiplier: number
  rawContribution: number
  contextMultiplier: number
  contextReason?: string
  overlapDiscounted: boolean
  overlapDiscountReason?: string
  finalContribution: number
}
```

---

## 4. Deterministic Evidence-Strength Classification

Evidence strength is categorized strictly as **`Strong`**, **`Moderate`**, or **`Weak`** based on documented, deterministic evaluation criteria rather than simulated probabilities.

### 4.1 Evaluation Criteria

| Rule / Signal | `Strong` Criteria | `Moderate` Criteria | `Weak` Criteria |
|---|---|---|---|
| **`burst_success`** | $\ge 4$ failures immediately followed by success | $1$–$3$ failures followed by success | Success without verified sequential failures in stream |
| **`brute_force`** | $\ge 10$ failed attempts | $5$–$9$ failed attempts | $< 5$ failures (sub-threshold) |
| **`password_spray`** | $\ge 5$ distinct user targets from source | $3$–$4$ distinct user targets | $< 3$ distinct targets |
| **`new_hosts`** | $\ge 5$ unobserved destination hosts | $3$–$4$ unobserved destination hosts | $< 3$ unobserved hosts |
| **`new_ip_location`** | N/A (single geo anomaly cannot be 'Strong') | Sufficient baseline ($\ge 5$ events), unmapped location | Insufficient baseline or partial VPN match |
| **`unusual_hours`** | N/A (timing alone cannot be 'Strong') | Sufficient baseline ($\ge 5$ events), 0 historical logins | Insufficient baseline, fallback to default 22-06 UTC |

### 4.2 Telemetry Traceability Penalties
- **Full Traceability (100%)**: All referenced `eventIds` exist in the active telemetry index.
- **Partial Traceability**: Missing event IDs reduce the confidence score by $20$ points.
- **Contextual Exception Active**: Any match with `contextSuppression` has its evidence strength score reduced by $25$ points and is capped at `Moderate` or `Weak`.

---

## 5. Incident Correlation & Account Separation

Incident correlation operates deterministically:
1. **Account Isolation**: Matches are grouped strictly by `username`. Detections for User A and User B are never merged into a single incident, even if their timestamps coincide or they originate from the same source IP.
2. **Temporal Window Clustering**: Consecutive rule matches for the same account occurring within a $2$-hour window (`DEFAULT_CORRELATION_WINDOW_MS = 7200000`) are correlated into an incident cluster. A gap exceeding $2$ hours cleanly initiates a new incident.
3. **Stable Incident Identifiers**: Incidents receive deterministic identifiers in the format `inc-XXXX-<username>` (e.g. `inc-0001-alice`).

---

## 6. Verification & Test Suite Summary

The Mission 03 implementation was verified through automated test suites covering all required scenarios:

```
Test Files  15 passed (15)
     Tests  179 passed (179)
```

### Key Test Suites:
- `src/engine/investigation.test.ts` (20 tests):
  - Strict ascending and descending chronological sorting.
  - Safe handling of null, missing, empty, and malformed timestamps.
  - Deterministic secondary sort stability.
  - Evidence-strength classification across high/low volume, burst success, and contextual exceptions.
  - Mathematical identity: $\sum \text{contributions} + \text{synergy} = \text{calculateIncidentRiskScore}()$.
  - User-to-host topology building, edge aggregation, privileged asset tagging, and empty destination handling.
  - Incident grouping and strict account separation.
- `src/test/investigationIntegration.test.tsx` (5 tests):
  - Investigation Studio rendering with SVG graph, risk breakdown, timeline, and alert explanations.
  - Table view alternative toggle and interaction.
  - Timeline event selection and Event Inspector drawer.
  - Bidirectional cross-filtering and filter reset.
  - Integration with `IncidentDetailModal` tab system.

---

## 7. Known Operational Limitations

1. **Perimeter Telemetry Gaps**: Authenticators terminating at reverse proxies or perimeter firewalls may not log destination host endpoints. The UserHostGraph explicitly identifies these as external/perimeter events.
2. **Heuristic Nature of Scoring**: Risk scores quantify abnormal behavioral patterns relative to configured rules and historical baselines. They must not be conflated with mathematical probabilities of compromise.
3. **Baseline Depth Sensitivity**: An account with limited baseline training history may trigger `new_ip_location` or `unusual_hours` on benign operational changes. The evidence evaluator explicitly marks these as `Weak`.
