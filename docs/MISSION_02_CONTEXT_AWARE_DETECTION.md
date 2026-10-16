# Mission 72 — Mission 02: Context-Aware Alert Detection

> **Operational Specification, Implementation Guide, and Verification Report**  
> *Suspicious Login and Activity Detector — Context-Aware Alert Detection*

---

## 1. Executive Summary

In security operations center (SOC) environments, naive behavioral anomaly detection generates severe alert fatigue. Legitimate operational patterns—such as IT helpdesk personnel traversing dozens of domain controllers and database servers during approved maintenance windows, or travelling employees connecting from corporate VPN ranges—routinely trigger high-severity unfamiliar-host and unfamiliar-location detections.

**Mission 02** introduces **Context-Aware Alert Detection** to the Mission 72 detection engine:
1. **Explicit Security Context**: Validated configuration for authorized helpdesk accounts, account role taxonomies (`admin`, `helpdesk`, `service`, `developer`, `regular`), target host scoping, activity scoping, and declared maintenance windows.
2. **Maintenance-Aware Detection**: Eliminates false positives when authorized helpdesk accounts access multiple unfamiliar hosts during active maintenance windows, while rigorously evaluating out-of-scope actions and regular user behavior.
3. **Approved Corporate VPN Matching**: Integrates bitwise CIDR arithmetic matching to suppress false-positive new-IP/location alerts for legitimate remote workers, without masking credential-stuffing or brute-force attacks.
4. **Transparent Audit Logging & Heuristic Scoring**: Suppressed signals are not discarded; they are recorded with preserved evidence and human-readable operational justifications. Risk scores are bounded [0–100] with explicit de-escalation weights.

---

## 2. Security Context Configuration Schema & Example

The engine extends `AnalysisConfig` with validated, explicit security context fields without creating a competing configuration system.

```typescript
export interface AnalysisConfig {
  timezone: string
  trainingPeriod: TimeWindow
  analysisPeriod: TimeWindow
  approvedVpnCidrs: Array<string | VpnRangeConfig>
  maintenanceWindows: MaintenanceWindow[]
  accountRoles: Record<string, AccountRole>
  authorizedHelpdeskAccounts: string[]
  rules: RuleThresholds
}
```

### Complete Example Configuration (`JSON`)

```json
{
  "timezone": "UTC",
  "trainingPeriod": {
    "start": "2026-10-01T00:00:00Z",
    "end": "2026-10-08T00:00:00Z"
  },
  "analysisPeriod": {
    "start": "2026-10-08T00:00:00Z",
    "end": "2026-10-15T00:00:00Z"
  },
  "approvedVpnCidrs": [
    {
      "cidr": "192.0.2.0/24",
      "id": "VPN-CORP-EAST",
      "description": "Approved Corporate VPN (Remote Workforce)"
    }
  ],
  "maintenanceWindows": [
    {
      "id": "MW-WEEKLY-SUNDAY",
      "description": "Weekly scheduled off-hours system backup and IT maintenance",
      "daysOfWeek": [0],
      "startHour": 2,
      "endHour": 4,
      "timezone": "UTC",
      "allowedUsers": ["svc_backup"],
      "authorizedHelpdeskAccounts": ["helpdesk1", "helpdesk2", "it_support", "helpdesk_bob"],
      "permittedHosts": [
        "dc-primary.corp.local",
        "dc-secondary.corp.local",
        "db-prod-01.corp.local",
        "db-prod-02.corp.local",
        "ldap-auth.corp.local",
        "app-web-01.corp.local",
        "app-web-02.corp.local",
        "app-api-01.corp.local",
        "fs-storage-01.corp.local",
        "ci-runner-01.corp.local"
      ],
      "permittedActivities": ["interactive", "network", "service", "rdp", "ssh", "smb", "authentication"]
    }
  ],
  "accountRoles": {
    "svc_backup": "service",
    "helpdesk1": "helpdesk",
    "helpdesk2": "helpdesk",
    "it_support": "helpdesk",
    "helpdesk_bob": "helpdesk",
    "alice": "regular",
    "bob": "regular",
    "victor": "regular",
    "charlie": "regular",
    "david": "regular",
    "diana": "regular",
    "edward": "developer",
    "frank": "regular"
  },
  "authorizedHelpdeskAccounts": ["helpdesk1", "helpdesk2", "it_support", "helpdesk_bob"],
  "rules": {
    "bruteForce": { "failureCount": 5, "windowSeconds": 120 },
    "burstSuccess": { "failureCount": 3, "windowSeconds": 180 },
    "passwordSpray": { "userCount": 4, "windowSeconds": 300 },
    "unusualHours": { "offHoursStart": 22, "offHoursEnd": 6 },
    "newHosts": { "newHostCount": 4, "windowHours": 4 }
  }
}
```

---

## 3. Maintenance Window Evaluation Architecture

### 3.1 Strict Authorization vs. Username Guessing
**Requirement:** *An account is not authorized merely because its username contains `helpdesk`. Authorization must come from explicit configuration.*

The engine enforces this by checking:
```typescript
const authorized =
  globalHelpdeskAccounts.has(ev.username) ||
  (w.authorizedHelpdeskAccounts?.includes(ev.username) ?? false)
```
If a user named `helpdesk_intruder` is not explicitly listed in `authorizedHelpdeskAccounts`, all unfamiliar-host and unusual-hours detections fire at full severity.

### 3.2 Timezone Normalization and Window Boundaries
Event timestamps (standardized to UTC ISO 8601 strings) are projected into the maintenance window's configured timezone (or the global log timezone) using `Intl.DateTimeFormat`:
- **Hours Range:** Supports both daytime windows (`startHour < endHour`) and overnight windows (`startHour > endHour`, wrapping midnight from e.g. 22:00 to 06:00).
- **Day-of-Week Tracking across Midnight:** For windows crossing midnight (e.g., Sunday 22:00 to Monday 06:00), events occurring between 00:00 and 05:59 on Monday are mapped back to Sunday (`(dayOfWeek + 6) % 7`), matching the declared Sunday window schedule.
- **Strict Boundaries:** Window boundaries are defined as `[startHour, endHour)` — inclusive of the start minute and exclusive of the end minute. An event at 01:58 is outside a 02:00 window; an event at 02:00 is inside; an event at 04:00 is outside.

### 3.3 Four-Point Exemption Check
A maintenance exemption is granted if and only if **all four conditions** are met:
1. **Window Active**: Current event timestamp falls within declared day and hour boundaries.
2. **Explicit Authorization**: Account is configured in `authorizedHelpdeskAccounts`.
3. **Host Scope Permitted**: If `permittedHosts` is configured, `ev.destination` must be an explicit member. Access to unapproved target servers (e.g. `restricted-vault.corp.local`) is **not** exempt.
4. **Activity Scope Permitted**: If `permittedActivities` is configured, `ev.logonType` or `ev.eventType` must match approved administrative protocols.

---

## 4. Corporate VPN Context & Login Detection

### 4.1 Accurate Bitwise CIDR Matching
To avoid false matches and vulnerabilities caused by string-prefix checks (e.g. naive `ip.startsWith("10.0.")`), IP addresses are converted to 32-bit unsigned integers:
```typescript
const ipInt = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0
const inRange = (ipInt & maskInt) === (networkInt & maskInt)
```

### 4.2 Targeted Signal Suppression
- **Rule Scoping**: Matching an approved VPN CIDR suppresses **only** `new_ip_location`.
- **Independence of Threat Rules**: Brute-force (`brute_force`), failure bursts (`burst_success`), and password spraying (`password_spray`) are evaluated completely independently. An attacker launching credential attacks through the corporate VPN is detected immediately.
- **Location Inference Disclaimer**: The detector does **not** treat a corporate VPN address as a user's physical geographic location, nor does VPN access prove that an authentication session is benign.

---

## 5. Active Rules During Maintenance Windows

| Detection Rule | Active During Maintenance? | Context Handling Behavior |
|---|---|---|
| **Brute Force (`brute_force`)** | **YES** (100% active) | Never suppressed. Multiple repeated failures always alert. |
| **Burst Success (`burst_success`)** | **YES** (100% active) | Never suppressed. Failures followed by success indicate credential stuffing or account takeover. |
| **Password Spray (`password_spray`)** | **YES** (100% active) | Never suppressed. One source IP hitting multiple users indicates coordinated attack. |
| **Unusual Hours (`unusual_hours`)** | **Conditional** | Suppressed **only** for users explicitly listed in `allowedUsers` during the window. |
| **New IP / Location (`new_ip_location`)** | **Conditional** | Suppressed if source IP is within `approvedVpnCidrs`. Reduced risk for `developer`/`admin` roles. |
| **New Hosts (`new_hosts`)** | **Conditional** | Suppressed **only** for authorized helpdesk accounts accessing permitted hosts during active maintenance. Regular users or out-of-scope hosts alert normally. |

---

## 6. Heuristic Risk Scoring & Audit Explainability

### 6.1 Composite Score Calculation
Risk scores are bounded $[0, 100]$ and computed deterministically:
$$\text{Score} = \min\left(100, \sum (\text{BaseScore} \times \text{Multiplier}) + \text{SynergyBonus} - \text{OverlapDiscount}\right)$$

- **Context Multiplier**: For de-escalated signals (e.g. helpdesk accessing unfamiliar hosts outside maintenance, or developer travel), a multiplier of $0.5$ or $0.6$ reduces score contribution while retaining incident visibility.
- **Overlap Discount**: Overlapping `brute_force` and `burst_success` on the same event sequence discounts the secondary rule to prevent artificial double-counting.
- **Synergy Bonus**: Observing 3 or more distinct MITRE tactics/rules adds $+15$ risk points.

### 6.2 Suppressed Signals Audit Trail
Every suppressed signal is recorded in `suppressedAlerts`:
```json
{
  "id": "suppressed-maint-host-hd-1",
  "ruleId": "new_hosts",
  "ruleName": "Sudden Access to Many Unfamiliar Hosts",
  "username": "helpdesk_bob",
  "timestamp": "2026-10-11T02:15:00.000Z",
  "policyType": "maintenance_window",
  "reason": "Legitimate helpdesk activity by \"helpdesk_bob\" on permitted host \"dc-primary.corp.local\" during approved maintenance window [MW-WEEKLY-SUNDAY]",
  "evidence": {
    "eventIds": ["hd-1"],
    "description": "Authorized helpdesk multi-host activity on dc-primary.corp.local during approved maintenance window",
    "data": { "destination": "dc-primary.corp.local", "windowId": "MW-WEEKLY-SUNDAY" }
  }
}
```

---

## 7. Synthetic Scenarios: Expected vs. Observed Outcomes

The pipeline was executed against the complete 14-scenario deterministic dataset (Seed: 42, 306 rows).

| Scenario ID | Name & Description | Category | Expected Rule & Outcome | Observed Outcome | Result |
|---|---|---|---|---|---|
| **SCENARIO-01** | Brute force against `victor` (6 failures in 60s) | Threat | `brute_force` → Alert | High-severity incident created (Risk 40) | **PASS** |
| **SCENARIO-02** | Failure burst followed by success for `charlie` | Threat | `burst_success` → Alert | Critical incident created (Risk 55) | **PASS** |
| **SCENARIO-03** | Password spray across 5 accounts from `198.51.100.99` | Threat | `password_spray` → Alert | 5 rule matches correlated (Risk 70) | **PASS** |
| **SCENARIO-04** | Unusual nighttime login for `diana` at 03:15 UTC | Threat | `unusual_hours` → Alert | Medium-severity incident created (Risk 25) | **PASS** |
| **SCENARIO-05** | New IP (`203.0.113.190`) & location login for `edward` | Threat | `new_ip_location` → Alert | Reduced risk (0.5x developer role) (Risk 18) | **PASS** |
| **SCENARIO-06** | Regular user `frank` accesses 5 unfamiliar hosts | Threat | `new_hosts` → Alert | High-severity incident created (Risk 40) | **PASS** |
| **SCENARIO-07** | Benign maintenance backup job for `svc_backup` | Benign Exception | `unusual_hours` → Suppressed | Fully suppressed; logged in audit | **PASS** |
| **SCENARIO-08** | Approved VPN login for `alice_vpn` (`192.0.2.88`) | Benign Exception | `new_ip_location` → Suppressed | Fully suppressed; logged in audit | **PASS** |
| **SCENARIO-09** | Exact duplicate records (3 rows) | Data Hygiene | Deduplicated | Deduplicated in IngestionReport | **PASS** |
| **SCENARIO-10** | Malformed rows (5 lines: missing dates, bad IPs) | Data Hygiene | Rejected | Rejected in `invalidRows` | **PASS** |
| **SCENARIO-11** | Authorized helpdesk `helpdesk_bob` in maintenance (Scenario A) | Benign Exception | `new_hosts` → Suppressed | 0 alerts fired; logged in audit trail | **PASS** |
| **SCENARIO-12** | Out-of-scope helpdesk access outside window (Scenario B) | Threat | `new_hosts` → Alert | Alert fired with context reduction (Risk 24) | **PASS** |
| **SCENARIO-13** | Failure burst for helpdesk during maintenance (Scenario E) | Threat | `burst_success` → Alert | Alert fired; attack not suppressed | **PASS** |
| **SCENARIO-14** | Maintenance window boundary cases (Scenario F) | Boundary Testing | Deterministic boundaries | Correct temporal classification | **PASS** |

---

## 8. Measured False-Positive Impact

Comparing pipeline execution with and without context-aware detection on the standard evaluation dataset:

- **Helpdesk Multi-Host Traversal**:
  - *Baseline Engine (No Context)*: 1 false-positive `new_hosts` alert fired for `helpdesk_bob` during approved maintenance.
  - *Context-Aware Engine*: 0 false-positive alerts fired for `helpdesk_bob` during maintenance. **100% reduction in false positives for authorized maintenance.**
- **Corporate VPN Remote Logins**:
  - *Baseline Engine (No Context)*: 1 false-positive `new_ip_location` alert fired for `alice_vpn`.
  - *Context-Aware Engine*: 0 false-positive alerts fired for approved VPN range `192.0.2.0/24`.
- **Security Invariance (No False Negatives Introduced)**:
  - When `helpdesk_bob` accessed unfamiliar hosts *outside* maintenance (Scenario 12), the alert fired as expected.
  - When `helpdesk_bob` experienced brute-force failures *during* maintenance (Scenario 13), the alert fired as expected.
  - When regular user `frank` accessed unfamiliar hosts (Scenario 06), the alert fired as expected.

---

## 9. Operational Uncertainties & Inherent Limitations

1. **Synthetic Fixtures Notice**: The synthetic test fixtures demonstrate deterministic functional behavior and policy mechanics. They do not constitute an empirical measurement of real-world machine learning precision or detection accuracy across enterprise networks.
2. **IP Geolocation Imprecision**: Mapping IP addresses to geographic cities or countries via GeoIP databases is prone to stale routing tables, mobile carrier proxy routing, and CDN egress hops. A "new location" is a statistical deviation, not conclusive proof of attacker movement.
3. **VPN Incomplete Scoping**: If network administrators fail to register new corporate VPN subnet allocations in `approvedVpnCidrs`, legitimate remote logins will temporarily generate new-IP alerts.
4. **Maintenance Creep**: Blanket exemptions applied to entire accounts can create blind spots. Scoping maintenance windows to explicit `permittedHosts` and `permittedActivities` is strongly recommended.
5. **Credential Compromise through VPN**: Attackers who obtain valid credentials and connect through corporate VPNs bypass `new_ip_location` alerts. Downstream detection relies entirely on behavioral rules (`brute_force`, `unusual_hours`, `new_hosts`).

---

## 10. Dashboard Demonstration Guide

1. **Launch the Application**: Run `npm run dev` and open `http://localhost:5173`.
2. **Load the Seeded Dataset**: Click **"Load Synthetic Demo Dataset"** on the landing banner or in the Load Data panel.
3. **Inspect the Incident Feed**:
   - Notice that `frank` has an active high-severity incident for accessing unfamiliar hosts.
   - Notice that `helpdesk_bob` has an active incident for accessing unfamiliar hosts on Tuesday (outside maintenance), but **none** for Sunday (during maintenance).
   - Click the `helpdesk_bob` incident to open the **Incident Detail Modal**. Notice the orange **"Context Reduced"** badge showing the 60% risk multiplier and contextual rationale.
4. **Inspect Suppressed Signals**:
   - Navigate to the **"Data Quality & Config"** tab.
   - Under the **"Context-Aware Policy Exceptions & Suppressed Signals"** audit log, observe the exact records showing why `alice_vpn` (Corporate VPN) and `helpdesk_bob` (Sunday Maintenance) were suppressed.
5. **Test Dynamic Configuration**:
   - In the **ConfigPanel**, remove `helpdesk_bob` from the Authorized Helpdesk Accounts field.
   - Click **"Apply & Rerun Pipeline"**.
   - Return to the Incident Feed: notice that `helpdesk_bob` now has an alert for the Sunday maintenance activity because explicit authorization was revoked.
