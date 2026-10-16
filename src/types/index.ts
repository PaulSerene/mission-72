/**
 * Core domain types for Mission 72 — Suspicious Activity Detector.
 *
 * These types model the raw data and detection outputs used throughout
 * the application. Keep this file framework-agnostic.
 */

// ─── Raw Log Entry ──────────────────────────────────────────────────────────

/** Severity level of a log event. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

/** Outcome of a login attempt or session action. */
export type EventOutcome = 'success' | 'failure' | 'timeout' | 'blocked' | 'unknown'

/** Categories of events the detector can observe. */
export type EventCategory =
  | 'authentication'
  | 'authorization'
  | 'network'
  | 'file_access'
  | 'process'
  | 'system'

/**
 * A single structured log entry produced by a monitored system.
 * Modelled after common SIEM/syslog fields.
 */
export interface LogEntry {
  /** Unique event identifier. */
  id: string
  /** ISO 8601 timestamp of when the event occurred. */
  timestamp: string
  /** Source IP address (IPv4 or IPv6). */
  sourceIp: string
  /** Destination IP address (if applicable). */
  destinationIp?: string
  /** User account involved in the event. */
  username: string
  /** Category of the event. */
  category: EventCategory
  /** Short human-readable description of the event. */
  message: string
  /** Outcome of the event. */
  outcome: EventOutcome
  /** Geographic location derived from IP (optional, filled by enrichment). */
  geoLocation?: GeoLocation
  /** Raw extra metadata from the originating system. */
  metadata?: Record<string, unknown>
}

// ─── Enrichment ─────────────────────────────────────────────────────────────

/** Geographic location information. */
export interface GeoLocation {
  country: string
  countryCode: string
  city?: string
  latitude?: number
  longitude?: number
}

// ─── Detection Output ────────────────────────────────────────────────────────

/** A rule that fired against one or more log entries. */
export interface DetectionRule {
  /** Machine-readable rule identifier. */
  id: string
  /** Human-readable rule name. */
  name: string
  /** Description of what the rule detects. */
  description: string
  /** Severity assigned to matches. */
  severity: Severity
  /** MITRE ATT&CK tactic tag (optional). */
  mitreTactic?: string
}

/**
 * A single alert produced by the detection engine.
 * Ties one or more log entries to the rule that triggered.
 */
export interface Alert {
  /** Unique alert identifier. */
  id: string
  /** ISO 8601 timestamp of alert creation. */
  timestamp: string
  /** The rule that triggered this alert. */
  rule: DetectionRule
  /** Severity (may be elevated from rule default by risk scoring). */
  severity: Severity
  /** Log entries that contributed to this alert. */
  sourceEvents: LogEntry[]
  /** Short summary for display on the dashboard. */
  summary: string
  /** Whether the alert has been acknowledged by an analyst. */
  acknowledged: boolean
}

// ─── Dashboard State ─────────────────────────────────────────────────────────

/** Aggregate statistics shown on the dashboard. */
export interface DashboardStats {
  totalEvents: number
  totalAlerts: number
  criticalAlerts: number
  highAlerts: number
  acknowledgedAlerts: number
  /** Timestamp of the most recent event processed. */
  lastEventAt: string | null
}

/** Status of the detection engine. */
export type EngineStatus = 'idle' | 'running' | 'paused' | 'error'

// ═══════════════════════════════════════════════════════════════════════════
// ─── Milestone 2: Data Pipeline & Detection Engine Types ─────────────────
// ═══════════════════════════════════════════════════════════════════════════

// ─── Auth Event (normalized output of CSV ingestion) ─────────────────────────

/** Authentication method used for the login. */
export type LogonType =
  | 'interactive'
  | 'network'
  | 'service'
  | 'batch'
  | 'remote_interactive'
  | 'unlock'
  | 'unknown'

/**
 * A single normalized authentication event produced by the ingestion pipeline.
 * This is the primary unit of analysis for detection rules.
 * All timestamps are UTC ISO 8601. Framework-agnostic.
 */
export interface AuthEvent {
  /** Stable, deterministic ID derived from normalized field content. */
  id: string
  /** UTC ISO 8601 timestamp. */
  timestamp: string
  /** Authenticated user account name (never invented — must exist in raw row). */
  username: string
  /** Source IPv4 address. */
  sourceIp: string
  /** Destination host/server name (null if absent in source data). */
  destination: string | null
  /** Event category (normalized from raw event_type/action field). */
  eventType: EventCategory
  /** Login outcome (normalized). */
  outcome: EventOutcome
  /** Logon method (normalized from raw logon_type field). */
  logonType: LogonType
  /**
   * Location label derived from IP-location CIDR mapping.
   * Null until enriched by the analysis pipeline.
   */
  location: string | null
  /** 0-indexed row number in the source CSV (for diagnostics). */
  rawRow: number
  /** True if this event is an exact duplicate of an earlier one in the batch. */
  isDuplicate: boolean
}

// ─── Ingestion Report ────────────────────────────────────────────────────────

/** A row that could not be normalized into a valid AuthEvent. */
export interface InvalidRow {
  /** 0-indexed row number in the source CSV. */
  rowIndex: number
  /** Human-readable reason for rejection. */
  reason: string
  /** Raw field values from PapaParse (for display and diagnostics). */
  raw: Record<string, string>
}

/**
 * Diagnostic for a field that was absent across multiple rows,
 * annotated with which detection rules depend on that field.
 */
export interface MissingFieldDiagnostic {
  /** Canonical field name (e.g. 'destination'). */
  field: string
  /** IDs of detection rules that require this field. */
  requiredByRules: string[]
  /** Number of otherwise-valid rows that were missing this field. */
  affectedRowCount: number
}

/**
 * Summary produced by the CSV ingestion pipeline.
 * Provides a complete picture of data quality before analysis begins.
 */
export interface IngestionReport {
  totalRows: number
  /** Count of rows successfully converted to AuthEvent. */
  validEvents: number
  /** Rows that were rejected (required fields missing/invalid). */
  invalidRows: InvalidRow[]
  /** Count of exact duplicate records (same stable ID) seen more than once. */
  duplicateCount: number
  /** Per-field diagnostics for optional fields that were frequently absent. */
  missingFields: MissingFieldDiagnostic[]
  /** The IANA timezone used to normalize naive timestamps. */
  timezone: string
}

/** Returned by parseAuthCsv — events plus a full quality report. */
export interface IngestionResult {
  /** De-duplicated, normalized events sorted by timestamp (ascending). */
  events: AuthEvent[]
  report: IngestionReport
}

// ─── Assets ──────────────────────────────────────────────────────────────────

/** An entry from the asset inventory CSV. */
export interface AssetRecord {
  /** Normalized lowercase hostname. */
  host: string
  /** Role label (e.g. 'database', 'domain-controller'). */
  role: string
  /** Whether the host holds privileged access (e.g. DCs, LDAP, databases). */
  privileged: boolean
}

/**
 * An IP-to-location mapping entry from the ip_locations CSV.
 * Parsed and pre-computed for O(n) lookup performance.
 */
export interface IpLocationRecord {
  /** Original CIDR string (kept for display). */
  cidr: string
  /** Human-readable location label (e.g. 'Internal/Corporate'). */
  location: string
  /** Pre-computed network address as a 32-bit unsigned integer. */
  networkInt: number
  /** Pre-computed subnet mask as a 32-bit unsigned integer. */
  maskInt: number
}

/** Result of parsing the asset inventory CSV. */
export interface AssetParseResult {
  assets: AssetRecord[]
  invalidRows: { rowIndex: number; reason: string; raw: Record<string, string> }[]
}

/** Result of parsing the IP-location CSV. */
export interface IpLocationParseResult {
  locations: IpLocationRecord[]
  invalidRows: { rowIndex: number; reason: string; raw: Record<string, string> }[]
}

// ─── Behavioral Baselines ─────────────────────────────────────────────────────

/**
 * Quality of baseline data for a user.
 * - 'sufficient': ≥ 5 training events — rules apply normally.
 * - 'limited': 1–4 training events — rules fire but results are noted as low-confidence.
 * - 'none': 0 training events — rules fall back to configured defaults.
 */
export type BaselineStatus = 'sufficient' | 'limited' | 'none'

/**
 * Learned per-user behavioral profile built exclusively from training-period events.
 * Events outside the training window must never influence these values.
 */
export interface UserBaseline {
  username: string
  /** IPs the user successfully authenticated from during training. */
  knownIps: Set<string>
  /** Destination hosts the user accessed during training. */
  knownHosts: Set<string>
  /** Location labels seen during training (from IP-location enrichment). */
  knownLocations: Set<string>
  /**
   * Count of successful logins at each UTC hour (0–23) during training.
   * loginHourCounts[3] = 0 means the user never logged in at 3am UTC during training.
   */
  loginHourCounts: number[]
  /** Total number of training events for this user. */
  trainingEventCount: number
  status: BaselineStatus
}

// ─── Analysis Configuration ───────────────────────────────────────────────────

/** A UTC ISO 8601 time window (start inclusive, end exclusive). */
export interface TimeWindow {
  /** UTC ISO 8601 start timestamp (inclusive). */
  start: string
  /** UTC ISO 8601 end timestamp (exclusive). */
  end: string
}

/**
 * A recurring maintenance window during which certain alerts are suppressed.
 * Times are interpreted in UTC.
 */
export interface MaintenanceWindow {
  /** Days of week (0=Sun, 6=Sat). If absent, applies to all days. */
  daysOfWeek?: number[]
  /** UTC hour at which the window starts (0–23, inclusive). */
  startHour: number
  /** UTC hour at which the window ends (0–23, exclusive). */
  endHour: number
  /**
   * If set, maintenance suppression only applies to events from these usernames.
   * Useful for service accounts that legitimately run during off-hours.
   */
  allowedUsers?: string[]
}

/** Per-rule configurable thresholds. */
export interface RuleThresholds {
  bruteForce: {
    /** Minimum failure count to trigger the rule. */
    failureCount: number
    /** Sliding window duration in seconds. */
    windowSeconds: number
  }
  burstSuccess: {
    /** Minimum failure count before a success to trigger the rule. */
    failureCount: number
    /** Window duration in seconds (failures + success must all fit inside). */
    windowSeconds: number
  }
  passwordSpray: {
    /** Minimum distinct target user count to trigger the rule. */
    userCount: number
    /** Sliding window duration in seconds. */
    windowSeconds: number
  }
  unusualHours: {
    /**
     * Off-hours start (UTC hour, inclusive) for users WITHOUT a baseline.
     * Range wraps midnight: e.g. startHour=22, endHour=6 covers 22:00–05:59.
     */
    offHoursStart: number
    /** Off-hours end (UTC hour, exclusive) for users without a baseline. */
    offHoursEnd: number
  }
  newHosts: {
    /** Minimum number of previously-unseen hosts within the window to trigger. */
    newHostCount: number
    /** Window duration in hours. */
    windowHours: number
  }
}

/** Complete configuration object for the analysis pipeline. */
export interface AnalysisConfig {
  /**
   * IANA timezone name used to interpret naive (no-TZ) timestamps in CSV files.
   * Defaults to 'UTC' if not specified.
   */
  timezone: string
  /**
   * Events inside this window are used to build per-user behavioral baselines.
   * Events outside this window are never used for baseline learning.
   */
  trainingPeriod: TimeWindow
  /**
   * Events inside this window are evaluated by detection rules.
   * Events outside are ingested but not analyzed.
   */
  analysisPeriod: TimeWindow
  /** CIDR ranges for approved VPN infrastructure. New-IP alerts are suppressed for these. */
  approvedVpnCidrs: string[]
  /** Recurring maintenance windows that suppress specific alerts. */
  maintenanceWindows: MaintenanceWindow[]
  /** Per-rule configurable thresholds. */
  rules: RuleThresholds
}

// ─── Detection Results ────────────────────────────────────────────────────────

/**
 * Evidence attached to a rule match.
 * Contains event IDs and human-readable context — never raw credentials.
 */
export interface Evidence {
  /** IDs of AuthEvents that caused this match. */
  eventIds: string[]
  /** One-sentence description of the evidence. */
  description: string
  /** Structured data for UI display (e.g. counts, IP addresses). */
  data?: Record<string, unknown>
}

/**
 * A single rule firing against one or more AuthEvents.
 * Multiple RuleMatches for the same user/time window are correlated into an Incident.
 */
export interface RuleMatch {
  /** Machine-readable rule ID (e.g. 'brute_force'). */
  ruleId: string
  /** Human-readable rule name. */
  ruleName: string
  severity: Severity
  /** The primary affected user account. */
  username: string
  /** UTC ISO 8601 timestamp of the first event in this match. */
  timestamp: string
  evidence: Evidence
  /** MITRE ATT&CK tactic (optional). */
  mitreTactic?: string
}

/**
 * A correlated incident grouping one or more RuleMatches for the same user
 * and overlapping time window.
 *
 * Risk scores are bounded to [0, 100] and should be treated as explainable
 * heuristic scores — NOT as probabilities of compromise.
 */
export interface Incident {
  /** Unique incident identifier. */
  id: string
  /** Primary affected user (or source IP label for cross-user incidents). */
  username: string
  /** UTC ISO 8601 start timestamp of the earliest contributing event. */
  startTimestamp: string
  /** UTC ISO 8601 end timestamp of the latest contributing event. */
  endTimestamp: string
  /** All rule matches that contributed to this incident. */
  ruleMatches: RuleMatch[]
  /**
   * Heuristic risk score in [0, 100].
   * Higher values indicate more indicators of compromise.
   * Multiple rule matches are additive but capped at 100.
   */
  riskScore: number
  severity: Severity
  /** Concise English explanation suitable for display to an analyst. */
  explanation: string
  /** Recommended initial triage step. */
  recommendedTriage: string
}

/**
 * Complete output of the analysis pipeline.
 */
export interface AnalysisResult {
  /** Correlated incidents (one or more rule matches, deduplicated). */
  incidents: Incident[]
  /** All individual rule matches before correlation (superset of incident matches). */
  ruleMatches: RuleMatch[]
  /**
   * Usernames for whom training data was absent or insufficient.
   * Alerts for these users carry lower confidence.
   */
  insufficientBaselineUsers: string[]
}
