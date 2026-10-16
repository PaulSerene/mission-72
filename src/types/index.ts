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
export type EventOutcome = 'success' | 'failure' | 'timeout' | 'blocked'

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
