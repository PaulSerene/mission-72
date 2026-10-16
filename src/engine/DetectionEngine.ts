/**
 * Detection Engine — Mission 72
 *
 * The engine receives log entries and evaluates them against registered
 * detection rules to produce alerts. Rules are plain functions with a
 * defined interface, making them easy to unit-test in isolation.
 *
 * This module is intentionally framework-agnostic (no React imports).
 */

import type { Alert, DetectionRule, EngineStatus, LogEntry, Severity } from '@/types'

// ─── Rule Interface ───────────────────────────────────────────────────────────

/**
 * A detection rule evaluator.
 * Receives a batch of recent log entries and returns any alerts triggered.
 */
export interface RuleEvaluator {
  rule: DetectionRule
  evaluate: (entries: LogEntry[], history: LogEntry[]) => Alert[]
}

// ─── Engine ───────────────────────────────────────────────────────────────────

/**
 * Options for creating a DetectionEngine instance.
 */
export interface EngineOptions {
  /** Maximum number of log entries to retain in the sliding window. */
  historyLimit?: number
}

/**
 * The core detection engine.
 *
 * Usage:
 * ```ts
 * const engine = new DetectionEngine()
 * engine.register(myRule)
 * const alerts = engine.ingest([logEntry1, logEntry2])
 * ```
 */
export class DetectionEngine {
  private rules: RuleEvaluator[] = []
  private history: LogEntry[] = []
  private _status: EngineStatus = 'idle'
  private readonly historyLimit: number

  constructor(options: EngineOptions = {}) {
    this.historyLimit = options.historyLimit ?? 10_000
  }

  // ── Status ──────────────────────────────────────────────────────────────────

  get status(): EngineStatus {
    return this._status
  }

  // ── Rule Registration ────────────────────────────────────────────────────────

  /** Register a rule evaluator with the engine. */
  register(evaluator: RuleEvaluator): this {
    this.rules.push(evaluator)
    return this
  }

  /** Remove all registered rules (useful in tests). */
  clearRules(): this {
    this.rules = []
    return this
  }

  // ── Ingestion ────────────────────────────────────────────────────────────────

  /**
   * Ingest new log entries and run all registered rules against them.
   * Returns an array of alerts produced by this batch.
   */
  ingest(entries: LogEntry[]): Alert[] {
    if (entries.length === 0) return []

    this._status = 'running'
    const alerts: Alert[] = []

    try {
      for (const evaluator of this.rules) {
        const produced = evaluator.evaluate(entries, this.history)
        alerts.push(...produced)
      }

      // Append new entries to history and trim to the limit
      this.history = [...this.history, ...entries].slice(-this.historyLimit)
      this._status = 'idle'
    } catch (err) {
      this._status = 'error'
      throw err
    }

    return alerts
  }

  /** Return a copy of the current log history. */
  getHistory(): LogEntry[] {
    return [...this.history]
  }

  /** Clear all retained history (e.g. on reset). */
  clearHistory(): this {
    this.history = []
    return this
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Generate a random UUID-like alert ID (crypto.randomUUID when available). */
export function generateId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID()
  }
  // Fallback for environments without crypto.randomUUID
  return `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`
}

/** Create a minimal Alert object from a rule and matching log entries. */
export function buildAlert(
  rule: DetectionRule,
  sourceEvents: LogEntry[],
  summary: string,
  overrideSeverity?: Severity,
): Alert {
  return {
    id: generateId(),
    timestamp: new Date().toISOString(),
    rule,
    severity: overrideSeverity ?? rule.severity,
    sourceEvents,
    summary,
    acknowledged: false,
  }
}
