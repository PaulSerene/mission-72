/**
 * Unit tests for DetectionEngine — Mission 72
 */

import { describe, expect, it, vi } from 'vitest'
import { DetectionEngine, buildAlert, generateId } from '@/engine/DetectionEngine'
import type { LogEntry, Alert } from '@/types'

// ─── Fixtures ────────────────────────────────────────────────────────────────

function makeLogEntry(overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    id: generateId(),
    timestamp: new Date().toISOString(),
    sourceIp: '192.168.1.100',
    username: 'alice',
    category: 'authentication',
    message: 'Login attempt',
    outcome: 'success',
    ...overrides,
  }
}

// ─── generateId ──────────────────────────────────────────────────────────────

describe('generateId', () => {
  it('returns a non-empty string', () => {
    expect(typeof generateId()).toBe('string')
    expect(generateId().length).toBeGreaterThan(0)
  })

  it('returns unique values', () => {
    const ids = Array.from({ length: 100 }, generateId)
    const unique = new Set(ids)
    expect(unique.size).toBe(100)
  })
})

// ─── buildAlert ──────────────────────────────────────────────────────────────

describe('buildAlert', () => {
  const rule = {
    id: 'rule-001',
    name: 'Test Rule',
    description: 'A rule for testing.',
    severity: 'high' as const,
  }

  it('creates an alert with the correct rule and summary', () => {
    const entries = [makeLogEntry()]
    const alert = buildAlert(rule, entries, 'Test alert summary')

    expect(alert.rule).toBe(rule)
    expect(alert.summary).toBe('Test alert summary')
    expect(alert.severity).toBe('high')
    expect(alert.acknowledged).toBe(false)
    expect(alert.sourceEvents).toEqual(entries)
  })

  it('respects overrideSeverity', () => {
    const entries = [makeLogEntry()]
    const alert = buildAlert(rule, entries, 'Critical override', 'critical')
    expect(alert.severity).toBe('critical')
  })

  it('sets a valid ISO timestamp', () => {
    const alert = buildAlert(rule, [], 'No events')
    expect(() => new Date(alert.timestamp)).not.toThrow()
    expect(new Date(alert.timestamp).toISOString()).toBe(alert.timestamp)
  })
})

// ─── DetectionEngine ─────────────────────────────────────────────────────────

describe('DetectionEngine', () => {
  it('starts with idle status', () => {
    const engine = new DetectionEngine()
    expect(engine.status).toBe('idle')
  })

  it('returns no alerts when no rules are registered', () => {
    const engine = new DetectionEngine()
    const alerts = engine.ingest([makeLogEntry()])
    expect(alerts).toEqual([])
  })

  it('returns no alerts when ingesting an empty batch', () => {
    const engine = new DetectionEngine()
    const mockEvaluate = vi.fn().mockReturnValue([])
    engine.register({
      rule: { id: 'r1', name: 'R1', description: '', severity: 'low' },
      evaluate: mockEvaluate,
    })
    const alerts = engine.ingest([])
    expect(alerts).toEqual([])
    expect(mockEvaluate).not.toHaveBeenCalled()
  })

  it('calls registered rule evaluators with correct arguments', () => {
    const engine = new DetectionEngine()
    const entry = makeLogEntry()
    const mockEvaluate = vi.fn().mockReturnValue([])

    engine.register({
      rule: { id: 'r1', name: 'R1', description: '', severity: 'low' },
      evaluate: mockEvaluate,
    })

    engine.ingest([entry])

    expect(mockEvaluate).toHaveBeenCalledOnce()
    expect(mockEvaluate).toHaveBeenCalledWith([entry], [])
  })

  it('accumulates history across multiple ingest calls', () => {
    const engine = new DetectionEngine()
    const entry1 = makeLogEntry({ id: 'e1' })
    const entry2 = makeLogEntry({ id: 'e2' })

    engine.ingest([entry1])
    engine.ingest([entry2])

    const history = engine.getHistory()
    expect(history).toHaveLength(2)
    expect(history.map((e) => e.id)).toEqual(['e1', 'e2'])
  })

  it('passes accumulated history to rule evaluators on subsequent calls', () => {
    const engine = new DetectionEngine()
    const entry1 = makeLogEntry({ id: 'e1' })
    const entry2 = makeLogEntry({ id: 'e2' })
    const capturedHistories: LogEntry[][] = []

    engine.register({
      rule: { id: 'r1', name: 'R1', description: '', severity: 'low' },
      evaluate: (_entries, history) => {
        capturedHistories.push([...history])
        return []
      },
    })

    engine.ingest([entry1])
    engine.ingest([entry2])

    expect(capturedHistories[0]).toHaveLength(0)     // first call: no prior history
    expect(capturedHistories[1]).toHaveLength(1)     // second call: entry1 in history
    expect(capturedHistories[1][0].id).toBe('e1')
  })

  it('collects alerts from multiple rules', () => {
    const engine = new DetectionEngine()
    const entry = makeLogEntry()

    const alertA: Alert = buildAlert(
      { id: 'r1', name: 'Rule A', description: '', severity: 'high' },
      [entry],
      'Alert A',
    )
    const alertB: Alert = buildAlert(
      { id: 'r2', name: 'Rule B', description: '', severity: 'medium' },
      [entry],
      'Alert B',
    )

    engine.register({ rule: alertA.rule, evaluate: () => [alertA] })
    engine.register({ rule: alertB.rule, evaluate: () => [alertB] })

    const alerts = engine.ingest([entry])
    expect(alerts).toHaveLength(2)
    expect(alerts).toContain(alertA)
    expect(alerts).toContain(alertB)
  })

  it('enforces the history limit', () => {
    const engine = new DetectionEngine({ historyLimit: 5 })
    const entries = Array.from({ length: 8 }, (_, i) => makeLogEntry({ id: `e${i}` }))

    engine.ingest(entries)

    const history = engine.getHistory()
    expect(history).toHaveLength(5)
    expect(history[0].id).toBe('e3') // oldest retained
    expect(history[4].id).toBe('e7') // newest
  })

  it('clears history on clearHistory()', () => {
    const engine = new DetectionEngine()
    engine.ingest([makeLogEntry()])
    engine.clearHistory()
    expect(engine.getHistory()).toHaveLength(0)
  })

  it('supports method chaining on register and clearRules', () => {
    const engine = new DetectionEngine()
    const evaluator = {
      rule: { id: 'r1', name: 'R1', description: '', severity: 'low' as const },
      evaluate: () => [] as Alert[],
    }
    const result = engine.register(evaluator).clearRules()
    expect(result).toBe(engine)

    // After clearRules, no alerts produced
    expect(engine.ingest([makeLogEntry()])).toEqual([])
  })

  it('returns idle status after a successful ingest', () => {
    const engine = new DetectionEngine()
    engine.ingest([makeLogEntry()])
    expect(engine.status).toBe('idle')
  })
})
