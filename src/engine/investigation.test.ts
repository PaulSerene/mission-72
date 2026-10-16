/**
 * Unit tests for Mission 03 Investigation Engine:
 * - Chronological event sorting (handling valid, missing, or malformed timestamps)
 * - Deterministic evidence-strength evaluation
 * - User-to-host topology graph data generation
 * - Risk contributors, diminishing repetitions, overlap discounting, and context adjustments
 * - Incident grouping and account separation
 * - Normal vs suspicious log separation
 * - Empty and malformed data resilience
 */

import { describe, expect, it } from 'vitest'
import {
  sortEventsChronologically,
  evaluateEvidenceStrength,
  buildUserHostGraphData,
  safeParseTime,
} from './investigation'
import {
  decomposeIncidentRiskScore,
  calculateIncidentRiskScore,
  correlateIncidents,
} from './incidents'
import type { AuthEvent, RuleMatch, AssetRecord, Incident } from '@/types'

// ─── Test Helpers ─────────────────────────────────────────────────────────────

function makeAuthEvent(overrides: Partial<AuthEvent> = {}): AuthEvent {
  return {
    id: 'ev-test-1',
    timestamp: '2026-10-10T12:00:00Z',
    username: 'alice',
    sourceIp: '198.51.100.10',
    destination: 'app-srv-01',
    eventType: 'authentication',
    outcome: 'failure',
    logonType: 'interactive',
    location: 'External',
    rawRow: 1,
    isDuplicate: false,
    ...overrides,
  }
}

function makeRuleMatch(overrides: Partial<RuleMatch> = {}): RuleMatch {
  return {
    ruleId: 'brute_force',
    ruleName: 'Brute Force Authentication',
    severity: 'high',
    username: 'alice',
    timestamp: '2026-10-10T12:00:00Z',
    evidence: {
      eventIds: ['ev-test-1', 'ev-test-2', 'ev-test-3', 'ev-test-4', 'ev-test-5'],
      description: '5 consecutive authentication failures observed for alice',
    },
    ...overrides,
  }
}

// ─── Chronological Ordering Tests ─────────────────────────────────────────────

describe('safeParseTime & sortEventsChronologically', () => {
  it('correctly parses valid ISO timestamps into epoch milliseconds', () => {
    expect(safeParseTime('2026-10-10T12:00:00Z')).toBe(new Date('2026-10-10T12:00:00Z').getTime())
  })

  it('safely returns null for missing, null, undefined, or malformed timestamps', () => {
    expect(safeParseTime(null)).toBeNull()
    expect(safeParseTime(undefined)).toBeNull()
    expect(safeParseTime('')).toBeNull()
    expect(safeParseTime('not-a-date')).toBeNull()
  })

  it('sorts events in strict chronological order (ascending)', () => {
    const ev1 = makeAuthEvent({ id: 'ev-1', timestamp: '2026-10-10T10:00:00Z', rawRow: 1 })
    const ev2 = makeAuthEvent({ id: 'ev-2', timestamp: '2026-10-10T12:00:00Z', rawRow: 2 })
    const ev3 = makeAuthEvent({ id: 'ev-3', timestamp: '2026-10-10T08:00:00Z', rawRow: 3 })

    const sorted = sortEventsChronologically([ev1, ev2, ev3], 'asc')
    expect(sorted.map(e => e.id)).toEqual(['ev-3', 'ev-1', 'ev-2'])
  })

  it('sorts events in reverse chronological order (descending)', () => {
    const ev1 = makeAuthEvent({ id: 'ev-1', timestamp: '2026-10-10T10:00:00Z', rawRow: 1 })
    const ev2 = makeAuthEvent({ id: 'ev-2', timestamp: '2026-10-10T12:00:00Z', rawRow: 2 })
    const ev3 = makeAuthEvent({ id: 'ev-3', timestamp: '2026-10-10T08:00:00Z', rawRow: 3 })

    const sorted = sortEventsChronologically([ev1, ev2, ev3], 'desc')
    expect(sorted.map(e => e.id)).toEqual(['ev-2', 'ev-1', 'ev-3'])
  })

  it('safely places events with missing or malformed timestamps at the end without throwing', () => {
    const evValid1 = makeAuthEvent({ id: 'ev-valid-1', timestamp: '2026-10-10T10:00:00Z' })
    const evValid2 = makeAuthEvent({ id: 'ev-valid-2', timestamp: '2026-10-10T11:00:00Z' })
    const evBad1 = makeAuthEvent({ id: 'ev-bad-1', timestamp: 'malformed-date', rawRow: 10 })
    const evBad2 = makeAuthEvent({ id: 'ev-bad-2', timestamp: '', rawRow: 11 })

    const sorted = sortEventsChronologically([evBad1, evValid2, evBad2, evValid1], 'asc')
    expect(sorted[0].id).toBe('ev-valid-1')
    expect(sorted[1].id).toBe('ev-valid-2')
    expect(sorted[2].id).toBe('ev-bad-1')
    expect(sorted[3].id).toBe('ev-bad-2')
  })

  it('maintains deterministic secondary sort when timestamps are identical', () => {
    const evA = makeAuthEvent({ id: 'ev-A', timestamp: '2026-10-10T10:00:00Z', rawRow: 5 })
    const evB = makeAuthEvent({ id: 'ev-B', timestamp: '2026-10-10T10:00:00Z', rawRow: 2 })

    const sorted = sortEventsChronologically([evA, evB], 'asc')
    expect(sorted.map(e => e.id)).toEqual(['ev-B', 'ev-A'])
  })
})

// ─── Evidence Strength Classification Tests ───────────────────────────────────

describe('evaluateEvidenceStrength', () => {
  it('classifies high-volume brute force (>= 10 attempts) as Strong', () => {
    const eventIds = Array.from({ length: 12 }, (_, i) => `ev-${i + 1}`)
    const resolvedEvents = eventIds.map(id => makeAuthEvent({ id, outcome: 'failure' }))
    const match = makeRuleMatch({
      ruleId: 'brute_force',
      evidence: { eventIds, description: '12 failed attempts' },
    })

    const evalResult = evaluateEvidenceStrength(match, resolvedEvents, 'sufficient')
    expect(evalResult.level).toBe('Strong')
    expect(evalResult.allEventsResolved).toBe(true)
    expect(evalResult.resolvedEventCount).toBe(12)
    expect(evalResult.criteria.some(c => c.includes('High failure volume'))).toBe(true)
  })

  it('classifies burst success with >= 4 prior failures as Strong', () => {
    const failEvents = Array.from({ length: 4 }, (_, i) => makeAuthEvent({ id: `ev-f-${i}`, outcome: 'failure' }))
    const successEvent = makeAuthEvent({ id: 'ev-succ', outcome: 'success' })
    const allEvents = [...failEvents, successEvent]

    const match = makeRuleMatch({
      ruleId: 'burst_success',
      evidence: { eventIds: allEvents.map(e => e.id), description: '4 failures followed by success' },
    })

    const evalResult = evaluateEvidenceStrength(match, allEvents, 'sufficient')
    expect(evalResult.level).toBe('Strong')
    expect(evalResult.criteria.some(c => c.includes('Multi-event progression'))).toBe(true)
  })

  it('penalizes evidence strength when referenced events cannot be resolved in telemetry', () => {
    const match = makeRuleMatch({
      ruleId: 'brute_force',
      evidence: { eventIds: ['ev-1', 'ev-2', 'ev-3', 'ev-4', 'ev-5'], description: '5 events' },
    })
    // Only 1 of 5 events exists in the dataset
    const resolvedEvents = [makeAuthEvent({ id: 'ev-1' })]

    const evalResult = evaluateEvidenceStrength(match, resolvedEvents, 'sufficient')
    expect(evalResult.allEventsResolved).toBe(false)
    expect(evalResult.resolvedEventCount).toBe(1)
    expect(evalResult.totalEventCount).toBe(5)
    expect(evalResult.level).not.toBe('Strong')
  })

  it('de-escalates evidence strength when contextual exception is present', () => {
    const eventIds = Array.from({ length: 6 }, (_, i) => `ev-${i}`)
    const resolvedEvents = eventIds.map(id => makeAuthEvent({ id }))
    const match = makeRuleMatch({
      ruleId: 'brute_force',
      evidence: { eventIds, description: '6 events' },
      contextSuppression: {
        reason: 'Authorized penetration testing maintenance window',
        scoreMultiplier: 0.5,
      },
    })

    const evalResult = evaluateEvidenceStrength(match, resolvedEvents, 'sufficient')
    expect(evalResult.criteria.some(c => c.includes('Contextual exception active'))).toBe(true)
    expect(evalResult.score).toBeLessThan(75) // Not classified as Strong due to contextual discount
  })

  it('evaluates baseline confidence appropriately for unusual hours', () => {
    const ev = makeAuthEvent({ id: 'ev-1' })
    const match = makeRuleMatch({
      ruleId: 'unusual_hours',
      evidence: { eventIds: ['ev-1'], description: 'Off-hours login' },
    })

    const withBaseline = evaluateEvidenceStrength(match, [ev], 'sufficient')
    const withoutBaseline = evaluateEvidenceStrength(match, [ev], 'none')

    expect(withBaseline.score).toBeGreaterThan(withoutBaseline.score)
    expect(withoutBaseline.level).toBe('Weak')
    expect(withoutBaseline.criteria.some(c => c.includes('Default off-hours window'))).toBe(true)
  })
})

// ─── Risk Decomposition & Mathematical Fidelity Tests ────────────────────────

describe('decomposeIncidentRiskScore', () => {
  it('mathematically decomposes single rule matches faithfully', () => {
    const match = makeRuleMatch({ ruleId: 'brute_force' })
    const breakdown = decomposeIncidentRiskScore([match])

    expect(breakdown.finalScore).toBe(40)
    expect(breakdown.contributions).toHaveLength(1)
    expect(breakdown.contributions[0].ruleId).toBe('brute_force')
    expect(breakdown.contributions[0].baseScore).toBe(40)
    expect(breakdown.contributions[0].finalContribution).toBe(40)
    expect(breakdown.synergyBonus).toBe(0)
    expect(breakdown.finalScore).toBe(calculateIncidentRiskScore([match]))
  })

  it('accurately exposes diminishing returns on repeated firings of the same rule', () => {
    const matches = [
      makeRuleMatch({ ruleId: 'brute_force' }),
      makeRuleMatch({ ruleId: 'brute_force' }),
      makeRuleMatch({ ruleId: 'brute_force' }),
    ]
    const breakdown = decomposeIncidentRiskScore(matches)

    expect(breakdown.contributions).toHaveLength(3)
    // 1st occurrence: 40 * 1.0 = 40
    expect(breakdown.contributions[0].repetitionCount).toBe(1)
    expect(breakdown.contributions[0].finalContribution).toBe(40)

    // 2nd occurrence: 40 * 0.4 = 16
    expect(breakdown.contributions[1].repetitionCount).toBe(2)
    expect(breakdown.contributions[1].finalContribution).toBe(16)

    // 3rd occurrence: 40 * 0.2 = 8
    expect(breakdown.contributions[2].repetitionCount).toBe(3)
    expect(breakdown.contributions[2].finalContribution).toBe(8)

    // Total: 40 + 16 + 8 = 64
    expect(breakdown.finalScore).toBe(64)
    expect(breakdown.finalScore).toBe(calculateIncidentRiskScore(matches))
  })

  it('exposes overlap deduction when burst_success and brute_force share event sequences', () => {
    const sharedIds = ['ev-1', 'ev-2', 'ev-3']
    const matches = [
      makeRuleMatch({ ruleId: 'burst_success', evidence: { eventIds: sharedIds, description: 'burst' } }),
      makeRuleMatch({ ruleId: 'brute_force', evidence: { eventIds: sharedIds, description: 'bf' } }),
    ]
    const breakdown = decomposeIncidentRiskScore(matches)

    const burstContrib = breakdown.contributions.find(c => c.ruleId === 'burst_success')
    const bfContrib = breakdown.contributions.find(c => c.ruleId === 'brute_force')

    expect(burstContrib?.finalContribution).toBe(55)
    expect(bfContrib?.overlapDiscounted).toBe(true)
    expect(bfContrib?.finalContribution).toBe(15) // discounted secondary brute force
    expect(breakdown.finalScore).toBe(70)
    expect(breakdown.finalScore).toBe(calculateIncidentRiskScore(matches))
  })

  it('calculates multi-rule synergy bonus (+15) when 3 or more distinct rules fire', () => {
    const matches = [
      makeRuleMatch({ ruleId: 'brute_force' }),
      makeRuleMatch({ ruleId: 'new_hosts' }),
      makeRuleMatch({ ruleId: 'unusual_hours' }),
    ]
    const breakdown = decomposeIncidentRiskScore(matches)

    expect(breakdown.distinctRuleCount).toBe(3)
    expect(breakdown.synergyBonus).toBe(15)
    // 40 (brute_force) + 40 (new_hosts) + 25 (unusual_hours) = 105 + 15 = 120 -> capped at 100
    expect(breakdown.rawCalculatedScore).toBe(120)
    expect(breakdown.cappedAt100).toBe(true)
    expect(breakdown.finalScore).toBe(100)
    expect(breakdown.finalScore).toBe(calculateIncidentRiskScore(matches))
  })

  it('handles empty matches safely', () => {
    const breakdown = decomposeIncidentRiskScore([])
    expect(breakdown.finalScore).toBe(0)
    expect(breakdown.contributions).toHaveLength(0)
    expect(breakdown.synergyBonus).toBe(0)
    expect(breakdown.cappedAt100).toBe(false)
  })
})

// ─── User-to-Host Graph Topology Tests ────────────────────────────────────────

describe('buildUserHostGraphData', () => {
  const sampleIncident: Incident = {
    id: 'inc-0001-alice',
    username: 'alice',
    startTimestamp: '2026-10-10T10:00:00Z',
    endTimestamp: '2026-10-10T11:00:00Z',
    ruleMatches: [
      makeRuleMatch({
        evidence: { eventIds: ['ev-1', 'ev-2', 'ev-3', 'ev-4'], description: 'test match' },
      }),
    ],
    riskScore: 75,
    severity: 'high',
    explanation: 'Test incident',
    recommendedTriage: 'Verify activity',
  }

  const sampleAssets: AssetRecord[] = [
    { host: 'dc-primary.corp.local', role: 'domain-controller', privileged: true },
    { host: 'db-prod.corp.local', role: 'database', privileged: true },
    { host: 'app-web-01.corp.local', role: 'web-server', privileged: false },
  ]

  it('correctly aggregates multiple destination hosts, privileged flags, and outcomes', () => {
    const events: AuthEvent[] = [
      makeAuthEvent({ id: 'ev-1', destination: 'dc-primary.corp.local', outcome: 'failure' }),
      makeAuthEvent({ id: 'ev-2', destination: 'dc-primary.corp.local', outcome: 'failure' }),
      makeAuthEvent({ id: 'ev-3', destination: 'db-prod.corp.local', outcome: 'success' }),
      makeAuthEvent({ id: 'ev-4', destination: 'app-web-01.corp.local', outcome: 'success' }),
    ]

    const graph = buildUserHostGraphData(sampleIncident, events, sampleAssets)

    expect(graph.userNode.label).toBe('alice')
    expect(graph.hostNodes).toHaveLength(3)
    expect(graph.edges).toHaveLength(3)

    // DC primary host verification
    const dcNode = graph.hostNodes.find(h => h.label === 'dc-primary.corp.local')
    expect(dcNode).toBeDefined()
    expect(dcNode?.role).toBe('domain-controller')
    expect(dcNode?.isPrivileged).toBe(true)
    expect(dcNode?.eventCount).toBe(2)
    expect(dcNode?.failureCount).toBe(2)

    // DB host verification
    const dbNode = graph.hostNodes.find(h => h.label === 'db-prod.corp.local')
    expect(dbNode?.isPrivileged).toBe(true)
    expect(dbNode?.successCount).toBe(1)

    // Edge verification
    const dcEdge = graph.edges.find(e => e.targetHost === 'dc-primary.corp.local')
    expect(dcEdge?.eventCount).toBe(2)
    expect(dcEdge?.failureCount).toBe(2)
  })

  it('handles events with null/unspecified destination endpoints gracefully', () => {
    const perimeterEvents: AuthEvent[] = [
      makeAuthEvent({ id: 'ev-1', destination: null }),
      makeAuthEvent({ id: 'ev-2', destination: '' }),
    ]

    const graph = buildUserHostGraphData(sampleIncident, perimeterEvents, sampleAssets)
    expect(graph.hostNodes).toHaveLength(0)
    expect(graph.edges).toHaveLength(0)
    expect(graph.unspecifiedDestinationCount).toBe(2)
  })
})

// ─── Incident Grouping & Account Separation Tests ─────────────────────────────

describe('Incident Grouping & Account Separation', () => {
  it('does NOT merge events for different user accounts into the same incident', () => {
    const matches: RuleMatch[] = [
      makeRuleMatch({ username: 'alice', timestamp: '2026-10-10T10:00:00Z', ruleId: 'brute_force' }),
      makeRuleMatch({ username: 'bob', timestamp: '2026-10-10T10:05:00Z', ruleId: 'brute_force' }),
    ]

    const incidents = correlateIncidents(matches)
    expect(incidents).toHaveLength(2)
    expect(incidents.map(i => i.username)).toContain('alice')
    expect(incidents.map(i => i.username)).toContain('bob')
  })

  it('correlates multiple detections for the same user within the temporal window', () => {
    const matches: RuleMatch[] = [
      makeRuleMatch({ username: 'alice', timestamp: '2026-10-10T10:00:00Z', ruleId: 'brute_force' }),
      makeRuleMatch({ username: 'alice', timestamp: '2026-10-10T10:30:00Z', ruleId: 'burst_success' }),
      makeRuleMatch({ username: 'alice', timestamp: '2026-10-10T11:00:00Z', ruleId: 'new_hosts' }),
    ]

    const incidents = correlateIncidents(matches)
    expect(incidents).toHaveLength(1)
    expect(incidents[0].username).toBe('alice')
    expect(incidents[0].ruleMatches).toHaveLength(3)
    expect(incidents[0].startTimestamp).toBe('2026-10-10T10:00:00Z')
    expect(incidents[0].endTimestamp).toBe('2026-10-10T11:00:00Z')
  })
})
