/**
 * Unit tests for Incident Correlation & Risk Scoring — Mission 72
 */

import { describe, expect, it } from 'vitest'
import {
  correlateIncidents,
  calculateIncidentRiskScore,
  scoreToSeverity,
  generateExplanation,
  generateRecommendedTriage,
} from './incidents'
import type { RuleMatch } from '@/types'

function makeMatch(overrides: Partial<RuleMatch> = {}): RuleMatch {
  return {
    ruleId: 'unusual_hours',
    ruleName: 'Login During Unusual Hours',
    severity: 'medium',
    username: 'alice',
    timestamp: '2026-10-09T10:00:00Z',
    evidence: {
      eventIds: ['ev-1'],
      description: 'Login during unusual hours for alice',
    },
    ...overrides,
  }
}

describe('correlateIncidents', () => {
  it('groups multiple rule matches for the same user within correlation window into one incident', () => {
    const matches: RuleMatch[] = [
      makeMatch({
        ruleId: 'unusual_hours',
        timestamp: '2026-10-09T10:00:00Z',
        username: 'alice',
      }),
      makeMatch({
        ruleId: 'new_ip_location',
        timestamp: '2026-10-09T10:15:00Z',
        username: 'alice',
      }),
    ]

    const incidents = correlateIncidents(matches)
    expect(incidents).toHaveLength(1)
    expect(incidents[0].username).toBe('alice')
    expect(incidents[0].ruleMatches).toHaveLength(2)
    expect(incidents[0].startTimestamp).toBe('2026-10-09T10:00:00Z')
    expect(incidents[0].endTimestamp).toBe('2026-10-09T10:15:00Z')
  })

  it('separates matches for the same user when gap exceeds correlation window', () => {
    const matches: RuleMatch[] = [
      makeMatch({
        ruleId: 'unusual_hours',
        timestamp: '2026-10-09T10:00:00Z', // Day 1
        username: 'alice',
      }),
      makeMatch({
        ruleId: 'new_ip_location',
        timestamp: '2026-10-11T10:00:00Z', // 48h later
        username: 'alice',
      }),
    ]

    const incidents = correlateIncidents(matches)
    expect(incidents).toHaveLength(2)
  })

  it('separates incidents across different users', () => {
    const matches: RuleMatch[] = [
      makeMatch({ username: 'alice', timestamp: '2026-10-09T10:00:00Z' }),
      makeMatch({ username: 'bob', timestamp: '2026-10-09T10:05:00Z' }),
    ]

    const incidents = correlateIncidents(matches)
    expect(incidents).toHaveLength(2)
    expect(new Set(incidents.map(i => i.username))).toEqual(new Set(['alice', 'bob']))
  })
})

describe('calculateIncidentRiskScore & Overlap Prevention', () => {
  it('bounds risk score strictly between 0 and 100', () => {
    const manyMatches: RuleMatch[] = [
      makeMatch({ ruleId: 'burst_success' }),
      makeMatch({ ruleId: 'brute_force' }),
      makeMatch({ ruleId: 'new_hosts' }),
      makeMatch({ ruleId: 'new_ip_location' }),
      makeMatch({ ruleId: 'unusual_hours' }),
      makeMatch({ ruleId: 'password_spray' }),
    ]

    const score = calculateIncidentRiskScore(manyMatches)
    expect(score).toBeLessThanOrEqual(100)
    expect(score).toBeGreaterThanOrEqual(0)
    expect(score).toBe(100)
  })

  it('discounts overlapping brute_force when burst_success is present on the same event sequence', () => {
    const sharedEvents = ['ev-1', 'ev-2', 'ev-3']

    // Isolated burst_success (base 55)
    const singleBurst = [makeMatch({ ruleId: 'burst_success', evidence: { eventIds: sharedEvents, description: '' } })]
    const burstScore = calculateIncidentRiskScore(singleBurst)
    expect(burstScore).toBe(55)

    // Overlapping brute_force + burst_success on shared events
    const overlapMatches = [
      makeMatch({ ruleId: 'burst_success', evidence: { eventIds: sharedEvents, description: '' } }),
      makeMatch({ ruleId: 'brute_force', evidence: { eventIds: sharedEvents, description: '' } }),
    ]
    const overlapScore = calculateIncidentRiskScore(overlapMatches)

    // Without overlap discount it would be 55 + 40 = 95.
    // With overlap discount brute_force adds 15 -> 70.
    expect(overlapScore).toBe(70)
  })

  it('applies diminishing returns for repeated matches of the same rule', () => {
    const singleBf = [makeMatch({ ruleId: 'brute_force' })]
    const doubleBf = [makeMatch({ ruleId: 'brute_force' }), makeMatch({ ruleId: 'brute_force' })]

    const score1 = calculateIncidentRiskScore(singleBf)
    const score2 = calculateIncidentRiskScore(doubleBf)

    expect(score1).toBe(40)
    expect(score2).toBe(40 + 16) // 40 + round(40 * 0.4) = 56
  })
})

describe('scoreToSeverity', () => {
  it('maps scores to correct severity levels', () => {
    expect(scoreToSeverity(90)).toBe('critical')
    expect(scoreToSeverity(80)).toBe('critical')
    expect(scoreToSeverity(65)).toBe('high')
    expect(scoreToSeverity(60)).toBe('high')
    expect(scoreToSeverity(45)).toBe('medium')
    expect(scoreToSeverity(35)).toBe('medium')
    expect(scoreToSeverity(20)).toBe('low')
  })
})

describe('generateRecommendedTriage & generateExplanation', () => {
  it('generates specific triage for burst success / credential compromise', () => {
    const triage = generateRecommendedTriage([makeMatch({ ruleId: 'burst_success' })])
    expect(triage).toContain('Critical compromise indicator')
    expect(triage).toContain('revoke active sessions')
  })

  it('generates specific triage for password spray', () => {
    const triage = generateRecommendedTriage([makeMatch({ ruleId: 'password_spray' })])
    expect(triage).toContain('Password spraying detected')
    expect(triage).toContain('block offending source IP')
  })

  it('generates concise multi-rule explanation', () => {
    const matches = [
      makeMatch({ ruleId: 'brute_force', ruleName: 'Repeated Failures', evidence: { eventIds: ['1'], description: '5 failures' } }),
      makeMatch({ ruleId: 'new_hosts', ruleName: 'New Hosts', evidence: { eventIds: ['2'], description: '4 new hosts' } }),
    ]
    const exp = generateExplanation('alice', matches)
    expect(exp).toContain('Correlated incident for user "alice"')
    expect(exp).toContain('Repeated Failures')
    expect(exp).toContain('New Hosts')
  })
})
