/**
 * Unit tests for Behavioral Baseline Builder — Mission 72
 */

import { describe, expect, it } from 'vitest'
import { buildBaselines, makeEmptyBaseline, isUnusualHour } from './baseline'
import type { AuthEvent, AnalysisConfig } from '@/types'
import { createDefaultConfig } from './pipeline'

function makeAuthEvent(overrides: Partial<AuthEvent> = {}): AuthEvent {
  return {
    id: 'ev-test',
    timestamp: '2026-10-02T10:00:00Z',
    username: 'alice',
    sourceIp: '10.0.1.10',
    destination: 'workstation-alice.corp.local',
    eventType: 'authentication',
    outcome: 'success',
    logonType: 'interactive',
    location: 'Corporate LAN',
    rawRow: 0,
    isDuplicate: false,
    ...overrides,
  }
}

describe('buildBaselines — Isolation and Learning', () => {
  const config: AnalysisConfig = createDefaultConfig({
    trainingPeriod: {
      start: '2026-10-01T00:00:00Z',
      end: '2026-10-08T00:00:00Z',
    },
    analysisPeriod: {
      start: '2026-10-08T00:00:00Z',
      end: '2026-10-15T00:00:00Z',
    },
  })

  it('isolates training period strictly — events outside training period are ignored', () => {
    const events: AuthEvent[] = [
      // In training period:
      makeAuthEvent({
        id: 'e1',
        timestamp: '2026-10-02T10:00:00Z',
        username: 'alice',
        sourceIp: '10.0.1.10',
      }),
      makeAuthEvent({
        id: 'e2',
        timestamp: '2026-10-03T11:00:00Z',
        username: 'alice',
        sourceIp: '10.0.1.10',
      }),
      // Outside training period (before start):
      makeAuthEvent({
        id: 'e3',
        timestamp: '2026-09-30T23:59:59Z',
        username: 'alice',
        sourceIp: '198.51.100.1',
      }),
      // Outside training period (after end, in analysis period):
      makeAuthEvent({
        id: 'e4',
        timestamp: '2026-10-08T00:00:00Z',
        username: 'alice',
        sourceIp: '203.0.113.99',
      }),
    ]

    const baselines = buildBaselines(events, config)
    const aliceBaseline = baselines.get('alice')!

    expect(aliceBaseline).toBeDefined()
    expect(aliceBaseline.trainingEventCount).toBe(2)
    expect(aliceBaseline.knownIps.has('10.0.1.10')).toBe(true)
    // IPs from outside the training period must NEVER be learned
    expect(aliceBaseline.knownIps.has('198.51.100.1')).toBe(false)
    expect(aliceBaseline.knownIps.has('203.0.113.99')).toBe(false)
  })

  it('learns known IPs and hosts only from successful logins (not failed ones)', () => {
    const events: AuthEvent[] = [
      makeAuthEvent({
        id: 'e1',
        timestamp: '2026-10-02T10:00:00Z',
        username: 'bob',
        sourceIp: '10.0.1.50',
        destination: 'app-web-01.corp.local',
        outcome: 'success',
      }),
      makeAuthEvent({
        id: 'e2',
        timestamp: '2026-10-02T10:05:00Z',
        username: 'bob',
        sourceIp: '203.0.113.1', // attacker failure
        destination: 'dc-01.corp.local',
        outcome: 'failure',
      }),
    ]

    const baselines = buildBaselines(events, config)
    const bob = baselines.get('bob')!

    expect(bob.trainingEventCount).toBe(2)
    expect(bob.knownIps.has('10.0.1.50')).toBe(true)
    expect(bob.knownIps.has('203.0.113.1')).toBe(false) // failure IP not learned
    expect(bob.knownHosts.has('app-web-01.corp.local')).toBe(true)
    expect(bob.knownHosts.has('dc-01.corp.local')).toBe(false)
  })

  it('ignores duplicate events so they do not artificially inflate counts', () => {
    const events: AuthEvent[] = [
      makeAuthEvent({ id: 'e1', timestamp: '2026-10-02T10:00:00Z', username: 'charlie', isDuplicate: false }),
      makeAuthEvent({ id: 'e1-dup', timestamp: '2026-10-02T10:00:00Z', username: 'charlie', isDuplicate: true }),
    ]

    const baselines = buildBaselines(events, config)
    const charlie = baselines.get('charlie')!
    expect(charlie.trainingEventCount).toBe(1)
  })

  it('assigns correct baseline status based on training event volume', () => {
    // 0 training events -> 'none'
    const empty = makeEmptyBaseline('nobody')
    expect(empty.status).toBe('none')

    // 1-4 events -> 'limited'
    const limitedEvents = Array.from({ length: 3 }, (_, i) =>
      makeAuthEvent({ id: `e${i}`, timestamp: `2026-10-0${i + 1}T10:00:00Z`, username: 'david' }),
    )
    const david = buildBaselines(limitedEvents, config).get('david')!
    expect(david.status).toBe('limited')

    // >=5 events -> 'sufficient'
    const sufficientEvents = Array.from({ length: 6 }, (_, i) =>
      makeAuthEvent({ id: `e${i}`, timestamp: `2026-10-0${i + 1}T10:00:00Z`, username: 'emma' }),
    )
    const emma = buildBaselines(sufficientEvents, config).get('emma')!
    expect(emma.status).toBe('sufficient')
  })

  it('assigns "none" baseline explicitly to users observed only in analysis period', () => {
    const events: AuthEvent[] = [
      makeAuthEvent({
        id: 'e-analysis-only',
        timestamp: '2026-10-10T12:00:00Z', // in analysis period
        username: 'new_hire',
      }),
    ]

    const baselines = buildBaselines(events, config)
    const newHire = baselines.get('new_hire')!
    expect(newHire).toBeDefined()
    expect(newHire.status).toBe('none')
    expect(newHire.trainingEventCount).toBe(0)
  })
})

describe('isUnusualHour', () => {
  it('identifies unusual hours for users with baseline (hour count = 0)', () => {
    const baseline = makeEmptyBaseline('alice')
    baseline.status = 'sufficient'
    baseline.loginHourCounts[9] = 5 // logged in at 9 UTC
    baseline.loginHourCounts[14] = 3 // logged in at 14 UTC

    expect(isUnusualHour(9, baseline, 22, 6)).toBe(false)
    expect(isUnusualHour(14, baseline, 22, 6)).toBe(false)
    // 3am was never seen during training
    expect(isUnusualHour(3, baseline, 22, 6)).toBe(true)
  })

  it('falls back to configured off-hours window when baseline status is "none"', () => {
    const baseline = makeEmptyBaseline('new_user') // status 'none'

    // Off-hours 22 to 6 (wrapping midnight)
    expect(isUnusualHour(23, baseline, 22, 6)).toBe(true) // 23:00 is off-hours
    expect(isUnusualHour(3, baseline, 22, 6)).toBe(true) // 03:00 is off-hours
    expect(isUnusualHour(10, baseline, 22, 6)).toBe(false) // 10:00 is normal office hours
  })
})
