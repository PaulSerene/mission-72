/**
 * Mission 04 — Comprehensive Validation & Regression Test Suite
 *
 * Verifies detection correctness, context-aware policy suppression,
 * data quality/determinism, risk scoring reconciliation, and accuracy metrics
 * across deterministic synthetic authentication scenarios.
 */

import { describe, it, expect } from 'vitest'
import { runDetectionPipeline, createDefaultConfig } from '@/engine/pipeline'
import { parseAuthCsv, stableEventId } from '@/engine/ingest'
import {
  decomposeIncidentRiskScore,
  calculateIncidentRiskScore,
  correlateIncidents,
  scoreToSeverity,
} from '@/engine/incidents'
import {
  detectBruteForce,
  detectBurstSuccess,
  detectPasswordSpray,
  detectUnusualHours,
  detectNewIpOrLocation,
  detectNewHosts,
  detectImpossibleTravel,
  runAllRules,
  type RuleContext,
} from '@/engine/rules'
import { parseVpnCidrs } from '@/engine/assets'
import { generateAssetsCsv, generateIpLocationsCsv } from '@/data/generate'
import type { AuthEvent, UserBaseline, RuleMatch } from '@/types'

// ─── Test Helpers ─────────────────────────────────────────────────────────────

const assetsCsv = generateAssetsCsv()
const ipLocationsCsv = generateIpLocationsCsv()

function makeAuthEvent(overrides: Partial<AuthEvent> = {}): AuthEvent {
  return {
    id: 'ev-test-' + Math.random().toString(36).slice(2, 8),
    timestamp: '2026-10-09T10:00:00Z',
    username: 'test_user',
    sourceIp: '10.0.1.10',
    destination: 'workstation-test.corp.local',
    eventType: 'authentication',
    outcome: 'success',
    logonType: 'interactive',
    location: 'Corporate LAN',
    rawRow: 1,
    isDuplicate: false,
    ...overrides,
  }
}

function makeBaseline(username: string, overrides: Partial<UserBaseline> = {}): UserBaseline {
  const counts = new Array(24).fill(0)
  for (let h = 8; h <= 17; h++) {
    counts[h] = 5
  }
  return {
    username,
    knownIps: new Set(['10.0.1.10']),
    knownHosts: new Set(['workstation-test.corp.local']),
    knownLocations: new Set(['Corporate LAN']),
    loginHourCounts: counts,
    trainingEventCount: 20,
    status: 'sufficient',
    ...overrides,
  }
}

function makeContext(
  baselines: Record<string, Partial<UserBaseline>> = {},
  configOverrides = {},
): RuleContext {
  const config = createDefaultConfig(configOverrides)
  const map = new Map<string, UserBaseline>()
  for (const [u, b] of Object.entries(baselines)) {
    map.set(u, makeBaseline(u, b))
  }
  return {
    baselines: map,
    config,
    ipLocations: [],
    vpnCidrs: parseVpnCidrs(config.approvedVpnCidrs),
    accountRoles: config.accountRoles ?? {},
    authorizedHelpdeskAccounts: new Set(config.authorizedHelpdeskAccounts ?? []),
    suppressedAlerts: [],
  }
}

// ─── Test Suite ───────────────────────────────────────────────────────────────

describe('Mission 04 — Validation & Correctness Suite', () => {
  // ───────────────────────────────────────────────────────────────────────────
  // A. Normal and Suspicious Authentication
  // ───────────────────────────────────────────────────────────────────────────
  describe('A. Normal and Suspicious Authentication', () => {
    it('A1: normal successful logins during business hours produce 0 alerts and 0 incidents', () => {
      const csv = `timestamp,username,src_ip,dest,result,logon_type
2026-10-02T09:00:00Z,norm_user,10.0.1.10,workstation-alice.corp.local,success,interactive
2026-10-03T10:00:00Z,norm_user,10.0.1.10,workstation-alice.corp.local,success,interactive
2026-10-04T11:00:00Z,norm_user,10.0.1.10,workstation-alice.corp.local,success,interactive
2026-10-05T09:30:00Z,norm_user,10.0.1.10,workstation-alice.corp.local,success,interactive
2026-10-06T14:00:00Z,norm_user,10.0.1.10,workstation-alice.corp.local,success,interactive
2026-10-09T09:15:00Z,norm_user,10.0.1.10,workstation-alice.corp.local,success,interactive
2026-10-10T10:30:00Z,norm_user,10.0.1.10,workstation-alice.corp.local,success,interactive`

      const result = runDetectionPipeline({
        authData: csv,
        assetData: assetsCsv,
        ipLocationData: ipLocationsCsv,
      })

      expect(result.ruleMatches).toHaveLength(0)
      expect(result.incidents).toHaveLength(0)
    })

    it('A2: repeated authentication failures trigger brute_force and no unrelated alerts', () => {
      const ctx = makeContext({ victor: {} })
      // 5 failures within 40 seconds (threshold: 5 failures within 120s)
      const events: AuthEvent[] = Array.from({ length: 5 }, (_, i) =>
        makeAuthEvent({
          id: `bf-${i}`,
          timestamp: `2026-10-09T14:15:${String(i * 10).padStart(2, '0')}Z`,
          username: 'victor',
          sourceIp: '203.0.113.45',
          destination: 'app-web-01.corp.local',
          outcome: 'failure',
        })
      )

      const bfMatches = detectBruteForce(events, ctx)
      expect(bfMatches).toHaveLength(1)
      expect(bfMatches[0].ruleId).toBe('brute_force')
      expect(bfMatches[0].username).toBe('victor')
      expect(bfMatches[0].severity).toBe('high')

      // Verify absence of unrelated alerts
      expect(detectBurstSuccess(events, ctx)).toHaveLength(0)
      expect(detectPasswordSpray(events, ctx)).toHaveLength(0)
      expect(detectNewHosts(events, ctx)).toHaveLength(0)
      expect(detectUnusualHours(events, ctx)).toHaveLength(0)
    })

    it('A3: failure burst followed by successful login triggers burst_success', () => {
      const ctx = makeContext({ charlie: {} })
      // 3 failures followed by 1 success within 60s (threshold: 3 failures in 180s)
      const events: AuthEvent[] = [
        makeAuthEvent({ id: 'f1', timestamp: '2026-10-10T10:30:00Z', username: 'charlie', outcome: 'failure' }),
        makeAuthEvent({ id: 'f2', timestamp: '2026-10-10T10:30:15Z', username: 'charlie', outcome: 'failure' }),
        makeAuthEvent({ id: 'f3', timestamp: '2026-10-10T10:30:30Z', username: 'charlie', outcome: 'failure' }),
        makeAuthEvent({ id: 's1', timestamp: '2026-10-10T10:30:50Z', username: 'charlie', outcome: 'success' }),
      ]

      const bsMatches = detectBurstSuccess(events, ctx)
      expect(bsMatches).toHaveLength(1)
      expect(bsMatches[0].ruleId).toBe('burst_success')
      expect(bsMatches[0].username).toBe('charlie')
      expect(bsMatches[0].evidence.data?.failureCount).toBe(3)
      expect(bsMatches[0].evidence.eventIds).toContain('s1')

      // Absence of unrelated alerts
      expect(detectPasswordSpray(events, ctx)).toHaveLength(0)
      expect(detectNewHosts(events, ctx)).toHaveLength(0)
    })

    it('A4: regression check — success before failure burst does NOT trigger burst_success', () => {
      const ctx = makeContext({ charlie: {} })
      // Success at 10:30:00, then only 2 failures before end of sequence
      const events: AuthEvent[] = [
        makeAuthEvent({ id: 'f1', timestamp: '2026-10-10T10:30:00Z', username: 'charlie', outcome: 'failure' }),
        makeAuthEvent({ id: 'f2', timestamp: '2026-10-10T10:30:15Z', username: 'charlie', outcome: 'failure' }),
        makeAuthEvent({ id: 's1', timestamp: '2026-10-10T10:30:30Z', username: 'charlie', outcome: 'success' }),
        makeAuthEvent({ id: 'f3', timestamp: '2026-10-10T10:30:45Z', username: 'charlie', outcome: 'failure' }),
      ]

      // Only 2 failures preceded s1 (threshold requires >= 3 failures preceding success)
      const matches = detectBurstSuccess(events, ctx)
      expect(matches).toHaveLength(0)
    })

    it('A5: password spraying across multiple accounts triggers exactly one match per target and no false brute force', () => {
      const ctx = makeContext()
      const targets = ['david', 'emma', 'grace', 'hannah', 'ian']
      // 5 distinct accounts targeted by the same source IP in 40s
      const events: AuthEvent[] = targets.map((u, i) =>
        makeAuthEvent({
          id: `spray-${i}`,
          timestamp: `2026-10-11T16:01:${String(i * 10).padStart(2, '0')}Z`,
          username: u,
          sourceIp: '198.51.100.99',
          outcome: 'failure',
        })
      )

      const sprayMatches = detectPasswordSpray(events, ctx)
      expect(sprayMatches).toHaveLength(5)
      expect(new Set(sprayMatches.map(m => m.username))).toEqual(new Set(targets))

      // Crucial: Individual accounts had only 1 failure each, so brute_force must NOT fire
      expect(detectBruteForce(events, ctx)).toHaveLength(0)
      expect(detectBurstSuccess(events, ctx)).toHaveLength(0)
    })
  })

  // ───────────────────────────────────────────────────────────────────────────
  // B. Impossible Travel and VPN Context
  // ───────────────────────────────────────────────────────────────────────────
  describe('B. Impossible Travel and VPN Context', () => {
    it('B1: unfamiliar external IP/location triggers new_ip_location', () => {
      const ctx = makeContext({
        edward: {
          knownIps: new Set(['10.0.1.50']),
          knownLocations: new Set(['Corporate LAN']),
        },
      })

      const event = makeAuthEvent({
        id: 'new-loc-1',
        timestamp: '2026-10-13T11:00:35Z',
        username: 'edward',
        sourceIp: '203.0.113.190',
        location: 'External / Remote Access',
        outcome: 'success',
      })

      const matches = detectNewIpOrLocation([event], ctx)
      expect(matches).toHaveLength(1)
      expect(matches[0].ruleId).toBe('new_ip_location')
      expect(matches[0].username).toBe('edward')
    })

    it('B2: documented limitation — logins between two known baseline locations do not calculate velocity without coordinate schema', () => {
      // When a user has both locations in their baseline, new_ip_location does not fire.
      // This test verifies that SignalForge adheres to its architecture and documents that
      // GPS/velocity-based impossible travel is not claimed without geographic coordinate data.
      const ctx = makeContext({
        traveller: {
          knownIps: new Set(['10.0.1.10', '198.51.100.10']),
          knownLocations: new Set(['Corporate LAN', 'Branch Office']),
        },
      })

      const events: AuthEvent[] = [
        makeAuthEvent({
          id: 'trav-1',
          timestamp: '2026-10-09T10:00:00Z',
          username: 'traveller',
          sourceIp: '10.0.1.10',
          location: 'Corporate LAN',
          outcome: 'success',
        }),
        makeAuthEvent({
          id: 'trav-2',
          timestamp: '2026-10-09T10:05:00Z', // 5 minutes later from different known location
          username: 'traveller',
          sourceIp: '198.51.100.10',
          location: 'Branch Office',
          outcome: 'success',
        }),
      ]

      const matches = detectNewIpOrLocation(events, ctx)
      // Both locations are in baseline, so new_ip_location does not fire
      expect(matches).toHaveLength(0)
    })

    it('B2b: impossible travel detection flags rapid transitions between known locations when coordinate schema is provided', () => {
      const ctx = makeContext({
        traveller: {
          knownIps: new Set(['10.0.1.10', '198.51.100.10']),
          knownLocations: new Set(['London HQ', 'Tokyo Branch']),
        },
      })

      const events: AuthEvent[] = [
        makeAuthEvent({
          id: 'trav-1',
          timestamp: '2026-10-09T10:00:00Z',
          username: 'traveller',
          sourceIp: '10.0.1.10',
          location: 'London HQ',
          latitude: 51.5074,
          longitude: -0.1278,
          outcome: 'success',
        }),
        makeAuthEvent({
          id: 'trav-2',
          timestamp: '2026-10-09T10:05:00Z', // 5 minutes later from Tokyo
          username: 'traveller',
          sourceIp: '198.51.100.10',
          location: 'Tokyo Branch',
          latitude: 35.6762,
          longitude: 139.6503,
          outcome: 'success',
        }),
      ]

      // Impossible travel triggers even if both locations were previously in baseline!
      const travelMatches = detectImpossibleTravel(events, ctx)
      expect(travelMatches).toHaveLength(1)
      expect(travelMatches[0].ruleId).toBe('impossible_travel')
      expect(travelMatches[0].evidence.data?.distanceKm).toBeGreaterThan(9500)
    })

    it('B3: insufficient location evidence (unmapped IP / null location) does not fabricate location conclusions', () => {
      const csv = `timestamp,username,src_ip,dest,result,logon_type
2026-10-02T09:00:00Z,guest_user,10.0.1.10,workstation-alice.corp.local,success,interactive
2026-10-09T11:00:00Z,guest_user,172.31.254.99,workstation-alice.corp.local,success,interactive`

      const result = runDetectionPipeline({
        authData: csv,
        assetData: assetsCsv,
        ipLocationData: ipLocationsCsv, // 172.31.254.99 is not in ipLocations
      })

      const analysisEvent = result.events.find(e => e.sourceIp === '172.31.254.99')
      expect(analysisEvent).toBeDefined()
      expect(analysisEvent!.location).toBeNull()
    })

    it('B4: legitimate logins through configured approved VPN ranges are suppressed with audit log', () => {
      const csv = `timestamp,username,src_ip,dest,result,logon_type
2026-10-02T09:00:00Z,alice_vpn,10.0.1.25,ci-runner-01.corp.local,success,interactive
2026-10-09T09:30:00Z,alice_vpn,192.0.2.88,ci-runner-01.corp.local,success,interactive`

      const result = runDetectionPipeline({
        authData: csv,
        assetData: assetsCsv,
        ipLocationData: ipLocationsCsv,
      })

      // The new IP 192.0.2.88 is in approved VPN range (192.0.2.0/24)
      expect(result.ruleMatches.filter(r => r.ruleId === 'new_ip_location')).toHaveLength(0)
      expect(result.incidents).toHaveLength(0)

      // Audit log must record the suppression
      expect(result.suppressedAlerts).toHaveLength(1)
      expect(result.suppressedAlerts[0].policyType).toBe('approved_vpn')
      expect(result.suppressedAlerts[0].username).toBe('alice_vpn')
      expect(result.suppressedAlerts[0].reason).toContain('approved corporate VPN')
    })

    it('B5: approved VPN range does NOT suppress independent brute-force attacks', () => {
      // 5 failures originating from the approved VPN IP (192.0.2.88)
      const csvRows = [
        'timestamp,username,src_ip,dest,result,logon_type',
        '2026-10-02T09:00:00Z,victim,10.0.1.10,app-web-01.corp.local,success,interactive',
      ]
      for (let i = 0; i < 5; i++) {
        csvRows.push(
          `2026-10-09T14:00:${String(i * 10).padStart(2, '0')}Z,victim,192.0.2.88,app-web-01.corp.local,failure,network`
        )
      }

      const result = runDetectionPipeline({
        authData: csvRows.join('\n'),
        assetData: assetsCsv,
        ipLocationData: ipLocationsCsv,
      })

      // Brute-force must STILL be detected despite VPN IP!
      const bfMatches = result.ruleMatches.filter(r => r.ruleId === 'brute_force')
      expect(bfMatches).toHaveLength(1)
      expect(result.incidents).toHaveLength(1)
      expect(result.incidents[0].riskScore).toBe(40)
      expect(result.incidents[0].severity).toBe('medium')
    })

    it('B6: approved VPN range does NOT suppress independent password spraying', () => {
      // Attacker sprays 5 accounts from the approved VPN IP (192.0.2.88)
      const csvRows = [
        'timestamp,username,src_ip,dest,result,logon_type',
        '2026-10-02T09:00:00Z,u1,10.0.1.10,app-api-01.corp.local,success,interactive',
      ]
      const targets = ['u1', 'u2', 'u3', 'u4', 'u5']
      targets.forEach((u, i) => {
        csvRows.push(
          `2026-10-10T15:00:${String(i * 10).padStart(2, '0')}Z,${u},192.0.2.88,app-api-01.corp.local,failure,network`
        )
      })

      const result = runDetectionPipeline({
        authData: csvRows.join('\n'),
        assetData: assetsCsv,
        ipLocationData: ipLocationsCsv,
      })

      const sprayMatches = result.ruleMatches.filter(r => r.ruleId === 'password_spray')
      expect(sprayMatches).toHaveLength(5)
    })
  })

  // ───────────────────────────────────────────────────────────────────────────
  // C. Host Fan-out and Authorized Maintenance
  // ───────────────────────────────────────────────────────────────────────────
  describe('C. Host Fan-out and Authorized Maintenance', () => {
    it('C1: regular user accessing unusual number of distinct hosts triggers new_hosts', () => {
      const ctx = makeContext({
        frank: {
          knownHosts: new Set(['workstation-frank.corp.local']),
        },
      })

      // 4 unfamiliar hosts accessed within 1 hour (threshold: 3 within 24h)
      const events: AuthEvent[] = [
        makeAuthEvent({ id: 'h1', timestamp: '2026-10-13T15:10:00Z', username: 'frank', destination: 'dc-primary.corp.local' }),
        makeAuthEvent({ id: 'h2', timestamp: '2026-10-13T15:20:00Z', username: 'frank', destination: 'dc-secondary.corp.local' }),
        makeAuthEvent({ id: 'h3', timestamp: '2026-10-13T15:30:00Z', username: 'frank', destination: 'db-prod-01.corp.local' }),
        makeAuthEvent({ id: 'h4', timestamp: '2026-10-13T15:40:00Z', username: 'frank', destination: 'ldap-auth.corp.local' }),
      ]

      const matches = detectNewHosts(events, ctx)
      expect(matches).toHaveLength(1)
      expect(matches[0].ruleId).toBe('new_hosts')
      expect(matches[0].username).toBe('frank')
      expect(matches[0].severity).toBe('high')
      expect(matches[0].contextSuppression).toBeUndefined()
    })

    it('C2: approved helpdesk activity during maintenance window is suppressed with audit trail', () => {
      // helpdesk_bob accesses 4 unfamiliar hosts during Sunday 02:00-04:00 UTC window
      const ctx = makeContext({
        helpdesk_bob: {
          knownHosts: new Set(['workstation-bob.corp.local']),
        },
      })

      const events: AuthEvent[] = [
        makeAuthEvent({ id: 'm1', timestamp: '2026-10-11T02:15:00Z', username: 'helpdesk_bob', destination: 'dc-primary.corp.local', logonType: 'network' }),
        makeAuthEvent({ id: 'm2', timestamp: '2026-10-11T02:20:00Z', username: 'helpdesk_bob', destination: 'dc-secondary.corp.local', logonType: 'network' }),
        makeAuthEvent({ id: 'm3', timestamp: '2026-10-11T02:25:00Z', username: 'helpdesk_bob', destination: 'db-prod-01.corp.local', logonType: 'network' }),
        makeAuthEvent({ id: 'm4', timestamp: '2026-10-11T02:30:00Z', username: 'helpdesk_bob', destination: 'app-web-01.corp.local', logonType: 'network' }),
      ]

      const matches = detectNewHosts(events, ctx)
      expect(matches).toHaveLength(0)

      // Suppressed audit records must be generated
      expect(ctx.suppressedAlerts!.length).toBeGreaterThanOrEqual(4)
      expect(ctx.suppressedAlerts![0].policyType).toBe('maintenance_window')
      expect(ctx.suppressedAlerts![0].ruleId).toBe('new_hosts')
      expect(ctx.suppressedAlerts![0].reason).toContain('helpdesk')
    })

    it('C3: helpdesk activity outside maintenance window triggers new_hosts with partial context reduction', () => {
      // helpdesk_bob accesses 4 unfamiliar hosts on Tuesday at 10:00 UTC (outside maintenance)
      const ctx = makeContext({
        helpdesk_bob: {
          knownHosts: new Set(['workstation-bob.corp.local']),
        },
      })

      const events: AuthEvent[] = [
        makeAuthEvent({ id: 'o1', timestamp: '2026-10-13T10:10:00Z', username: 'helpdesk_bob', destination: 'dc-primary.corp.local' }),
        makeAuthEvent({ id: 'o2', timestamp: '2026-10-13T10:15:00Z', username: 'helpdesk_bob', destination: 'dc-secondary.corp.local' }),
        makeAuthEvent({ id: 'o3', timestamp: '2026-10-13T10:20:00Z', username: 'helpdesk_bob', destination: 'db-prod-01.corp.local' }),
        makeAuthEvent({ id: 'o4', timestamp: '2026-10-13T10:25:00Z', username: 'helpdesk_bob', destination: 'app-web-01.corp.local' }),
      ]

      const matches = detectNewHosts(events, ctx)
      expect(matches).toHaveLength(1)
      expect(matches[0].ruleId).toBe('new_hosts')
      expect(matches[0].contextSuppression).toBeDefined()
      expect(matches[0].contextSuppression?.scoreMultiplier).toBe(0.6)
    })

    it('C4: unauthorized regular user accessing hosts during maintenance window is NOT exempt', () => {
      const ctx = makeContext({
        regular_joe: {
          knownHosts: new Set(['workstation-joe.corp.local']),
        },
      })

      // regular_joe is NOT in authorizedHelpdeskAccounts
      const events: AuthEvent[] = [
        makeAuthEvent({ id: 'u1', timestamp: '2026-10-11T02:15:00Z', username: 'regular_joe', destination: 'dc-primary.corp.local' }),
        makeAuthEvent({ id: 'u2', timestamp: '2026-10-11T02:20:00Z', username: 'regular_joe', destination: 'dc-secondary.corp.local' }),
        makeAuthEvent({ id: 'u3', timestamp: '2026-10-11T02:25:00Z', username: 'regular_joe', destination: 'db-prod-01.corp.local' }),
        makeAuthEvent({ id: 'u4', timestamp: '2026-10-11T02:30:00Z', username: 'regular_joe', destination: 'app-web-01.corp.local' }),
      ]

      const matches = detectNewHosts(events, ctx)
      expect(matches).toHaveLength(1)
      expect(matches[0].ruleId).toBe('new_hosts')
      expect(matches[0].contextSuppression).toBeUndefined() // No discount
    })

    it('C5: genuine credential attacks during maintenance window are NOT suppressed', () => {
      // Brute force occurring during Sunday 02:00-04:00 maintenance window
      const ctx = makeContext({ target: {} })
      const events: AuthEvent[] = Array.from({ length: 5 }, (_, i) =>
        makeAuthEvent({
          id: `m-bf-${i}`,
          timestamp: `2026-10-11T02:30:${String(i * 10).padStart(2, '0')}Z`,
          username: 'target',
          outcome: 'failure',
        })
      )

      const bfMatches = detectBruteForce(events, ctx)
      expect(bfMatches).toHaveLength(1)
      expect(bfMatches[0].ruleId).toBe('brute_force')
    })
  })

  // ───────────────────────────────────────────────────────────────────────────
  // D. Data Quality and Determinism
  // ───────────────────────────────────────────────────────────────────────────
  describe('D. Data Quality and Determinism', () => {
    it('D1: duplicate rows do not inflate event counts or trigger brute_force', () => {
      // 1 real failure + 5 exact duplicate rows
      const baseRow = '2026-10-09T14:15:00Z,victor,203.0.113.45,app-web-01.corp.local,failure,network'
      const csv = `timestamp,username,src_ip,dest,result,logon_type\n${Array(6).fill(baseRow).join('\n')}`

      const result = runDetectionPipeline({
        authData: csv,
        assetData: assetsCsv,
        ipLocationData: ipLocationsCsv,
      })

      expect(result.ingestionReport?.totalRows).toBe(6)
      expect(result.ingestionReport?.duplicateCount).toBe(5)
      // 1 unique event is below the threshold of 5, so brute_force must NOT fire!
      expect(result.ruleMatches).toHaveLength(0)
      expect(result.incidents).toHaveLength(0)

      // Verify stable event ID determinism
      const id1 = stableEventId('victor', '203.0.113.45', '2026-10-09T14:15:00Z', 'failure', 'app-web-01.corp.local')
      const id2 = stableEventId('victor', '203.0.113.45', '2026-10-09T14:15:00Z', 'failure', 'app-web-01.corp.local')
      expect(id1).toBe(id2)
      expect(id1).toMatch(/^ev-[0-9a-f]{8}$/)
    })

    it('D2: out-of-order timestamps are sorted chronologically and detect attacks reliably', () => {
      // 5 failures in reverse chronological order
      const reversedCsv = `timestamp,username,src_ip,dest,result,logon_type
2026-10-09T14:15:40Z,victor,203.0.113.45,app-web-01.corp.local,failure,network
2026-10-09T14:15:30Z,victor,203.0.113.45,app-web-01.corp.local,failure,network
2026-10-09T14:15:20Z,victor,203.0.113.45,app-web-01.corp.local,failure,network
2026-10-09T14:15:10Z,victor,203.0.113.45,app-web-01.corp.local,failure,network
2026-10-09T14:15:00Z,victor,203.0.113.45,app-web-01.corp.local,failure,network`

      const result = runDetectionPipeline({
        authData: reversedCsv,
        assetData: assetsCsv,
        ipLocationData: ipLocationsCsv,
      })

      // Ingest sorts events ascending
      expect(result.events[0].timestamp).toBe('2026-10-09T14:15:00.000Z')
      expect(result.events[4].timestamp).toBe('2026-10-09T14:15:40.000Z')

      // Attack is detected identically
      const bf = result.ruleMatches.filter(r => r.ruleId === 'brute_force')
      expect(bf).toHaveLength(1)
    })

    it('D3: missing or unparseable timestamps are rejected to invalidRows without crashing', () => {
      const csv = `timestamp,username,src_ip,dest,result,logon_type
,user1,10.0.1.10,host1,success,interactive
not-a-timestamp,user2,10.0.1.10,host1,success,interactive
2026-10-09T10:00:00Z,user3,10.0.1.10,host1,success,interactive`

      const result = parseAuthCsv(csv, createDefaultConfig())
      expect(result.report.invalidRows).toHaveLength(2)
      expect(result.report.validEvents).toBe(1)
      expect(result.events[0].username).toBe('user3')
    })

    it('D4: missing or invalid IP addresses are rejected to invalidRows', () => {
      const csv = `timestamp,username,src_ip,dest,result,logon_type
2026-10-09T10:00:00Z,user1,,host1,success,interactive
2026-10-09T10:00:00Z,user2,999.999.999.999,host1,success,interactive
2026-10-09T10:00:00Z,user3,invalid-ip,host1,success,interactive
2026-10-09T10:00:00Z,user4,10.0.1.10,host1,success,interactive`

      const result = parseAuthCsv(csv, createDefaultConfig())
      expect(result.report.invalidRows).toHaveLength(3)
      expect(result.report.validEvents).toBe(1)
      expect(result.events[0].username).toBe('user4')
    })

    it('D5: determinism — repeated analysis of the same dataset yields identical results', () => {
      const csv = `timestamp,username,src_ip,dest,result,logon_type
2026-10-02T09:00:00Z,alice,10.0.1.10,host-a,success,interactive
2026-10-09T14:15:00Z,victor,203.0.113.45,host-b,failure,network
2026-10-09T14:15:10Z,victor,203.0.113.45,host-b,failure,network
2026-10-09T14:15:20Z,victor,203.0.113.45,host-b,failure,network
2026-10-09T14:15:30Z,victor,203.0.113.45,host-b,failure,network
2026-10-09T14:15:40Z,victor,203.0.113.45,host-b,failure,network`

      const run1 = runDetectionPipeline({ authData: csv, assetData: assetsCsv, ipLocationData: ipLocationsCsv })
      const run2 = runDetectionPipeline({ authData: csv, assetData: assetsCsv, ipLocationData: ipLocationsCsv })

      expect(run1.events.length).toBe(run2.events.length)
      expect(run1.ruleMatches.length).toBe(run2.ruleMatches.length)
      expect(run1.incidents.length).toBe(run2.incidents.length)
      expect(run1.incidents[0].riskScore).toBe(run2.incidents[0].riskScore)
      expect(run1.incidents[0].id).toBe(run2.incidents[0].id)
    })
  })

  // ───────────────────────────────────────────────────────────────────────────
  // E. Risk Scoring and Incident Correlation
  // ───────────────────────────────────────────────────────────────────────────
  describe('E. Risk Scoring and Incident Correlation', () => {
    it('E1: risk score boundaries [0, 100] and cap enforcement', () => {
      // 4 distinct high/critical severity matches: 40 + 55 + 40 + 35 = 170 + 15 synergy = 185
      const matches: RuleMatch[] = [
        {
          ruleId: 'brute_force',
          ruleName: 'Repeated Authentication Failures',
          severity: 'high',
          username: 'victim',
          timestamp: '2026-10-09T10:00:00Z',
          evidence: { eventIds: ['e1'], description: 'bf' },
        },
        {
          ruleId: 'burst_success',
          ruleName: 'Failure Burst Followed by Successful Login',
          severity: 'high',
          username: 'victim',
          timestamp: '2026-10-09T10:02:00Z',
          evidence: { eventIds: ['e2'], description: 'bs' },
        },
        {
          ruleId: 'new_hosts',
          ruleName: 'Sudden Access to Many Unfamiliar Hosts',
          severity: 'high',
          username: 'victim',
          timestamp: '2026-10-09T10:05:00Z',
          evidence: { eventIds: ['e3'], description: 'nh' },
        },
        {
          ruleId: 'new_ip_location',
          ruleName: 'Login from Unfamiliar IP or Location',
          severity: 'medium',
          username: 'victim',
          timestamp: '2026-10-09T10:06:00Z',
          evidence: { eventIds: ['e4'], description: 'nl' },
        },
      ]

      const breakdown = decomposeIncidentRiskScore(matches)
      expect(breakdown.rawCalculatedScore).toBeGreaterThan(100)
      expect(breakdown.finalScore).toBe(100)
      expect(breakdown.cappedAt100).toBe(true)
      expect(breakdown.synergyBonus).toBe(15) // >= 3 distinct rules
      expect(scoreToSeverity(breakdown.finalScore)).toBe('critical')
    })

    it('E2: rule contribution reconciliation matches final risk score', () => {
      const matches: RuleMatch[] = [
        {
          ruleId: 'brute_force',
          ruleName: 'Repeated Authentication Failures',
          severity: 'high',
          username: 'user1',
          timestamp: '2026-10-09T10:00:00Z',
          evidence: { eventIds: ['e1'], description: 'bf' },
        },
        {
          ruleId: 'unusual_hours',
          ruleName: 'Login During Unusual Hours',
          severity: 'medium',
          username: 'user1',
          timestamp: '2026-10-09T10:05:00Z',
          evidence: { eventIds: ['e2'], description: 'uh' },
        },
      ]

      const breakdown = decomposeIncidentRiskScore(matches)
      const sumContribs = breakdown.contributions.reduce((acc, c) => acc + c.finalContribution, 0)
      expect(sumContribs + breakdown.synergyBonus).toBe(breakdown.rawCalculatedScore)
      expect(breakdown.finalScore).toBe(Math.min(100, Math.max(0, breakdown.rawCalculatedScore)))
      expect(calculateIncidentRiskScore(matches)).toBe(breakdown.finalScore)
    })

    it('E3: account separation — different accounts are never grouped into the same incident', () => {
      const matches: RuleMatch[] = [
        {
          ruleId: 'brute_force',
          ruleName: 'Repeated Authentication Failures',
          severity: 'high',
          username: 'alice',
          timestamp: '2026-10-09T10:00:00Z',
          evidence: { eventIds: ['e1'], description: 'bf alice' },
        },
        {
          ruleId: 'brute_force',
          ruleName: 'Repeated Authentication Failures',
          severity: 'high',
          username: 'bob',
          timestamp: '2026-10-09T10:00:05Z', // 5 seconds later
          evidence: { eventIds: ['e2'], description: 'bf bob' },
        },
      ]

      const incidents = correlateIncidents(matches)
      expect(incidents).toHaveLength(2)
      expect(incidents.map(i => i.username)).toContain('alice')
      expect(incidents.map(i => i.username)).toContain('bob')
    })

    it('E4: stable temporal clustering separates events outside correlation window', () => {
      const matches: RuleMatch[] = [
        {
          ruleId: 'brute_force',
          ruleName: 'Repeated Authentication Failures',
          severity: 'high',
          username: 'alice',
          timestamp: '2026-10-09T08:00:00Z',
          evidence: { eventIds: ['e1'], description: 'morning attack' },
        },
        {
          ruleId: 'brute_force',
          ruleName: 'Repeated Authentication Failures',
          severity: 'high',
          username: 'alice',
          timestamp: '2026-10-09T08:30:00Z', // 30m later (grouped)
          evidence: { eventIds: ['e2'], description: 'morning follow-up' },
        },
        {
          ruleId: 'brute_force',
          ruleName: 'Repeated Authentication Failures',
          severity: 'high',
          username: 'alice',
          timestamp: '2026-10-09T15:00:00Z', // 6.5h later (outside 2h window, separate incident)
          evidence: { eventIds: ['e3'], description: 'afternoon attack' },
        },
      ]

      const incidents = correlateIncidents(matches)
      expect(incidents).toHaveLength(2)
      expect(incidents[0].ruleMatches).toHaveLength(2) // morning cluster
      expect(incidents[1].ruleMatches).toHaveLength(1) // afternoon cluster
    })

    it('E5: contextual reductions and suppression audit traceability', () => {
      const matchWithReduction: RuleMatch = {
        ruleId: 'new_ip_location',
        ruleName: 'Login from Unfamiliar IP or Location',
        severity: 'medium',
        username: 'edward_dev',
        timestamp: '2026-10-09T10:00:00Z',
        evidence: { eventIds: ['e1'], description: 'remote login' },
        contextSuppression: {
          reason: 'Account role "developer" is expected to occasionally access from new locations',
          scoreMultiplier: 0.5,
        },
      }

      const breakdown = decomposeIncidentRiskScore([matchWithReduction])
      expect(breakdown.contributions[0].contextMultiplier).toBe(0.5)
      expect(breakdown.contributions[0].finalContribution).toBe(Math.round(35 * 0.5)) // 18
      expect(breakdown.finalScore).toBe(18)
    })
  })

  // ───────────────────────────────────────────────────────────────────────────
  // F. Labeled Scenario Accuracy Evaluation Matrix
  // ───────────────────────────────────────────────────────────────────────────
  describe('F. Accuracy Evaluation & Scenario Matrix', () => {
    interface LabeledScenario {
      id: string
      name: string
      type: 'threat' | 'benign'
      events: AuthEvent[]
      expectedIncident: boolean
      expectedRule?: string
    }

    it('F1: evaluates precision, recall, and F1 score against a labeled synthetic scenario matrix', () => {
      const scenarios: LabeledScenario[] = [
        // 1. Brute Force (Threat)
        {
          id: 'SCEN-01',
          name: 'Brute Force Attack',
          type: 'threat',
          expectedIncident: true,
          expectedRule: 'brute_force',
          events: Array.from({ length: 5 }, (_, i) =>
            makeAuthEvent({
              timestamp: `2026-10-09T14:15:${String(i * 10).padStart(2, '0')}Z`,
              username: 'user_bf',
              outcome: 'failure',
            })
          ),
        },
        // 2. Burst Success (Threat)
        {
          id: 'SCEN-02',
          name: 'Burst Success Attack',
          type: 'threat',
          expectedIncident: true,
          expectedRule: 'burst_success',
          events: [
            makeAuthEvent({ timestamp: '2026-10-10T10:30:00Z', username: 'user_bs', outcome: 'failure' }),
            makeAuthEvent({ timestamp: '2026-10-10T10:30:15Z', username: 'user_bs', outcome: 'failure' }),
            makeAuthEvent({ timestamp: '2026-10-10T10:30:30Z', username: 'user_bs', outcome: 'failure' }),
            makeAuthEvent({ timestamp: '2026-10-10T10:30:45Z', username: 'user_bs', outcome: 'success' }),
          ],
        },
        // 3. Password Spray (Threat)
        {
          id: 'SCEN-03',
          name: 'Password Spray Attack',
          type: 'threat',
          expectedIncident: true,
          expectedRule: 'password_spray',
          events: ['sp1', 'sp2', 'sp3', 'sp4', 'sp5'].map((u, i) =>
            makeAuthEvent({
              timestamp: `2026-10-11T16:01:${String(i * 10).padStart(2, '0')}Z`,
              username: u,
              sourceIp: '198.51.100.99',
              outcome: 'failure',
            })
          ),
        },
        // 4. Unusual Hours Login (Threat)
        {
          id: 'SCEN-04',
          name: 'Nighttime Off-Hours Login',
          type: 'threat',
          expectedIncident: true,
          expectedRule: 'unusual_hours',
          events: [
            makeAuthEvent({
              timestamp: '2026-10-12T03:15:00Z',
              username: 'user_uh',
              outcome: 'success',
            }),
          ],
        },
        // 5. New Location Login (Threat)
        {
          id: 'SCEN-05',
          name: 'Login from Unfamiliar Location',
          type: 'threat',
          expectedIncident: true,
          expectedRule: 'new_ip_location',
          events: [
            makeAuthEvent({
              timestamp: '2026-10-13T11:00:00Z',
              username: 'user_nl',
              sourceIp: '203.0.113.190',
              location: 'External / Remote Access',
              outcome: 'success',
            }),
          ],
        },
        // 6. Host Fan-out (Threat)
        {
          id: 'SCEN-06',
          name: 'Sudden Many New Hosts',
          type: 'threat',
          expectedIncident: true,
          expectedRule: 'new_hosts',
          events: [
            makeAuthEvent({ timestamp: '2026-10-13T15:10:00Z', username: 'user_nh', destination: 'host-1' }),
            makeAuthEvent({ timestamp: '2026-10-13T15:20:00Z', username: 'user_nh', destination: 'host-2' }),
            makeAuthEvent({ timestamp: '2026-10-13T15:30:00Z', username: 'user_nh', destination: 'host-3' }),
            makeAuthEvent({ timestamp: '2026-10-13T15:40:00Z', username: 'user_nh', destination: 'host-4' }),
          ],
        },
        // 7. Normal Login (Benign)
        {
          id: 'SCEN-07',
          name: 'Normal Working Hours Login',
          type: 'benign',
          expectedIncident: false,
          events: [
            makeAuthEvent({
              timestamp: '2026-10-09T09:00:00Z',
              username: 'user_norm',
              sourceIp: '10.0.1.10',
              destination: 'workstation-test.corp.local',
              location: 'Corporate LAN',
              outcome: 'success',
            }),
          ],
        },
        // 8. Approved VPN Activity (Benign Exception)
        {
          id: 'SCEN-08',
          name: 'Approved VPN Remote Access',
          type: 'benign',
          expectedIncident: false,
          events: [
            makeAuthEvent({
              timestamp: '2026-10-09T09:30:00Z',
              username: 'user_vpn',
              sourceIp: '192.0.2.88', // in approved VPN 192.0.2.0/24
              outcome: 'success',
            }),
          ],
        },
        // 9. Approved Helpdesk Maintenance (Benign Exception)
        {
          id: 'SCEN-09',
          name: 'Authorized Maintenance Traversal',
          type: 'benign',
          expectedIncident: false,
          events: [
            makeAuthEvent({ timestamp: '2026-10-11T02:15:00Z', username: 'helpdesk1', destination: 'dc-primary.corp.local' }),
            makeAuthEvent({ timestamp: '2026-10-11T02:20:00Z', username: 'helpdesk1', destination: 'dc-secondary.corp.local' }),
            makeAuthEvent({ timestamp: '2026-10-11T02:25:00Z', username: 'helpdesk1', destination: 'db-prod-01.corp.local' }),
            makeAuthEvent({ timestamp: '2026-10-11T02:30:00Z', username: 'helpdesk1', destination: 'app-web-01.corp.local' }),
          ],
        },
        // 10. Sub-Threshold Failures (Benign / Non-Attack)
        {
          id: 'SCEN-10',
          name: 'Single Accidental Password Typo',
          type: 'benign',
          expectedIncident: false,
          events: [
            makeAuthEvent({
              timestamp: '2026-10-09T10:00:00Z',
              username: 'user_typo',
              outcome: 'failure',
            }),
            makeAuthEvent({
              timestamp: '2026-10-09T10:00:30Z',
              username: 'user_typo',
              outcome: 'success',
            }),
          ],
        },
        // 11. Impossible Travel (Threat)
        {
          id: 'SCEN-11',
          name: 'Impossible Transcontinental Velocity',
          type: 'threat',
          expectedIncident: true,
          expectedRule: 'impossible_travel',
          events: [
            makeAuthEvent({
              timestamp: '2026-10-09T10:00:00Z',
              username: 'user_it',
              location: 'London HQ',
              latitude: 51.5074,
              longitude: -0.1278,
              outcome: 'success',
            }),
            makeAuthEvent({
              timestamp: '2026-10-09T10:15:00Z',
              username: 'user_it',
              location: 'Tokyo Branch',
              latitude: 35.6762,
              longitude: 139.6503,
              outcome: 'success',
            }),
          ],
        },
        // 12. Plausible Transcontinental Travel (Benign)
        {
          id: 'SCEN-12',
          name: 'Plausible Transcontinental Flight',
          type: 'benign',
          expectedIncident: false,
          events: [
            makeAuthEvent({
              timestamp: '2026-10-09T08:00:00Z',
              username: 'user_pt',
              location: 'London HQ',
              latitude: 51.5074,
              longitude: -0.1278,
              outcome: 'success',
            }),
            makeAuthEvent({
              timestamp: '2026-10-10T02:00:00Z', // 18 hours later
              username: 'user_pt',
              location: 'Tokyo Branch',
              latitude: 35.6762,
              longitude: 139.6503,
              outcome: 'success',
            }),
          ],
        },
      ]

      let truePositives = 0
      let falsePositives = 0
      let falseNegatives = 0
      let trueNegatives = 0

      for (const scen of scenarios) {
        // Setup baseline for the user in scenario
        const user = scen.events[0].username
        const baselineOverrides: Partial<UserBaseline> = {
          knownIps: new Set(['10.0.1.10']),
          knownHosts: new Set(['workstation-test.corp.local']),
          knownLocations: new Set(['Corporate LAN']),
        }
        if (scen.id === 'SCEN-09') {
          // Maintenance engineer routinely operates during the 02:00 Sunday window
          const counts = new Array(24).fill(0)
          for (let h = 8; h <= 17; h++) counts[h] = 5
          counts[2] = 5
          baselineOverrides.loginHourCounts = counts
        }
        if (scen.id === 'SCEN-11') {
          baselineOverrides.knownLocations = new Set(['London HQ', 'Tokyo Branch'])
        }
        if (scen.id === 'SCEN-12') {
          // Both locations and flight arrival hour recognized for international traveler
          baselineOverrides.knownLocations = new Set(['London HQ', 'Tokyo Branch'])
          const counts = new Array(24).fill(0)
          for (let h = 0; h < 24; h++) counts[h] = 5
          baselineOverrides.loginHourCounts = counts
        }
        const ctx = makeContext({
          [user]: baselineOverrides,
        })

        // Run rules using full context-aware dispatcher
        const matches: RuleMatch[] = runAllRules(scen.events, ctx)
        const incidents = correlateIncidents(matches)
        const hasIncident = incidents.length > 0

        if (scen.type === 'threat') {
          if (hasIncident) {
            truePositives++
            if (scen.expectedRule) {
              expect(matches.some(m => m.ruleId === scen.expectedRule)).toBe(true)
            }
          } else {
            falseNegatives++
          }
        } else {
          // benign
          if (hasIncident) {
            falsePositives++
          } else {
            trueNegatives++
          }
        }
      }

      const precision = truePositives / (truePositives + falsePositives)
      const recall = truePositives / (truePositives + falseNegatives)
      const f1 = (2 * precision * recall) / (precision + recall)

      // Verified exact counts (7 threats, 5 benign cases)
      expect(truePositives).toBe(7)
      expect(trueNegatives).toBe(5)
      expect(falsePositives).toBe(0)
      expect(falseNegatives).toBe(0)

      expect(precision).toBe(1.0)
      expect(recall).toBe(1.0)
      expect(f1).toBe(1.0)
    })
  })
})
