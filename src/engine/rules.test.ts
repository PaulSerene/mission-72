/**
 * Unit tests for Detection Rules & False Positive Suppression — Mission 72
 * Includes context-aware alert detection tests (Mission 02).
 */

import { describe, expect, it } from 'vitest'
import {
  detectBruteForce,
  detectBurstSuccess,
  detectPasswordSpray,
  detectUnusualHours,
  detectNewIpOrLocation,
  detectNewHosts,
  type RuleContext,
} from './rules'
import { calculateIncidentRiskScore } from './incidents'
import { createDefaultConfig } from './pipeline'
import { makeEmptyBaseline } from './baseline'
import { parseVpnCidrs } from './assets'
import type { AuthEvent, UserBaseline } from '@/types'

function makeAuthEvent(overrides: Partial<AuthEvent> = {}): AuthEvent {
  return {
    id: `ev-${Math.random().toString(36).slice(2, 9)}`,
    timestamp: '2026-10-09T10:00:00Z',
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

function createContext(userBaselines: Record<string, Partial<UserBaseline>> = {}): RuleContext {
  const config = createDefaultConfig()
  const baselines = new Map<string, UserBaseline>()

  for (const [username, partial] of Object.entries(userBaselines)) {
    const b = makeEmptyBaseline(username)
    b.status = partial.status ?? 'sufficient'
    if (partial.knownIps) b.knownIps = partial.knownIps
    if (partial.knownHosts) b.knownHosts = partial.knownHosts
    if (partial.knownLocations) b.knownLocations = partial.knownLocations
    if (partial.loginHourCounts) b.loginHourCounts = partial.loginHourCounts
    b.trainingEventCount = partial.trainingEventCount ?? 10
    baselines.set(username, b)
  }

  return {
    config,
    baselines,
    ipLocations: [],
    vpnCidrs: parseVpnCidrs(config.approvedVpnCidrs),
    accountRoles: {},
    authorizedHelpdeskAccounts: new Set(),
  }
}

describe('Rule 1: detectBruteForce', () => {
  it('triggers when failures reach threshold (5) within window (120s)', () => {
    const ctx = createContext({ victor: {} })
    const events: AuthEvent[] = Array.from({ length: 5 }, (_, i) =>
      makeAuthEvent({
        id: `bf-${i}`,
        timestamp: `2026-10-09T14:15:${String(i * 10).padStart(2, '0')}Z`,
        username: 'victor',
        outcome: 'failure',
      }),
    )

    const matches = detectBruteForce(events, ctx)
    expect(matches).toHaveLength(1)
    expect(matches[0].ruleId).toBe('brute_force')
    expect(matches[0].username).toBe('victor')
    expect(matches[0].evidence.eventIds).toHaveLength(5)
  })

  it('does not trigger when failure count is below threshold', () => {
    const ctx = createContext({ victor: {} })
    const events: AuthEvent[] = Array.from({ length: 4 }, (_, i) =>
      makeAuthEvent({
        timestamp: `2026-10-09T14:15:${String(i * 10).padStart(2, '0')}Z`,
        username: 'victor',
        outcome: 'failure',
      }),
    )

    const matches = detectBruteForce(events, ctx)
    expect(matches).toHaveLength(0)
  })

  it('does not trigger when failures are outside sliding window', () => {
    const ctx = createContext({ victor: {} })
    // 5 failures spaced 4m (240s) apart = 960s > sliding window
    const events: AuthEvent[] = Array.from({ length: 5 }, (_, i) =>
      makeAuthEvent({
        timestamp: `2026-10-09T14:${String(i * 4).padStart(2, '0')}:00Z`,
        username: 'victor',
        outcome: 'failure',
      }),
    )

    const matches = detectBruteForce(events, ctx)
    expect(matches).toHaveLength(0)
  })
})

describe('Rule 2: detectBurstSuccess', () => {
  it('triggers when >= 3 failures are followed by success within window (180s)', () => {
    const ctx = createContext({ charlie: {} })
    const events: AuthEvent[] = [
      makeAuthEvent({ id: 'f1', timestamp: '2026-10-10T10:30:00Z', username: 'charlie', outcome: 'failure' }),
      makeAuthEvent({ id: 'f2', timestamp: '2026-10-10T10:30:15Z', username: 'charlie', outcome: 'failure' }),
      makeAuthEvent({ id: 'f3', timestamp: '2026-10-10T10:30:30Z', username: 'charlie', outcome: 'failure' }),
      makeAuthEvent({ id: 's1', timestamp: '2026-10-10T10:31:00Z', username: 'charlie', outcome: 'success' }),
    ]

    const matches = detectBurstSuccess(events, ctx)
    expect(matches).toHaveLength(1)
    expect(matches[0].ruleId).toBe('burst_success')
    expect(matches[0].username).toBe('charlie')
    expect(matches[0].evidence.data?.failureCount).toBe(3)
  })

  it('does not trigger if success occurs before failures', () => {
    const ctx = createContext({ charlie: {} })
    const events: AuthEvent[] = [
      makeAuthEvent({ id: 's1', timestamp: '2026-10-10T10:30:00Z', username: 'charlie', outcome: 'success' }),
      makeAuthEvent({ id: 'f1', timestamp: '2026-10-10T10:30:15Z', username: 'charlie', outcome: 'failure' }),
      makeAuthEvent({ id: 'f2', timestamp: '2026-10-10T10:30:30Z', username: 'charlie', outcome: 'failure' }),
      makeAuthEvent({ id: 'f3', timestamp: '2026-10-10T10:30:45Z', username: 'charlie', outcome: 'failure' }),
    ]

    const matches = detectBurstSuccess(events, ctx)
    expect(matches).toHaveLength(0)
  })
})

describe('Rule 3: detectPasswordSpray', () => {
  it('triggers when same IP targets >= 4 distinct accounts with failures', () => {
    const ctx = createContext()
    const targets = ['user1', 'user2', 'user3', 'user4', 'user5']
    const events: AuthEvent[] = targets.map((u, i) =>
      makeAuthEvent({
        id: `spray-${i}`,
        timestamp: `2026-10-11T16:00:${String(i * 10).padStart(2, '0')}Z`,
        username: u,
        sourceIp: '198.51.100.99',
        outcome: 'failure',
      }),
    )

    const matches = detectPasswordSpray(events, ctx)
    expect(matches).toHaveLength(5)
    expect(matches[0].ruleId).toBe('password_spray')
    expect(matches.map(m => m.username)).toEqual(targets)
    expect(matches[0].evidence.data?.sourceIp).toBe('198.51.100.99')
  })

  it('does not trigger if only single account is targeted repeatedly (that is brute force)', () => {
    const ctx = createContext()
    const events: AuthEvent[] = Array.from({ length: 6 }, (_, i) =>
      makeAuthEvent({
        timestamp: `2026-10-11T16:00:${String(i * 10).padStart(2, '0')}Z`,
        username: 'single_target',
        sourceIp: '198.51.100.99',
        outcome: 'failure',
      }),
    )

    const matches = detectPasswordSpray(events, ctx)
    expect(matches).toHaveLength(0)
  })
})

describe('Rule 4: detectUnusualHours & Maintenance Suppression', () => {
  it('triggers on off-hours login for user with baseline', () => {
    const hourCounts = new Array(24).fill(0)
    hourCounts[9] = 10 // only 9am UTC
    const ctx = createContext({ diana: { loginHourCounts: hourCounts } })

    const events: AuthEvent[] = [
      makeAuthEvent({
        timestamp: '2026-10-12T03:15:00Z', // 03:00 UTC
        username: 'diana',
        outcome: 'success',
      }),
    ]

    const matches = detectUnusualHours(events, ctx)
    expect(matches).toHaveLength(1)
    expect(matches[0].ruleId).toBe('unusual_hours')
    expect(matches[0].username).toBe('diana')
  })

  it('suppresses unusual hours alert when event falls inside configured maintenance window for allowed user', () => {
    const hourCounts = new Array(24).fill(0)
    hourCounts[10] = 5
    // svc_backup has maintenance window on Sunday (day 0) 02:00–04:00 UTC
    const ctx = createContext({ svc_backup: { loginHourCounts: hourCounts } })

    const events: AuthEvent[] = [
      makeAuthEvent({
        timestamp: '2026-10-11T02:30:00Z', // Sunday 02:30 UTC
        username: 'svc_backup',
        outcome: 'success',
      }),
    ]

    const matches = detectUnusualHours(events, ctx)
    // Must be suppressed!
    expect(matches).toHaveLength(0)
  })

  it('does NOT suppress for unauthorized users during maintenance window', () => {
    const hourCounts = new Array(24).fill(0)
    hourCounts[10] = 5
    const ctx = createContext({ regular_user: { loginHourCounts: hourCounts } })

    const events: AuthEvent[] = [
      makeAuthEvent({
        timestamp: '2026-10-11T02:30:00Z', // Sunday 02:30 UTC
        username: 'regular_user',
        outcome: 'success',
      }),
    ]

    const matches = detectUnusualHours(events, ctx)
    // regular_user is not in allowedUsers ['svc_backup'], so alert fires
    expect(matches).toHaveLength(1)
  })
})

describe('Rule 5: detectNewIpOrLocation & Approved VPN Suppression', () => {
  it('triggers on login from unfamiliar IP and location', () => {
    const ctx = createContext({
      edward: {
        knownIps: new Set(['10.0.1.50']),
        knownLocations: new Set(['Corporate LAN']),
      },
    })

    const events: AuthEvent[] = [
      makeAuthEvent({
        timestamp: '2026-10-13T11:00:00Z',
        username: 'edward',
        sourceIp: '203.0.113.190',
        location: 'External / Remote Access',
        outcome: 'success',
      }),
    ]

    const matches = detectNewIpOrLocation(events, ctx)
    expect(matches).toHaveLength(1)
    expect(matches[0].ruleId).toBe('new_ip_location')
    expect(matches[0].username).toBe('edward')
  })

  it('suppresses new IP alert when IP falls in approved VPN CIDR range (192.0.2.0/24)', () => {
    const ctx = createContext({
      alice_vpn: {
        knownIps: new Set(['10.0.1.25']),
        knownLocations: new Set(['Corporate LAN']),
      },
    })

    const events: AuthEvent[] = [
      makeAuthEvent({
        timestamp: '2026-10-09T09:30:00Z',
        username: 'alice_vpn',
        sourceIp: '192.0.2.88', // inside approved VPN
        location: 'Approved Corporate VPN',
        outcome: 'success',
      }),
    ]

    const matches = detectNewIpOrLocation(events, ctx)
    // Must be suppressed by VPN policy!
    expect(matches).toHaveLength(0)
  })

  it('does NOT suppress unrelated rules (e.g. brute force) even from approved VPN IP', () => {
    const ctx = createContext({
      attacker: {
        knownIps: new Set(['10.0.1.25']),
      },
    })

    const events: AuthEvent[] = Array.from({ length: 5 }, (_, i) =>
      makeAuthEvent({
        id: `bf-vpn-${i}`,
        timestamp: `2026-10-09T14:15:${String(i * 10).padStart(2, '0')}Z`,
        username: 'attacker',
        sourceIp: '192.0.2.88', // VPN IP
        outcome: 'failure',
      }),
    )

    const matches = detectBruteForce(events, ctx)
    // Brute force must STILL fire even from a VPN IP
    expect(matches).toHaveLength(1)
  })

  it('applies contextSuppression with 0.5 multiplier for developer role new-IP logins', () => {
    const ctx: RuleContext = {
      ...createContext({
        dev_alice: {
          knownIps: new Set(['10.0.1.50']),
          knownLocations: new Set(['Corporate LAN']),
        },
      }),
      accountRoles: { dev_alice: 'developer' },
    }

    const events: AuthEvent[] = [
      makeAuthEvent({
        timestamp: '2026-10-13T11:00:00Z',
        username: 'dev_alice',
        sourceIp: '203.0.113.191',
        location: 'External / Remote Access',
        outcome: 'success',
      }),
    ]

    const matches = detectNewIpOrLocation(events, ctx)
    expect(matches).toHaveLength(1)
    expect(matches[0].contextSuppression).toBeDefined()
    expect(matches[0].contextSuppression!.scoreMultiplier).toBe(0.5)
    expect(matches[0].contextSuppression!.reason).toContain('developer')
  })

  it('does NOT apply contextSuppression for regular user new-IP logins', () => {
    const ctx = createContext({
      regular_user: {
        knownIps: new Set(['10.0.1.50']),
        knownLocations: new Set(['Corporate LAN']),
      },
    })

    const events: AuthEvent[] = [
      makeAuthEvent({
        timestamp: '2026-10-13T11:00:00Z',
        username: 'regular_user',
        sourceIp: '203.0.113.192',
        location: 'External / Remote Access',
        outcome: 'success',
      }),
    ]

    const matches = detectNewIpOrLocation(events, ctx)
    expect(matches).toHaveLength(1)
    expect(matches[0].contextSuppression).toBeUndefined()
  })
})

describe('Rule 6: detectNewHosts', () => {
  it('triggers when user accesses >= 4 new hosts within window (4h)', () => {
    const ctx = createContext({
      frank: {
        knownHosts: new Set(['workstation-frank.corp.local', 'ci-runner-01.corp.local']),
      },
    })

    const newServers = ['dc-01', 'dc-02', 'db-01', 'ldap-01', 'fs-01']
    const events: AuthEvent[] = newServers.map((host, i) =>
      makeAuthEvent({
        id: `host-${i}`,
        timestamp: `2026-10-13T15:${String(i * 10).padStart(2, '0')}:00Z`,
        username: 'frank',
        destination: host,
        outcome: 'success',
      }),
    )

    const matches = detectNewHosts(events, ctx)
    expect(matches).toHaveLength(1)
    expect(matches[0].ruleId).toBe('new_hosts')
    expect(matches[0].evidence.data?.newHostCount).toBe(5)
  })

  it('does not count hosts already present in the user training baseline', () => {
    const ctx = createContext({
      frank: {
        knownHosts: new Set(['dc-01', 'dc-02', 'db-01', 'ldap-01']),
      },
    })

    const events: AuthEvent[] = ['dc-01', 'dc-02', 'db-01', 'ldap-01'].map((host, i) =>
      makeAuthEvent({
        timestamp: `2026-10-13T15:${String(i * 10).padStart(2, '0')}:00Z`,
        username: 'frank',
        destination: host,
        outcome: 'success',
      }),
    )

    const matches = detectNewHosts(events, ctx)
    expect(matches).toHaveLength(0)
  })
})

describe('Context-Aware Alert Detection (Mission 02)', () => {
  it('suppresses new_hosts for authorized helpdesk during maintenance window', () => {
    // helpdesk1 is in the default maintenance window's authorizedHelpdeskAccounts
    const ctx = createContext({
      helpdesk1: {
        knownHosts: new Set(['ws-helpdesk.corp.local']),
      },
    })

    // Sunday 02:30 UTC = inside maintenance window (Sun 02:00–04:00)
    const newServers = ['dc-01', 'dc-02', 'db-01', 'ldap-01', 'fs-01']
    const events: AuthEvent[] = newServers.map((host, i) =>
      makeAuthEvent({
        id: `hd-${i}`,
        // 2026-10-12 is a Monday, use 2026-10-11 (Sunday)
        timestamp: `2026-10-11T02:${String(i * 5 + 30).padStart(2, '0')}:00Z`,
        username: 'helpdesk1',
        destination: host,
        outcome: 'success',
      }),
    )

    const matches = detectNewHosts(events, ctx)
    // ALL events occur during the maintenance window — fully suppressed
    expect(matches).toHaveLength(0)
  })

  it('applies partial suppression (scoreMultiplier 0.6) for helpdesk outside maintenance window', () => {
    const ctx: RuleContext = {
      ...createContext({
        it_support: {
          knownHosts: new Set(['ws-helpdesk.corp.local']),
        },
      }),
      accountRoles: { it_support: 'helpdesk' },
    }

    // Tuesday 14:00 UTC = NOT in maintenance window
    const newServers = ['dc-01', 'dc-02', 'db-01', 'ldap-01', 'fs-01']
    const events: AuthEvent[] = newServers.map((host, i) =>
      makeAuthEvent({
        id: `it-${i}`,
        timestamp: `2026-10-14T14:${String(i * 5).padStart(2, '0')}:00Z`, // Tuesday
        username: 'it_support',
        destination: host,
        outcome: 'success',
      }),
    )

    const matches = detectNewHosts(events, ctx)
    expect(matches).toHaveLength(1)
    expect(matches[0].contextSuppression).toBeDefined()
    expect(matches[0].contextSuppression!.scoreMultiplier).toBe(0.6)
    expect(matches[0].contextSuppression!.reason).toContain('helpdesk')
  })

  it('does NOT suppress new_hosts for regular users accessing many new hosts', () => {
    const ctx = createContext({
      regular_user: {
        knownHosts: new Set(['workstation.corp.local']),
      },
    })

    const newServers = ['dc-01', 'dc-02', 'db-01', 'ldap-01', 'fs-01']
    const events: AuthEvent[] = newServers.map((host, i) =>
      makeAuthEvent({
        id: `reg-${i}`,
        timestamp: `2026-10-13T15:${String(i * 10).padStart(2, '0')}:00Z`,
        username: 'regular_user',
        destination: host,
        outcome: 'success',
      }),
    )

    const matches = detectNewHosts(events, ctx)
    expect(matches).toHaveLength(1)
    expect(matches[0].contextSuppression).toBeUndefined()
  })

  it('suppresses new_hosts for global authorizedHelpdeskAccounts during maintenance window', () => {
    const ctx: RuleContext = {
      ...createContext({
        global_helpdesk: {
          knownHosts: new Set(['ws-helpdesk.corp.local']),
        },
      }),
      authorizedHelpdeskAccounts: new Set(['global_helpdesk']),
    }

    // Sunday 02:30 UTC = in maintenance window
    const newServers = ['dc-01', 'dc-02', 'db-01', 'ldap-01', 'fs-01']
    const events: AuthEvent[] = newServers.map((host, i) =>
      makeAuthEvent({
        id: `ghd-${i}`,
        timestamp: `2026-10-11T02:${String(i * 5 + 30).padStart(2, '0')}:00Z`,
        username: 'global_helpdesk',
        destination: host,
        outcome: 'success',
      }),
    )

    const matches = detectNewHosts(events, ctx)
    expect(matches).toHaveLength(0)
  })

  it('does NOT exempt authorized helpdesk when acting outside maintenance window (Scenario B)', () => {
    const ctx: RuleContext = {
      ...createContext({
        global_helpdesk: {
          knownHosts: new Set(['ws-helpdesk.corp.local']),
        },
      }),
      accountRoles: { global_helpdesk: 'helpdesk' },
      authorizedHelpdeskAccounts: new Set(['global_helpdesk']),
    }

    // Wednesday 10:00 UTC = outside maintenance window
    const newServers = ['dc-01', 'dc-02', 'db-01', 'ldap-01', 'fs-01']
    const events: AuthEvent[] = newServers.map((host, i) =>
      makeAuthEvent({
        id: `ghd-out-${i}`,
        timestamp: `2026-10-09T10:${String(i * 5).padStart(2, '0')}:00Z`,
        username: 'global_helpdesk',
        destination: host,
        outcome: 'success',
      }),
    )

    const matches = detectNewHosts(events, ctx)
    expect(matches).toHaveLength(1)
    expect(matches[0].ruleId).toBe('new_hosts')
    expect(matches[0].contextSuppression).toBeDefined()
  })

  it('contextSuppression multiplier reduces risk score in calculateIncidentRiskScore', () => {
    const matchWithCtx = {
      ruleId: 'new_hosts',
      ruleName: 'Sudden Access to Many Unfamiliar Hosts',
      severity: 'high' as const,
      username: 'it_support',
      timestamp: '2026-10-14T14:00:00Z',
      evidence: { eventIds: ['e1'], description: 'test' },
      contextSuppression: { reason: 'helpdesk role', scoreMultiplier: 0.6 },
    }
    const matchWithoutCtx = { ...matchWithCtx, contextSuppression: undefined }

    const scoreWith = calculateIncidentRiskScore([matchWithCtx])
    const scoreWithout = calculateIncidentRiskScore([matchWithoutCtx])

    // With suppression (0.6x multiplier on 40 base): 24. Without: 40.
    expect(scoreWith).toBeLessThan(scoreWithout)
    expect(scoreWith).toBe(24)
    expect(scoreWithout).toBe(40)
  })
})
