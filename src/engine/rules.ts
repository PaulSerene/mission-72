/**
 * Detection Rules — Mission 72
 *
 * Six rule functions, each returning RuleMatch[] for their respective threat.
 * Rules are pure functions of (events, context) — no side effects, no global state.
 * They are deterministic: out-of-order or duplicate inputs produce the same output.
 *
 * Configurable thresholds live in AnalysisConfig.rules.
 * Suppression logic (VPN, maintenance windows) is applied inside each rule.
 *
 * MITRE ATT&CK tags are informational and not used for detection decisions.
 *
 * False-positive suppression is scoped: VPN suppresses only new_ip_location;
 * maintenance windows suppress only unusual_hours. All other rules fire normally.
 *
 * Risk scores per rule (used by incidents.ts — additive, capped at 100):
 *   brute_force:       40
 *   burst_success:     55
 *   password_spray:    35 per victim (max 70 for the spray source)
 *   unusual_hours:     25
 *   new_ip_location:   35
 *   new_hosts:         40
 */

import type {
  AuthEvent,
  AnalysisConfig,
  RuleMatch,
  Evidence,
  Severity,
  MaintenanceWindow,
  UserBaseline,
} from '@/types'
import { isUnusualHour } from './baseline'
import { parseVpnCidrs, isIpInAnyCidr } from './assets'
import type { IpLocationRecord } from '@/types'

// ─── Rule Score Weights (exported for incident risk scoring) ──────────────────

export const RULE_SCORES: Record<string, number> = {
  brute_force: 40,
  burst_success: 55,
  password_spray: 35,
  unusual_hours: 25,
  new_ip_location: 35,
  new_hosts: 40,
}

// ─── Context Passed to All Rules ──────────────────────────────────────────────

export interface RuleContext {
  baselines: Map<string, UserBaseline>
  config: AnalysisConfig
  ipLocations: IpLocationRecord[]
  /** Pre-parsed VPN CIDRs for fast repeated matching. */
  vpnCidrs: Array<{ network: number; mask: number }>
}

// ─── Shared Helpers ───────────────────────────────────────────────────────────

function ms(ts: string): number {
  return new Date(ts).getTime()
}

function utcHour(ts: string): number {
  return new Date(ts).getUTCHours()
}

function sortByTime(evs: AuthEvent[]): AuthEvent[] {
  return [...evs].sort((a, b) => a.timestamp.localeCompare(b.timestamp))
}

/**
 * Return true if an event falls within a configured maintenance window
 * AND (if allowedUsers is set) the event's user is in that list.
 */
function isInMaintenanceWindow(ev: AuthEvent, windows: MaintenanceWindow[]): boolean {
  const hour = utcHour(ev.timestamp)
  const dayOfWeek = new Date(ev.timestamp).getUTCDay()

  return windows.some(w => {
    // Day of week filter
    if (w.daysOfWeek && !w.daysOfWeek.includes(dayOfWeek)) return false
    // User filter
    if (w.allowedUsers && !w.allowedUsers.includes(ev.username)) return false
    // Hour range (may wrap midnight)
    const { startHour, endHour } = w
    const inRange = startHour <= endHour
      ? hour >= startHour && hour < endHour
      : hour >= startHour || hour < endHour
    return inRange
  })
}

/** Build a RuleMatch object. */
function match(
  ruleId: string,
  ruleName: string,
  severity: Severity,
  username: string,
  timestamp: string,
  evidence: Evidence,
  mitreTactic?: string,
): RuleMatch {
  return { ruleId, ruleName, severity, username, timestamp, evidence, mitreTactic }
}

// ─── Rule 1: Brute Force ──────────────────────────────────────────────────────

/**
 * Repeated Authentication Failures
 *
 * Fires when the same user accumulates ≥ failureCount failures within a
 * sliding window of windowSeconds. The window starts at the first failure
 * and expands forward. Non-overlapping windows are reported separately.
 *
 * Only fires in the analysis period. Duplicate events are excluded.
 *
 * Suppression: none (VPN/maintenance suppression applies to other rules).
 */
export function detectBruteForce(events: AuthEvent[], ctx: RuleContext): RuleMatch[] {
  const { failureCount, windowSeconds } = ctx.config.rules.bruteForce
  const analysisStart = ms(ctx.config.analysisPeriod.start)
  const analysisEnd = ms(ctx.config.analysisPeriod.end)
  const windowMs = windowSeconds * 1000

  // Collect failures per user in analysis period (exclude duplicates)
  const byUser = new Map<string, AuthEvent[]>()
  for (const ev of events) {
    const t = ms(ev.timestamp)
    if (t < analysisStart || t >= analysisEnd) continue
    if (ev.isDuplicate) continue
    if (ev.outcome !== 'failure') continue
    const arr = byUser.get(ev.username) ?? []
    arr.push(ev)
    byUser.set(ev.username, arr)
  }

  const matches: RuleMatch[] = []

  for (const [username, userEvents] of byUser) {
    const sorted = sortByTime(userEvents)
    let i = 0
    while (i < sorted.length) {
      const windowStart = ms(sorted[i].timestamp)
      const windowEnd = windowStart + windowMs
      const inWindow = sorted.filter((e, j) => j >= i && ms(e.timestamp) <= windowEnd)
      if (inWindow.length >= failureCount) {
        matches.push(match(
          'brute_force',
          'Repeated Authentication Failures',
          'high',
          username,
          sorted[i].timestamp,
          {
            eventIds: inWindow.map(e => e.id),
            description: `${inWindow.length} login failures within ${windowSeconds}s for user "${username}"`,
            data: { failureCount: inWindow.length, windowSeconds, username },
          },
          'Credential Access (T1110)',
        ))
        // Skip past the matched window to avoid double-counting
        i += inWindow.length
      } else {
        i++
      }
    }
  }

  return matches
}

// ─── Rule 2: Failure Burst Followed by Success ────────────────────────────────

/**
 * Failure Burst Followed by Success
 *
 * Fires when a user has ≥ failureCount failures followed by a successful login,
 * all within windowSeconds. This pattern is consistent with a successful
 * brute-force or credential-stuffing attack.
 *
 * Only the first qualifying window per user is reported to avoid noise.
 */
export function detectBurstSuccess(events: AuthEvent[], ctx: RuleContext): RuleMatch[] {
  const { failureCount, windowSeconds } = ctx.config.rules.burstSuccess
  const analysisStart = ms(ctx.config.analysisPeriod.start)
  const analysisEnd = ms(ctx.config.analysisPeriod.end)
  const windowMs = windowSeconds * 1000

  // Group by user, all event types
  const byUser = new Map<string, AuthEvent[]>()
  for (const ev of events) {
    const t = ms(ev.timestamp)
    if (t < analysisStart || t >= analysisEnd) continue
    if (ev.isDuplicate) continue
    const arr = byUser.get(ev.username) ?? []
    arr.push(ev)
    byUser.set(ev.username, arr)
  }

  const matches: RuleMatch[] = []

  for (const [username, userEvents] of byUser) {
    const sorted = sortByTime(userEvents)
    const reported = new Set<string>() // window-start event IDs already reported

    for (let i = 0; i < sorted.length; i++) {
      if (sorted[i].outcome !== 'failure') continue
      if (reported.has(sorted[i].id)) continue

      const windowStart = ms(sorted[i].timestamp)
      const windowEnd = windowStart + windowMs

      // Collect all events in window
      const inWindow = sorted.filter((e, j) => j >= i && ms(e.timestamp) <= windowEnd)
      const failures = inWindow.filter(e => e.outcome === 'failure')
      const successes = inWindow.filter(e => e.outcome === 'success')

      if (failures.length >= failureCount && successes.length > 0) {
        const lastSuccess = successes[successes.length - 1]
        matches.push(match(
          'burst_success',
          'Failure Burst Followed by Successful Login',
          'high',
          username,
          sorted[i].timestamp,
          {
            eventIds: inWindow.map(e => e.id),
            description: `${failures.length} failures then success within ${windowSeconds}s — possible successful brute-force for "${username}"`,
            data: {
              failureCount: failures.length,
              successAt: lastSuccess.timestamp,
              sourceIp: lastSuccess.sourceIp,
            },
          },
          'Credential Access (T1110)',
        ))
        // Mark window events as processed
        inWindow.forEach(e => reported.add(e.id))
      }
    }
  }

  return matches
}

// ─── Rule 3: Password Spraying ────────────────────────────────────────────────

/**
 * Password Spraying
 *
 * Fires when the same source IP attempts to authenticate as ≥ userCount
 * distinct users, all failing, within windowSeconds.
 *
 * One RuleMatch is produced per targeted user (per spray source+window).
 * Evidence includes the full list of targeted users for context.
 * Duplicate events are excluded.
 */
export function detectPasswordSpray(events: AuthEvent[], ctx: RuleContext): RuleMatch[] {
  const { userCount, windowSeconds } = ctx.config.rules.passwordSpray
  const analysisStart = ms(ctx.config.analysisPeriod.start)
  const analysisEnd = ms(ctx.config.analysisPeriod.end)
  const windowMs = windowSeconds * 1000

  // Collect failures per source IP in analysis period
  const bySourceIp = new Map<string, AuthEvent[]>()
  for (const ev of events) {
    const t = ms(ev.timestamp)
    if (t < analysisStart || t >= analysisEnd) continue
    if (ev.isDuplicate) continue
    if (ev.outcome !== 'failure') continue
    const arr = bySourceIp.get(ev.sourceIp) ?? []
    arr.push(ev)
    bySourceIp.set(ev.sourceIp, arr)
  }

  const matches: RuleMatch[] = []

  for (const [sourceIp, ipEvents] of bySourceIp) {
    const sorted = sortByTime(ipEvents)
    const reported = new Set<string>() // event IDs already in a reported match

    for (let i = 0; i < sorted.length; i++) {
      if (reported.has(sorted[i].id)) continue

      const windowStart = ms(sorted[i].timestamp)
      const windowEnd = windowStart + windowMs
      const inWindow = sorted.filter((e, j) => j >= i && ms(e.timestamp) <= windowEnd)

      const distinctUsers = new Set(inWindow.map(e => e.username))
      if (distinctUsers.size >= userCount) {
        const userList = [...distinctUsers]

        // One match per targeted user
        for (const targetUser of userList) {
          const userEvents = inWindow.filter(e => e.username === targetUser)
          matches.push(match(
            'password_spray',
            'Password Spraying',
            'high',
            targetUser,
            sorted[i].timestamp,
            {
              eventIds: userEvents.map(e => e.id),
              description: `Source IP ${sourceIp} targeted ${distinctUsers.size} accounts within ${windowSeconds}s — consistent with password spraying`,
              data: { sourceIp, targetedUsers: userList, windowSeconds },
            },
            'Credential Access (T1110.003)',
          ))
        }

        inWindow.forEach(e => reported.add(e.id))
        i += inWindow.length - 1
      }
    }
  }

  // Deduplicate (same user+ruleId+timestamp may appear via overlapping windows)
  return deduplicateMatches(matches)
}

// ─── Rule 4: Unusual Login Hours ─────────────────────────────────────────────

/**
 * Login During Unusual Hours
 *
 * For users with a baseline: fires if they successfully log in at a UTC hour
 * they have never used during training.
 * For users without a baseline: fires if the login falls within the configured
 * off-hours window (offHoursStart → offHoursEnd, wrapping midnight).
 *
 * Suppression: suppressed for events falling within a configured maintenance
 * window that lists the user in allowedUsers.
 */
export function detectUnusualHours(events: AuthEvent[], ctx: RuleContext): RuleMatch[] {
  const analysisStart = ms(ctx.config.analysisPeriod.start)
  const analysisEnd = ms(ctx.config.analysisPeriod.end)
  const { offHoursStart, offHoursEnd } = ctx.config.rules.unusualHours

  const matches: RuleMatch[] = []

  for (const ev of events) {
    const t = ms(ev.timestamp)
    if (t < analysisStart || t >= analysisEnd) continue
    if (ev.isDuplicate) continue
    // Only alert on successful logins
    if (ev.outcome !== 'success') continue
    // Maintenance window suppression
    if (isInMaintenanceWindow(ev, ctx.config.maintenanceWindows)) continue

    const baseline = ctx.baselines.get(ev.username)
    if (!baseline) continue // no baseline → can't assess; skip

    const hour = utcHour(ev.timestamp)
    if (!isUnusualHour(hour, baseline, offHoursStart, offHoursEnd)) continue

    const note = baseline.status === 'none'
      ? `User "${ev.username}" has no baseline — off-hours login at ${String(hour).padStart(2, '0')}:00 UTC`
      : `User "${ev.username}" has never logged in at ${String(hour).padStart(2, '0')}:00 UTC during the training period`

    matches.push(match(
      'unusual_hours',
      'Login During Unusual Hours',
      'medium',
      ev.username,
      ev.timestamp,
      {
        eventIds: [ev.id],
        description: note,
        data: { hour, sourceIp: ev.sourceIp, baselineStatus: baseline.status },
      },
      'Initial Access (T1078)',
    ))
  }

  return matches
}

// ─── Rule 5: New IP or Location ───────────────────────────────────────────────

/**
 * Login from Unfamiliar Source IP or Location
 *
 * Fires on a SUCCESSFUL login from an IP address not seen during training,
 * where the location is also new (or no baseline exists).
 *
 * Suppression: if the source IP falls within an approved VPN CIDR range,
 * the alert is suppressed. This does not suppress other rules for the same event.
 *
 * Users with 'none' baseline: treated conservatively — any successful login
 * from any IP may be worth noting, but we only fire if the IP is new
 * (which for a 'none' user means "any IP"). We suppress to avoid alert storms
 * for service accounts that just appeared — only fire if the location is unknown.
 */
export function detectNewIpOrLocation(events: AuthEvent[], ctx: RuleContext): RuleMatch[] {
  const analysisStart = ms(ctx.config.analysisPeriod.start)
  const analysisEnd = ms(ctx.config.analysisPeriod.end)

  const matches: RuleMatch[] = []

  for (const ev of events) {
    const t = ms(ev.timestamp)
    if (t < analysisStart || t >= analysisEnd) continue
    if (ev.isDuplicate) continue
    if (ev.outcome !== 'success') continue

    // VPN suppression: approved VPN IPs are known-good new IPs
    if (isIpInAnyCidr(ev.sourceIp, ctx.vpnCidrs)) continue

    const baseline = ctx.baselines.get(ev.username)
    if (!baseline) continue

    const isNewIp = !baseline.knownIps.has(ev.sourceIp)
    const isNewLocation = ev.location !== null && !baseline.knownLocations.has(ev.location)

    // Require at least one of: new IP or new location
    if (!isNewIp && !isNewLocation) continue

    // For 'none' baseline users: only fire if location is unknown (to suppress
    // service account spam when they have no history at all)
    if (baseline.status === 'none' && ev.location === null) continue

    const parts: string[] = []
    if (isNewIp) parts.push(`new source IP: ${ev.sourceIp}`)
    if (isNewLocation && ev.location) parts.push(`new location: ${ev.location}`)

    matches.push(match(
      'new_ip_location',
      'Login from Unfamiliar IP or Location',
      'medium',
      ev.username,
      ev.timestamp,
      {
        eventIds: [ev.id],
        description: `"${ev.username}" logged in from ${parts.join(' and ')} — not observed during training`,
        data: {
          sourceIp: ev.sourceIp,
          location: ev.location,
          isNewIp,
          isNewLocation,
          knownIpCount: baseline.knownIps.size,
        },
      },
      'Initial Access (T1078)',
    ))
  }

  return matches
}

// ─── Rule 6: Sudden Access to Many New Hosts ─────────────────────────────────

/**
 * Sudden Access to Many Unfamiliar Hosts
 *
 * Fires when a user accesses ≥ newHostCount distinct hosts not seen in their
 * training baseline, within a sliding window of windowHours.
 *
 * Only events with a non-null destination are considered.
 * Duplicate events are excluded.
 * One match is reported per qualifying window per user (earliest window first).
 */
export function detectNewHosts(events: AuthEvent[], ctx: RuleContext): RuleMatch[] {
  const { newHostCount, windowHours } = ctx.config.rules.newHosts
  const analysisStart = ms(ctx.config.analysisPeriod.start)
  const analysisEnd = ms(ctx.config.analysisPeriod.end)
  const windowMs = windowHours * 3600 * 1000

  const matches: RuleMatch[] = []

  // Group by user
  const byUser = new Map<string, AuthEvent[]>()
  for (const ev of events) {
    const t = ms(ev.timestamp)
    if (t < analysisStart || t >= analysisEnd) continue
    if (ev.isDuplicate) continue
    if (!ev.destination) continue
    const arr = byUser.get(ev.username) ?? []
    arr.push(ev)
    byUser.set(ev.username, arr)
  }

  for (const [username, userEvents] of byUser) {
    const baseline = ctx.baselines.get(username)
    if (!baseline) continue

    const sorted = sortByTime(userEvents)
    const reported = new Set<string>()

    for (let i = 0; i < sorted.length; i++) {
      if (reported.has(sorted[i].id)) continue

      const windowStart = ms(sorted[i].timestamp)
      const windowEnd = windowStart + windowMs
      const inWindow = sorted.filter((e, j) => j >= i && ms(e.timestamp) <= windowEnd)

      // Count new hosts (not in training baseline)
      const newHosts = new Set(
        inWindow
          .map(e => e.destination!)
          .filter(host => !baseline.knownHosts.has(host)),
      )

      if (newHosts.size >= newHostCount) {
        const matchingEvents = inWindow.filter(e => newHosts.has(e.destination!))
        matches.push(match(
          'new_hosts',
          'Sudden Access to Many Unfamiliar Hosts',
          'high',
          username,
          sorted[i].timestamp,
          {
            eventIds: matchingEvents.map(e => e.id),
            description: `"${username}" accessed ${newHosts.size} previously-unseen hosts within ${windowHours}h`,
            data: {
              newHostCount: newHosts.size,
              newHosts: [...newHosts].slice(0, 20), // cap for display
              windowHours,
              knownHostCount: baseline.knownHosts.size,
            },
          },
          'Discovery (T1046)',
        ))
        inWindow.forEach(e => reported.add(e.id))
      }
    }
  }

  return matches
}

// ─── Deduplication Helper ─────────────────────────────────────────────────────

/**
 * Remove duplicate RuleMatches that have the same ruleId + username + timestamp.
 * Keeps the first occurrence.
 */
function deduplicateMatches(matches: RuleMatch[]): RuleMatch[] {
  const seen = new Set<string>()
  return matches.filter(m => {
    const key = `${m.ruleId}|${m.username}|${m.timestamp}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

// ─── Run All Rules ────────────────────────────────────────────────────────────

/**
 * Run all six detection rules against the provided event set.
 * Returns all RuleMatches across all rules, unsorted.
 */
export function runAllRules(events: AuthEvent[], ctx: RuleContext): RuleMatch[] {
  // Pre-parse VPN CIDRs once for all rules that need them
  const ctxWithVpn: RuleContext = {
    ...ctx,
    vpnCidrs: parseVpnCidrs(ctx.config.approvedVpnCidrs),
  }

  return [
    ...detectBruteForce(events, ctxWithVpn),
    ...detectBurstSuccess(events, ctxWithVpn),
    ...detectPasswordSpray(events, ctxWithVpn),
    ...detectUnusualHours(events, ctxWithVpn),
    ...detectNewIpOrLocation(events, ctxWithVpn),
    ...detectNewHosts(events, ctxWithVpn),
  ]
}
