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
  AccountRole,
  ContextSuppression,
  SuppressedAlert,
  IpLocationRecord,
} from '@/types'
import { isUnusualHour } from './baseline'
import { parseVpnCidrs, lookupMatchingVpn, type ParsedVpnCidr } from './assets'
import {
  isValidCoordinate,
  haversineDistanceKm,
  calculateTravelSpeedKmH,
  DEFAULT_MAX_TRAVEL_SPEED_KM_H,
  DEFAULT_MIN_TRAVEL_DISTANCE_KM,
} from './geo'

// ─── Rule Score Weights (exported for incident risk scoring) ──────────────────

export const RULE_SCORES: Record<string, number> = {
  brute_force: 40,
  burst_success: 55,
  password_spray: 35,
  unusual_hours: 25,
  new_ip_location: 35,
  new_hosts: 40,
  impossible_travel: 50,
}

// ─── Context Passed to All Rules ──────────────────────────────────────────────

export interface RuleContext {
  baselines: Map<string, UserBaseline>
  config: AnalysisConfig
  ipLocations: IpLocationRecord[]
  /** Pre-parsed VPN CIDRs with metadata for matching. */
  vpnCidrs: ParsedVpnCidr[]
  /**
   * Account role map (username → AccountRole).
   * Accounts absent from this map are treated as 'regular'.
   */
  accountRoles: Record<string, AccountRole>
  /**
   * Global set of authorized helpdesk accounts.
   * Combined with per-maintenance-window authorizedHelpdeskAccounts.
   */
  authorizedHelpdeskAccounts: Set<string>
  /**
   * Audit log of alert signals suppressed by legitimate security context.
   */
  suppressedAlerts?: SuppressedAlert[]
}

// ─── Shared Helpers ───────────────────────────────────────────────────────────

function ms(ts: string): number {
  return new Date(ts).getTime()
}

function sortByTime(evs: AuthEvent[]): AuthEvent[] {
  return [...evs].sort((a, b) => a.timestamp.localeCompare(b.timestamp))
}

/**
 * Convert an ISO timestamp to local hour (0-23) and day-of-week (0=Sun..6=Sat)
 * for a specific IANA timezone.
 */
export function getHourAndDayInTimezone(
  isoTimestamp: string,
  timezone: string = 'UTC',
): { hour: number; dayOfWeek: number } {
  try {
    const d = new Date(isoTimestamp)
    const fmt = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      hour: 'numeric',
      hour12: false,
      weekday: 'short',
    })
    const parts = fmt.formatToParts(d)
    let hour = d.getUTCHours()
    let weekdayStr = ''
    for (const p of parts) {
      if (p.type === 'hour') {
        const val = parseInt(p.value, 10)
        hour = val === 24 ? 0 : val
      } else if (p.type === 'weekday') {
        weekdayStr = p.value
      }
    }
    const days: Record<string, number> = {
      Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6,
    }
    const dayOfWeek = days[weekdayStr] ?? d.getUTCDay()
    return { hour, dayOfWeek }
  } catch {
    const d = new Date(isoTimestamp)
    return { hour: d.getUTCHours(), dayOfWeek: d.getUTCDay() }
  }
}

/**
 * Return whether an event falls within a configured maintenance window
 * that permits off-hours activity for this user.
 */
export function isInMaintenanceWindow(
  ev: AuthEvent,
  windows: MaintenanceWindow[],
  defaultTimezone: string = 'UTC',
): { inWindow: boolean; window?: MaintenanceWindow; reason?: string } {
  for (const w of windows) {
    if (w.start && w.end) {
      const evMs = ms(ev.timestamp)
      const wStartMs = ms(w.start)
      const wEndMs = ms(w.end)
      if (evMs < wStartMs || evMs >= wEndMs) continue
    } else {
      const tz = w.timezone || defaultTimezone || 'UTC'
      const { hour, dayOfWeek } = getHourAndDayInTimezone(ev.timestamp, tz)
      const { startHour, endHour } = w
      if (startHour === undefined || endHour === undefined) continue
      let hourMatch = false
      let isPreviousDayWindow = false

      if (startHour < endHour) {
        hourMatch = hour >= startHour && hour < endHour
      } else {
        // Midnight crossing (e.g. 22:00 to 06:00)
        if (hour >= startHour) {
          hourMatch = true
          isPreviousDayWindow = false
        } else if (hour < endHour) {
          hourMatch = true
          isPreviousDayWindow = true
        }
      }

      if (!hourMatch) continue

      if (w.daysOfWeek && w.daysOfWeek.length > 0) {
        const targetDay = isPreviousDayWindow ? (dayOfWeek + 6) % 7 : dayOfWeek
        if (!w.daysOfWeek.includes(targetDay)) continue
      }
    }

    // User filter (if specified, only allowedUsers or approvedAccounts are exempted)
    const allowed = (w.allowedUsers ?? [])
      .concat(w.approvedAccounts ?? [])
      .concat(w.authorizedHelpdeskAccounts ?? [])
    if (allowed.length > 0 && !allowed.includes(ev.username)) {
      continue
    }

    return {
      inWindow: true,
      window: w,
      reason: `Event for "${ev.username}" is within declared maintenance window ${w.id ? `[${w.id}]` : ''} (${w.description ?? w.scope ?? 'Scheduled maintenance'})`,
    }
  }

  return { inWindow: false }
}

export interface MaintenanceEvaluationResult {
  inWindow: boolean
  window?: MaintenanceWindow
  authorized: boolean
  hostPermitted: boolean
  activityPermitted: boolean
  exemptionApplies: boolean
  reason: string
}

/**
 * Evaluate whether an event represents authorized helpdesk maintenance activity.
 *
 * Requirements:
 * 1. Event falls within an active maintenance window (normalized to window timezone, supports midnight wrap).
 * 2. Account is explicitly authorized (in window or global authorizedHelpdeskAccounts). Username containing "helpdesk" is not enough!
 * 3. Destination host is within permittedHosts scope (if configured).
 * 4. Activity/service is within permittedActivities scope (if configured).
 */
export function evaluateMaintenanceContext(
  ev: AuthEvent,
  windows: MaintenanceWindow[],
  globalHelpdeskAccounts: Set<string>,
  defaultTimezone: string = 'UTC',
): MaintenanceEvaluationResult {
  for (const w of windows) {
    if (w.start && w.end) {
      const evMs = ms(ev.timestamp)
      const wStartMs = ms(w.start)
      const wEndMs = ms(w.end)
      if (evMs < wStartMs || evMs >= wEndMs) continue
    } else {
      const tz = w.timezone || defaultTimezone || 'UTC'
      const { hour, dayOfWeek } = getHourAndDayInTimezone(ev.timestamp, tz)
      const { startHour, endHour } = w
      if (startHour === undefined || endHour === undefined) continue
      let hourMatch = false
      let isPreviousDayWindow = false

      if (startHour < endHour) {
        hourMatch = hour >= startHour && hour < endHour
      } else {
        if (hour >= startHour) {
          hourMatch = true
          isPreviousDayWindow = false
        } else if (hour < endHour) {
          hourMatch = true
          isPreviousDayWindow = true
        }
      }

      if (!hourMatch) continue

      if (w.daysOfWeek && w.daysOfWeek.length > 0) {
        const targetDay = isPreviousDayWindow ? (dayOfWeek + 6) % 7 : dayOfWeek
        if (!w.daysOfWeek.includes(targetDay)) continue
      }
    }

    // Active maintenance window!
    // Check explicit authorization: Must be explicitly configured, not inferred from username
    const authorized =
      globalHelpdeskAccounts.has(ev.username) ||
      (w.authorizedHelpdeskAccounts?.includes(ev.username) ?? false) ||
      (w.approvedAccounts?.includes(ev.username) ?? false) ||
      (w.allowedUsers?.includes(ev.username) ?? false)

    // Check destination host scope
    let hostPermitted = true
    if (w.permittedHosts && w.permittedHosts.length > 0) {
      hostPermitted = ev.destination ? w.permittedHosts.includes(ev.destination) : false
    } else if (w.scope && /all workstations/i.test(w.scope)) {
      hostPermitted = ev.destination
        ? ev.destination.toUpperCase().startsWith('WS-') ||
          ev.destination.toLowerCase().includes('workstation') ||
          ev.destination.toLowerCase().includes('pc')
        : true
    }

    // Check activity scope
    let activityPermitted = true
    if (w.permittedActivities && w.permittedActivities.length > 0) {
      const acts = w.permittedActivities.map(a => a.toLowerCase().trim())
      const evLogon = ev.logonType ? String(ev.logonType).toLowerCase().trim() : null
      const evType = ev.eventType ? String(ev.eventType).toLowerCase().trim() : null
      activityPermitted = (evLogon !== null && acts.includes(evLogon)) || (evType !== null && acts.includes(evType))
    }

    const exemptionApplies = authorized && hostPermitted && activityPermitted

    let reason = ''
    if (!authorized) {
      reason = `Account "${ev.username}" is not explicitly authorized for maintenance in window ${w.id ?? 'default'}`
    } else if (!hostPermitted) {
      reason = `Destination host "${ev.destination}" is outside permitted maintenance scope for window ${w.id ?? 'default'}`
    } else if (!activityPermitted) {
      reason = `Activity "${ev.logonType ?? ev.eventType}" is outside permitted maintenance activities for window ${w.id ?? 'default'}`
    } else {
      reason = `Legitimate helpdesk activity by "${ev.username}" on permitted host "${ev.destination}" during approved maintenance window ${w.id ? `[${w.id}]` : ''}`
    }

    return {
      inWindow: true,
      window: w,
      authorized,
      hostPermitted,
      activityPermitted,
      exemptionApplies,
      reason,
    }
  }

  return {
    inWindow: false,
    authorized: globalHelpdeskAccounts.has(ev.username),
    hostPermitted: false,
    activityPermitted: false,
    exemptionApplies: false,
    reason: 'Event timestamp is outside declared maintenance windows',
  }
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
  contextSuppression?: ContextSuppression,
): RuleMatch {
  return { ruleId, ruleName, severity, username, timestamp, evidence, mitreTactic, contextSuppression }
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
      const successes = inWindow.filter(e => e.outcome === 'success')

      for (const succ of successes) {
        const failuresBefore = inWindow.filter(
          e => e.outcome === 'failure' && ms(e.timestamp) < ms(succ.timestamp),
        )

        if (failuresBefore.length >= failureCount) {
          matches.push(match(
            'burst_success',
            'Failure Burst Followed by Successful Login',
            'high',
            username,
            sorted[i].timestamp,
            {
              eventIds: [...failuresBefore.map(e => e.id), succ.id],
              description: `${failuresBefore.length} failures then success within ${windowSeconds}s — possible successful brute-force for "${username}"`,
              data: {
                failureCount: failuresBefore.length,
                successAt: succ.timestamp,
                sourceIp: succ.sourceIp,
              },
            },
            'Credential Access (T1110)',
          ))
          // Mark window events as processed
          inWindow.forEach(e => reported.add(e.id))
          break
        }
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
    const maint = isInMaintenanceWindow(ev, ctx.config.maintenanceWindows, ctx.config.timezone)
    if (maint.inWindow) {
      ctx.suppressedAlerts?.push({
        id: `suppressed-maint-hours-${ev.id}`,
        ruleId: 'unusual_hours',
        ruleName: 'Login During Unusual Hours',
        username: ev.username,
        timestamp: ev.timestamp,
        policyType: 'maintenance_window',
        reason: maint.reason ?? 'Suppressed by maintenance window policy',
        evidence: {
          eventIds: [ev.id],
          description: `Off-hours login during declared maintenance window ${maint.window?.id ?? ''}`,
          data: {
            windowId: maint.window?.id,
            startHour: maint.window?.startHour,
            endHour: maint.window?.endHour,
            timezone: maint.window?.timezone ?? ctx.config.timezone,
          },
        },
      })
      continue
    }

    const baseline = ctx.baselines.get(ev.username)
    if (!baseline) continue // no baseline → can't assess; skip

    const { hour } = getHourAndDayInTimezone(ev.timestamp, ctx.config.timezone)
    if (!isUnusualHour(hour, baseline, offHoursStart, offHoursEnd)) continue

    const tzLabel = ctx.config.timezone ?? 'UTC'
    const note = baseline.status === 'none'
      ? `User "${ev.username}" has no baseline — off-hours login at ${String(hour).padStart(2, '0')}:00 ${tzLabel}`
      : `User "${ev.username}" has never logged in at ${String(hour).padStart(2, '0')}:00 ${tzLabel} during the training period`

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
 * Full suppression: if the source IP falls within an approved VPN CIDR range.
 * Audit evidence and policy details are recorded for security transparency.
 *
 * Partial suppression (contextSuppression): if the account role is 'admin' or
 * 'developer' and the account has a VPN-adjacent travel pattern — the match
 * is retained but risk score multiplier is reduced to 0.5.
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

    // Full suppression: approved VPN IPs are known-good remote access points
    const matchingVpn = lookupMatchingVpn(ev.sourceIp, ctx.vpnCidrs)
    if (matchingVpn) {
      const baseline = ctx.baselines.get(ev.username)
      const isNewIp = !baseline || !baseline.knownIps.has(ev.sourceIp)
      const isNewLocation = !baseline || (ev.location !== null && !baseline.knownLocations.has(ev.location))

      if (isNewIp || isNewLocation) {
        const vpnDesc = matchingVpn.description ?? matchingVpn.cidr
        const vpnId = matchingVpn.id ? ` [${matchingVpn.id}]` : ''
        ctx.suppressedAlerts?.push({
          id: `suppressed-vpn-${ev.id}`,
          ruleId: 'new_ip_location',
          ruleName: 'Login from Unfamiliar IP or Location',
          username: ev.username,
          timestamp: ev.timestamp,
          policyType: 'approved_vpn',
          reason: `Source IP ${ev.sourceIp} is within approved corporate VPN range (${vpnDesc}${vpnId}). New-location alert suppressed.`,
          evidence: {
            eventIds: [ev.id],
            description: `Legitimate travelling employee or remote login via approved corporate VPN (${matchingVpn.cidr})`,
            data: {
              sourceIp: ev.sourceIp,
              vpnCidr: matchingVpn.cidr,
              vpnId: matchingVpn.id,
              vpnDescription: matchingVpn.description,
              location: ev.location,
            },
          },
        })
      }
      continue
    }

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

    // Context-aware partial suppression: developers and admins frequently travel
    // or work remotely. Retain the alert but reduce risk contribution.
    const role = ctx.accountRoles[ev.username] ?? 'regular'
    let contextSuppression: ContextSuppression | undefined
    if (role === 'developer' || role === 'admin') {
      contextSuppression = {
        reason: `Account role "${role}" is expected to occasionally access from new locations. Risk contribution reduced.`,
        scoreMultiplier: 0.5,
      }
    }

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
          accountRole: role,
        },
      },
      'Initial Access (T1078)',
      contextSuppression,
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
 * Context-aware suppression:
 *   - Fully suppressed for authorized helpdesk accounts during active maintenance
 *     windows when accessing permitted hosts and performing permitted activities.
 *   - Explanations and evidence are recorded in suppressedAlerts.
 *   - Outside maintenance windows or for out-of-scope targets, the exemption does
 *     not apply. A partial context reduction is noted for helpdesk accounts.
 *   - Regular users accessing unfamiliar hosts outside maintenance trigger normal alerts.
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

    const role = ctx.accountRoles[username] ?? 'regular'
    const sorted = sortByTime(userEvents)

    // Evaluate maintenance exemptions for all events from this user
    const exemptEventIds = new Set<string>()
    for (const ev of sorted) {
      const evalRes = evaluateMaintenanceContext(
        ev,
        ctx.config.maintenanceWindows,
        ctx.authorizedHelpdeskAccounts,
        ctx.config.timezone,
      )
      if (evalRes.exemptionApplies) {
        exemptEventIds.add(ev.id)
        ctx.suppressedAlerts?.push({
          id: `suppressed-maint-host-${ev.id}`,
          ruleId: 'new_hosts',
          ruleName: 'Sudden Access to Many Unfamiliar Hosts',
          username: ev.username,
          timestamp: ev.timestamp,
          policyType: 'maintenance_window',
          reason: evalRes.reason,
          evidence: {
            eventIds: [ev.id],
            description: `Authorized helpdesk multi-host activity on ${ev.destination} during approved maintenance window`,
            data: {
              destination: ev.destination,
              windowId: evalRes.window?.id,
              windowHours: `${evalRes.window?.startHour}:00–${evalRes.window?.endHour}:00`,
              accountRole: role,
            },
          },
        })
      }
    }

    // Only non-exempt events count towards unauthorized unfamiliar host access
    const nonExemptEvents = sorted.filter(e => !exemptEventIds.has(e.id))
    const reported = new Set<string>()

    for (let i = 0; i < nonExemptEvents.length; i++) {
      if (reported.has(nonExemptEvents[i].id)) continue

      const windowStart = ms(nonExemptEvents[i].timestamp)
      const windowEnd = windowStart + windowMs
      const inWindow = nonExemptEvents.filter((e, j) => j >= i && ms(e.timestamp) <= windowEnd)

      // Count new hosts (not in training baseline)
      const newHosts = new Set(
        inWindow
          .map(e => e.destination!)
          .filter(host => !baseline.knownHosts.has(host)),
      )

      if (newHosts.size >= newHostCount) {
        const matchingEvents = inWindow.filter(e => newHosts.has(e.destination!))

        // Partial suppression for helpdesk/developer roles outside maintenance windows
        let contextSuppression: ContextSuppression | undefined
        if (role === 'helpdesk' || role === 'developer') {
          contextSuppression = {
            reason: `Account role "${role}" is expected to access multiple hosts. Review is still recommended outside maintenance windows or for unapproved host scope.`,
            scoreMultiplier: 0.6,
          }
        }

        matches.push(match(
          'new_hosts',
          'Sudden Access to Many Unfamiliar Hosts',
          'high',
          username,
          nonExemptEvents[i].timestamp,
          {
            eventIds: matchingEvents.map(e => e.id),
            description: `"${username}" accessed ${newHosts.size} previously-unseen hosts within ${windowHours}h`,
            data: {
              newHostCount: newHosts.size,
              newHosts: [...newHosts].slice(0, 20), // cap for display
              windowHours,
              knownHostCount: baseline.knownHosts.size,
              accountRole: role,
            },
          },
          'Discovery (T1046)',
          contextSuppression,
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

// ─── Rule 7: Impossible Travel Between Geographically Incompatible Logins ────

/**
 * Impossible Travel Between Geographically Incompatible Logins
 *
 * Examines consecutive successful logins for the same account.
 * Uses the Haversine formula to compute great-circle distance between coordinates.
 * Calculates required minimum travel speed from distance and positive elapsed time.
 *
 * Triggers an impossible-travel alert only when:
 * 1. Both events have valid timestamps and are successful logins for the same account.
 * 2. Both events have valid, trustworthy coordinates in [-90, 90] and [-180, 180].
 * 3. The second event (or transition) occurs within the analysis period.
 * 4. The elapsed time is positive (t2 > t1).
 * 5. The locations are sufficiently far apart (≥ minDistanceKm, default 100 km).
 * 6. The required travel speed exceeds the configured conservative threshold (> maxSpeedKmH, default 1000 km/h).
 *
 * VPN Context Exception:
 * If either event originates from an approved corporate VPN CIDR, the egress IP location
 * reflects VPN infrastructure rather than verified physical user travel.
 * The impossible-travel alert is suppressed with a clear audit trail.
 */
export function detectImpossibleTravel(events: AuthEvent[], ctx: RuleContext): RuleMatch[] {
  const analysisStart = ms(ctx.config.analysisPeriod.start)
  const analysisEnd = ms(ctx.config.analysisPeriod.end)
  const maxSpeedKmH =
    ctx.config.rules.impossibleTravel?.maxSpeedKmH ?? DEFAULT_MAX_TRAVEL_SPEED_KM_H
  const minDistanceKm =
    ctx.config.rules.impossibleTravel?.minDistanceKm ?? DEFAULT_MIN_TRAVEL_DISTANCE_KM

  const matches: RuleMatch[] = []

  // Group successful non-duplicate events by username
  const byUser = new Map<string, AuthEvent[]>()
  for (const ev of events) {
    if (ev.isDuplicate) continue
    if (ev.outcome !== 'success') continue

    const list = byUser.get(ev.username) ?? []
    list.push(ev)
    byUser.set(ev.username, list)
  }

  for (const [username, userEvents] of byUser) {
    // Sort chronologically ascending
    const sorted = [...userEvents].sort((a, b) => a.timestamp.localeCompare(b.timestamp))

    for (let i = 1; i < sorted.length; i++) {
      const prev = sorted[i - 1]
      const curr = sorted[i]

      const tPrev = ms(prev.timestamp)
      const tCurr = ms(curr.timestamp)

      // Skip invalid timestamps
      if (isNaN(tPrev) || isNaN(tCurr)) continue

      // Must have positive elapsed time (equal or out-of-order timestamps skipped)
      const elapsedMs = tCurr - tPrev
      if (elapsedMs <= 0) continue

      // Alert only if current event (the destination of the transition) is in analysis period
      if (tCurr < analysisStart || tCurr >= analysisEnd) continue

      // Both events must have valid, trustworthy coordinates
      if (
        !isValidCoordinate(prev.latitude, prev.longitude) ||
        !isValidCoordinate(curr.latitude, curr.longitude)
      ) {
        continue
      }

      // Calculate great-circle distance
      const distanceKm = haversineDistanceKm(
        prev.latitude!,
        prev.longitude!,
        curr.latitude!,
        curr.longitude!,
      )

      // Must exceed minimum distance to avoid metro-area ISP IP jitter
      if (distanceKm < minDistanceKm) continue

      // Calculate required velocity
      const speedKmH = calculateTravelSpeedKmH(distanceKm, elapsedMs)
      if (speedKmH <= maxSpeedKmH) continue

      // Check VPN Context Suppression:
      // If either event originates from an approved corporate VPN CIDR, the egress IP location
      // represents VPN gateway infrastructure rather than verified physical user travel.
      const vpnPrev = lookupMatchingVpn(prev.sourceIp, ctx.vpnCidrs)
      const vpnCurr = lookupMatchingVpn(curr.sourceIp, ctx.vpnCidrs)

      if (vpnPrev || vpnCurr) {
        const matchingVpn = vpnCurr ?? vpnPrev
        ctx.suppressedAlerts?.push({
          id: `suppressed-vpn-travel-${curr.id}`,
          ruleId: 'impossible_travel',
          ruleName: 'Impossible Travel Between Geographically Incompatible Logins',
          username,
          timestamp: curr.timestamp,
          policyType: 'approved_vpn',
          reason: `Login sequence from ${prev.location ?? prev.sourceIp} to ${curr.location ?? curr.sourceIp} involves approved corporate VPN (${matchingVpn?.cidr ?? 'approved VPN'}). Egress IP location reflects VPN gateway infrastructure rather than verified physical user travel. Impossible travel alert suppressed to prevent false positive.`,
          evidence: {
            eventIds: [prev.id, curr.id],
            description: `VPN gateway egress (${matchingVpn?.cidr}) distorts geographic velocity calculation (${Math.round(speedKmH)} km/h over ${Math.round(distanceKm)} km)`,
            data: {
              event1Id: prev.id,
              event2Id: curr.id,
              distanceKm: Math.round(distanceKm),
              speedKmH: Math.round(speedKmH),
              vpnCidr: matchingVpn?.cidr,
            },
          },
        })
        continue
      }

      const elapsedMinutes = elapsedMs / (60 * 1000)
      const loc1 = prev.location ?? prev.sourceIp
      const loc2 = curr.location ?? curr.sourceIp
      const severity: Severity = speedKmH >= 2000 ? 'critical' : 'high'

      matches.push(
        match(
          'impossible_travel',
          'Impossible Travel Between Geographically Incompatible Logins',
          severity,
          username,
          curr.timestamp,
          {
            eventIds: [prev.id, curr.id],
            description: `Impossible travel: User "${username}" authenticated from ${loc1} and ${loc2} (${Math.round(distanceKm)} km apart) within ${elapsedMinutes < 1 ? '<1' : Math.round(elapsedMinutes)}m. Required travel speed of ${Math.round(speedKmH)} km/h exceeds maximum plausible threshold (${maxSpeedKmH} km/h).`,
            data: {
              event1Id: prev.id,
              event2Id: curr.id,
              event1Timestamp: prev.timestamp,
              event2Timestamp: curr.timestamp,
              event1Location: loc1,
              event2Location: loc2,
              event1Ip: prev.sourceIp,
              event2Ip: curr.sourceIp,
              distanceKm: Math.round(distanceKm),
              elapsedMinutes: Math.round(elapsedMinutes * 10) / 10,
              speedKmH: Math.round(speedKmH),
              maxSpeedThreshold: maxSpeedKmH,
            },
          },
          'Initial Access (T1078)',
        ),
      )
    }
  }

  return matches
}

// ─── Run All Rules ────────────────────────────────────────────────────────────

/**
 * Run all seven detection rules against the provided event set.
 * Returns all RuleMatches across all rules, unsorted.
 */
export function runAllRules(events: AuthEvent[], ctx: RuleContext): RuleMatch[] {
  // Pre-parse VPN CIDRs once for all rules that need them
  const ctxWithVpn: RuleContext = {
    ...ctx,
    vpnCidrs: parseVpnCidrs(ctx.config.approvedVpnCidrs),
    // Merge config-level accountRoles and authorizedHelpdeskAccounts
    accountRoles: ctx.config.accountRoles ?? {},
    authorizedHelpdeskAccounts: new Set([
      ...(ctx.config.authorizedHelpdeskAccounts ?? []),
      ...ctx.authorizedHelpdeskAccounts,
    ]),
  }

  return [
    ...detectBruteForce(events, ctxWithVpn),
    ...detectBurstSuccess(events, ctxWithVpn),
    ...detectPasswordSpray(events, ctxWithVpn),
    ...detectUnusualHours(events, ctxWithVpn),
    ...detectNewIpOrLocation(events, ctxWithVpn),
    ...detectNewHosts(events, ctxWithVpn),
    ...detectImpossibleTravel(events, ctxWithVpn),
  ]
}
