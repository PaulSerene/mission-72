/**
 * Behavioral Baseline Builder — Mission 72
 *
 * Builds per-user behavioral profiles exclusively from events inside the
 * configured training period. Events outside the training window are never
 * used for baseline learning.
 *
 * A baseline captures:
 *   - Known source IPs (successful logins only)
 *   - Known destination hosts
 *   - Known source locations (from IP-location enrichment)
 *   - Login hour distribution (UTC, 0–23)
 *   - Training event count and quality status
 */

import type { AuthEvent, AnalysisConfig, UserBaseline, BaselineStatus } from '@/types'

// ─── Status Thresholds ────────────────────────────────────────────────────────

/** Minimum events for a 'sufficient' baseline (detection rules apply with full confidence). */
const SUFFICIENT_THRESHOLD = 5
/** Minimum events for a 'limited' baseline (rules apply but results are low-confidence). */
const LIMITED_THRESHOLD = 1

// ─── Builder ─────────────────────────────────────────────────────────────────

/**
 * Build per-user behavioral baselines from the given events and configuration.
 *
 * Only events whose UTC timestamps fall within [config.trainingPeriod.start,
 * config.trainingPeriod.end) are considered. Events outside this window are
 * silently ignored — they must never influence learned values.
 *
 * Users who appear only in the analysis period (no training events) receive a
 * baseline with status 'none'. The caller should treat their alerts as
 * lower-confidence and note them in AnalysisResult.insufficientBaselineUsers.
 *
 * @param events   All ingested AuthEvents (training + analysis periods combined).
 * @param config   Analysis configuration (defines trainingPeriod).
 * @returns        Map from username → UserBaseline.
 */
export function buildBaselines(
  events: AuthEvent[],
  config: AnalysisConfig,
): Map<string, UserBaseline> {
  const trainStart = new Date(config.trainingPeriod.start).getTime()
  const trainEnd = new Date(config.trainingPeriod.end).getTime()

  // Collect all usernames across the full event set (so analysis-only users
  // still get a 'none' baseline rather than being absent from the map).
  const allUsers = new Set(events.map(e => e.username))

  // Accumulate training data per user
  const data = new Map<string, {
    ips: Set<string>
    hosts: Set<string>
    locations: Set<string>
    hourCounts: number[]
    count: number
  }>()

  for (const ev of events) {
    const evTime = new Date(ev.timestamp).getTime()
    // Strict training period: [start, end)
    if (evTime < trainStart || evTime >= trainEnd) continue
    // Duplicate events are skipped — they would inflate counts artificially
    if (ev.isDuplicate) continue

    if (!data.has(ev.username)) {
      data.set(ev.username, {
        ips: new Set(),
        hosts: new Set(),
        locations: new Set(),
        hourCounts: new Array<number>(24).fill(0),
        count: 0,
      })
    }

    const d = data.get(ev.username)!
    d.count++

    // Learn source IPs only from successful logins (failures may be from attackers)
    if (ev.outcome === 'success') {
      d.ips.add(ev.sourceIp)
      if (ev.location) d.locations.add(ev.location)
      if (ev.destination) d.hosts.add(ev.destination)
    }

    // Login hour distribution: track all events in configured timezone
    const { hour } = getHourAndDayInTimezone(ev.timestamp, config.timezone)
    d.hourCounts[hour]++
  }

  // Build baselines for all observed users
  const baselines = new Map<string, UserBaseline>()

  for (const username of allUsers) {
    const d = data.get(username)

    if (!d || d.count === 0) {
      // No training events for this user
      baselines.set(username, makeEmptyBaseline(username))
      continue
    }

    const status: BaselineStatus =
      d.count >= SUFFICIENT_THRESHOLD ? 'sufficient'
      : d.count >= LIMITED_THRESHOLD ? 'limited'
      : 'none'

    baselines.set(username, {
      username,
      knownIps: d.ips,
      knownHosts: d.hosts,
      knownLocations: d.locations,
      loginHourCounts: d.hourCounts,
      trainingEventCount: d.count,
      status,
    })
  }

  return baselines
}

/**
 * Create a placeholder baseline for a user with no training data.
 * Callers must check `status === 'none'` and fall back to configured defaults.
 */
export function makeEmptyBaseline(username: string): UserBaseline {
  return {
    username,
    knownIps: new Set(),
    knownHosts: new Set(),
    knownLocations: new Set(),
    loginHourCounts: new Array<number>(24).fill(0),
    trainingEventCount: 0,
    status: 'none',
  }
}

/**
 * Return true if the given UTC hour is considered "unusual" for this user.
 *
 * For users with sufficient/limited baselines:
 *   Unusual = the user logged in 0 times at this hour during training.
 *
 * For users with 'none' baseline:
 *   Unusual = the hour falls within the configured off-hours window.
 *   Off-hours wraps midnight: offHoursStart=22, offHoursEnd=6 → hours 22–5 are off-hours.
 */
export function isUnusualHour(
  hour: number,
  baseline: UserBaseline,
  offHoursStart: number,
  offHoursEnd: number,
): boolean {
  // Check if the hour falls in the configured off-hours window (e.g. 22:00 to 06:00 UTC)
  const isOffHours =
    offHoursStart <= offHoursEnd
      ? hour >= offHoursStart && hour < offHoursEnd
      : hour >= offHoursStart || hour < offHoursEnd

  if (!isOffHours) {
    return false
  }

  // If in off-hours, check if user routinely logs in during this hour
  if (baseline.status !== 'none') {
    return baseline.loginHourCounts[hour] === 0
  }

  return true
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
      }
      if (p.type === 'weekday') {
        weekdayStr = p.value
      }
    }
    const days: Record<string, number> = {
      Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6,
    }
    const dayOfWeek = weekdayStr in days ? days[weekdayStr] : d.getUTCDay()
    return { hour, dayOfWeek }
  } catch {
    const d = new Date(isoTimestamp)
    return { hour: d.getUTCHours(), dayOfWeek: d.getUTCDay() }
  }
}

