/**
 * CSV Ingestion Pipeline — Mission 72
 *
 * Parses CSV log files using PapaParse with flexible field-alias resolution.
 * Normalizes events to AuthEvent, validates required fields, deduplicates
 * exact records by stable content hash, and returns a detailed IngestionReport.
 *
 * This module is intentionally framework-agnostic and has no React imports.
 *
 * Timezone handling: naive timestamps (no TZ suffix) are interpreted using
 * config.timezone via the Intl API — the browser's local timezone is never
 * assumed to equal the configured timezone.
 *
 * IPv6 CIDR is not validated here. Source IPs are validated as IPv4.
 * Non-IPv4 IPs cause the row to be rejected.
 */

import Papa from 'papaparse'
import type {
  AuthEvent,
  AnalysisConfig,
  IngestionResult,
  IngestionReport,
  InvalidRow,
  MissingFieldDiagnostic,
  EventOutcome,
  EventCategory,
  LogonType,
} from '@/types'
import { isValidCoordinate } from './geo'

// ─── Field Alias Tables ───────────────────────────────────────────────────────

const USERNAME_ALIASES = ['username', 'user', 'account', 'userid', 'user_id', 'login', 'user_name']
const SRC_IP_ALIASES = ['src_ip', 'source_ip', 'ip', 'sourceip', 'source', 'client_ip', 'srcip', 'src', 'ipaddress', 'ip_address']
const DEST_ALIASES = ['dest', 'destination', 'host', 'hostname', 'target', 'server', 'dst', 'dest_host', 'target_host', 'destination_host', 'destinationhost', 'dest_hostname', 'target_hostname']
const LOCATION_ALIASES = ['location', 'geo', 'city', 'country', 'ip_location', 'source_location', 'user_location', 'geolocation']
const TIMESTAMP_ALIASES = ['timestamp', 'time', 'datetime', 'date', 'event_time', 'log_time', 'created_at', 'ts', 'eventtime', 'logtime']
const EVENT_TYPE_ALIASES = ['event_type', 'action', 'event', 'type', 'eventtype', 'event_name', 'category']
const OUTCOME_ALIASES = ['result', 'status', 'outcome', 'success', 'logon_result', 'auth_result', 'auth_status']
const LOGON_TYPE_ALIASES = ['logon_type', 'login_type', 'auth_type', 'authtype', 'authentication_type', 'logontype']
const LATITUDE_ALIASES = ['latitude', 'lat']
const LONGITUDE_ALIASES = ['longitude', 'lon', 'long', 'lng']
const EVENT_ID_ALIASES = ['event_id', 'eventid']
const FAILURE_REASON_ALIASES = ['failure_reason', 'fail_reason', 'reason', 'error']

/**
 * Which detection rule IDs depend on each optional field.
 * Used to populate MissingFieldDiagnostic.requiredByRules.
 */
const FIELD_RULE_REQUIREMENTS: Record<string, string[]> = {
  destination: ['new_hosts'],
  event_type: [],
  logon_type: [],
}

// ─── Normalization Helpers ────────────────────────────────────────────────────

/**
 * Normalize a raw key-value row: lowercase + trim + collapse spaces in keys.
 * Returns a new Record with normalized keys pointing to trimmed values.
 */
function normalizeKeys(row: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(row)) {
    const valStr = typeof v === 'string' ? v : Array.isArray(v) ? (v as string[]).join(',') : String(v ?? '')
    out[k.toLowerCase().trim().replace(/\s+/g, '_')] = valStr.trim()
  }
  return out
}

/**
 * Scan a normalized row for the first alias that has a non-empty value.
 * Returns the value or null.
 */
function findField(row: Record<string, string>, aliases: string[]): string | null {
  for (const alias of aliases) {
    const val = row[alias]
    if (val !== undefined && val !== '') return val
  }
  return null
}

/** Normalize an event outcome string to EventOutcome. */
function normalizeOutcome(raw: string): EventOutcome {
  const v = raw.toLowerCase().trim()
  if (v === 'success' || v === 'succeeded' || v === 'true' || v === '1' || v === 'ok') return 'success'
  if (v === 'failure' || v === 'failed' || v === 'fail' || v === 'false' || v === '0' || v === 'denied') return 'failure'
  if (v === 'timeout' || v === 'timed_out' || v === 'timed out') return 'timeout'
  if (v === 'blocked' || v === 'block' || v === 'reject' || v === 'rejected') return 'blocked'
  return 'unknown'
}

/** Normalize an event type string to EventCategory. */
function normalizeEventType(raw: string): EventCategory {
  const v = raw.toLowerCase().trim().replace(/[\s-]/g, '_')
  if (v.includes('auth') || v.includes('login') || v.includes('logon') || v.includes('sign')) return 'authentication'
  if (v.includes('authz') || v.includes('access') || v.includes('permission') || v.includes('privilege')) return 'authorization'
  if (v.includes('network') || v.includes('connect') || v.includes('firewall')) return 'network'
  if (v.includes('file') || v.includes('share') || v.includes('folder')) return 'file_access'
  if (v.includes('process') || v.includes('exec') || v.includes('spawn')) return 'process'
  if (v.includes('system') || v.includes('service') || v.includes('startup') || v.includes('shutdown')) return 'system'
  return 'authentication' // most logs are auth events
}

/** Normalize a logon type string to LogonType. */
function normalizeLogonType(raw: string): LogonType {
  const v = raw.toLowerCase().trim().replace(/[\s-]/g, '_')
  if (v === '2' || v.includes('interact')) return 'interactive'
  if (v === '3' || v.includes('network')) return 'network'
  if (v === '5' || v.includes('service')) return 'service'
  if (v === '4' || v.includes('batch')) return 'batch'
  if (v === '10' || v.includes('remote') || v.includes('rdp')) return 'remote_interactive'
  if (v === '7' || v.includes('unlock')) return 'unlock'
  return 'unknown'
}

// ─── IPv4 Validation ─────────────────────────────────────────────────────────

/**
 * Returns true if the string is a syntactically valid IPv4 address.
 * Rejects IPs with any octet > 255 or non-numeric components.
 */
export function isValidIpv4(ip: string): boolean {
  const parts = ip.split('.')
  if (parts.length !== 4) return false
  return parts.every(p => /^\d+$/.test(p) && parseInt(p, 10) >= 0 && parseInt(p, 10) <= 255)
}

// ─── Timezone-Aware Timestamp Parsing ────────────────────────────────────────

/**
 * Given a UTC Date, return the UTC offset (in minutes) of the specified
 * IANA timezone at that instant.
 *
 * Returns: (localTimeMs - utcTimeMs) / 60_000
 * e.g. UTC-5 returns -300, UTC+5:30 returns +330.
 */
function getTimezoneOffsetMinutes(timezone: string, utcDate: Date): number {
  const fmt = new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  })
  const parts = fmt.formatToParts(utcDate)
  const get = (type: string) => parseInt(parts.find(p => p.type === type)?.value ?? '0', 10)
  // Reconstruct the local time as if it were UTC
  const localMs = Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'), get('second'))
  return (localMs - utcDate.getTime()) / 60_000
}

/**
 * Parse a naive (no timezone) datetime string and convert to UTC ISO 8601,
 * interpreting it as being in the specified IANA timezone.
 *
 * Supported formats:
 * - YYYY-MM-DDTHH:mm:ss[.sss]  (ISO-like, no TZ)
 * - YYYY-MM-DD HH:mm:ss[.sss]  (space separator)
 * - MM/DD/YYYY HH:mm:ss         (US format)
 *
 * Returns null for unrecognized formats or unrepresentable dates.
 */
export function parseNaiveDatetime(raw: string, timezone: string): string | null {
  const t = raw.trim()

  // ISO-like: YYYY-MM-DD[T ]HH:mm:ss[.sss]
  const isoMatch = t.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?$/)
  if (isoMatch) {
    const [, yr, mo, dy, hr, mi, sc] = isoMatch.map(Number)
    if (mo < 1 || mo > 12 || dy < 1 || dy > 31 || hr > 23 || mi > 59 || sc > 59) return null
    return convertNaiveToUtc(yr, mo, dy, hr, mi, sc, timezone)
  }

  // US format: MM/DD/YYYY HH:mm:ss
  const usMatch = t.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4}) (\d{2}):(\d{2}):(\d{2})$/)
  if (usMatch) {
    const [, mo, dy, yr, hr, mi, sc] = usMatch.map(Number)
    if (mo < 1 || mo > 12 || dy < 1 || dy > 31 || hr > 23 || mi > 59 || sc > 59) return null
    return convertNaiveToUtc(yr, mo, dy, hr, mi, sc, timezone)
  }

  return null
}

/**
 * Parse a timestamp string that already contains timezone information
 * (any ISO 8601 string ending in Z or ±HH:MM).
 */
export function parseZonedDatetime(raw: string): string | null {
  if (!raw) return null
  let t = raw.trim()

  // Clean redundant offset + Z, e.g. "2026-10-12T10:00:00+00:00Z" -> "2026-10-12T10:00:00+00:00"
  t = t.replace(/([+-]\d{2}:?\d{2})\s*Z$/i, '$1')

  // Convert space separator to T if date and time
  t = t.replace(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})/, '$1T$2')

  // Format ±HHMM to ±HH:MM
  t = t.replace(/([+-]\d{2})(\d{2})$/, '$1:$2')

  // Must end with Z or ±HH:MM or timezone designation (e.g. UTC, GMT)
  if (!(/Z$|[+-]\d{2}:?\d{2}$|UTC$|GMT$/i.test(t))) return null

  const d = new Date(t)
  return isNaN(d.getTime()) ? null : d.toISOString()
}

/**
 * Parse a Unix timestamp (10-digit seconds or 13-digit milliseconds).
 */
export function parseUnixTimestamp(raw: string): string | null {
  const t = raw.trim()
  if (/^\d{10}$/.test(t)) {
    const d = new Date(parseInt(t, 10) * 1000)
    return isNaN(d.getTime()) ? null : d.toISOString()
  }
  if (/^\d{13}$/.test(t)) {
    const d = new Date(parseInt(t, 10))
    return isNaN(d.getTime()) ? null : d.toISOString()
  }
  return null
}

function convertNaiveToUtc(
  yr: number, mo: number, dy: number, hr: number, mi: number, sc: number,
  timezone: string,
): string | null {
  // Create a Date that represents these values at UTC (as a proxy for "naive local time")
  const estimatedUtcMs = Date.UTC(yr, mo - 1, dy, hr, mi, sc)
  const estimatedUtc = new Date(estimatedUtcMs)

  let offset: number
  try {
    offset = getTimezoneOffsetMinutes(timezone, estimatedUtc)
  } catch {
    return null // unknown timezone
  }

  // UTC = localTime - offset  (offset is local - UTC)
  const utcMs = estimatedUtcMs - offset * 60_000
  const result = new Date(utcMs)

  // Verify in case we landed on a DST boundary
  let verifyOffset: number
  try {
    verifyOffset = getTimezoneOffsetMinutes(timezone, result)
  } catch {
    return null
  }
  if (verifyOffset !== offset) {
    return new Date(estimatedUtcMs - verifyOffset * 60_000).toISOString()
  }

  return result.toISOString()
}

/**
 * Parse any timestamp string to a UTC ISO 8601 string.
 * Tries: unix → zoned ISO → naive (with configured timezone).
 * Returns null if all formats fail.
 */
export function parseTimestamp(raw: string, timezone: string): string | null {
  if (!raw || raw.trim() === '') return null
  return (
    parseUnixTimestamp(raw) ??
    parseZonedDatetime(raw) ??
    parseNaiveDatetime(raw, timezone)
  )
}

// ─── Stable Event ID ─────────────────────────────────────────────────────────

/**
 * FNV-1a 32-bit hash — deterministic, no external dependency.
 * Used to generate stable event IDs from normalized field content.
 * Identical records produce the same ID regardless of import order or count.
 */
function fnv1a32(str: string): number {
  let hash = 0x811c9dc5
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i)
    // Multiply by FNV prime 16777619, keeping result in uint32
    hash = Math.imul(hash, 0x01000193) >>> 0
  }
  return hash
}

/**
 * Produce a stable event ID from normalized content fields.
 * The ID is the same for identical records across multiple imports.
 */
export function stableEventId(
  username: string,
  sourceIp: string,
  utcTimestamp: string,
  outcome: string,
  destination: string,
): string {
  const content = `${username}|${sourceIp}|${utcTimestamp}|${outcome}|${destination}`
  return `ev-${fnv1a32(content).toString(16).padStart(8, '0')}`
}

// ─── Main Parse Function ──────────────────────────────────────────────────────

/**
 * Parse a CSV string containing authentication log data into normalized AuthEvents.
 *
 * @param csvText  Raw CSV string (any line ending, with or without BOM).
 * @param config   Analysis configuration (timezone, thresholds, etc.).
 * @returns        De-duplicated, sorted AuthEvents and a detailed IngestionReport.
 */
export function parseAuthCsv(csvText: string, config: AnalysisConfig): IngestionResult {
  const timezone = config.timezone || 'UTC'

  // ── 1. Parse CSV ────────────────────────────────────────────────────────────
  const parsed = Papa.parse<Record<string, string>>(csvText, {
    header: true,
    skipEmptyLines: true,
    transformHeader: (h) => h.toLowerCase().trim().replace(/\s+/g, '_'),
  })

  const rawRows: Record<string, string>[] = parsed.data

  // ── 2. Normalize & validate each row ────────────────────────────────────────
  const validEvents: AuthEvent[] = []
  const invalidRows: InvalidRow[] = []
  const seenIds = new Map<string, number>() // id → count
  let duplicateCount = 0

  // Track optional-field absences across valid rows
  const missingDestCount = { count: 0 }

  for (let rowIndex = 0; rowIndex < rawRows.length; rowIndex++) {
    const normalized = normalizeKeys(rawRows[rowIndex])

    // ── Required: timestamp ──────────────────────────────────────────────────
    const rawTs = findField(normalized, TIMESTAMP_ALIASES)
    if (rawTs === null || rawTs === '') {
      invalidRows.push({ rowIndex, reason: 'Missing or empty timestamp', raw: rawRows[rowIndex] })
      continue
    }
    const utcTs = parseTimestamp(rawTs, timezone)
    if (utcTs === null) {
      invalidRows.push({ rowIndex, reason: `Unparseable timestamp: "${rawTs}"`, raw: rawRows[rowIndex] })
      continue
    }

    // ── Required: username ───────────────────────────────────────────────────
    const username = findField(normalized, USERNAME_ALIASES)
    if (!username) {
      invalidRows.push({ rowIndex, reason: 'Missing or empty username', raw: rawRows[rowIndex] })
      continue
    }

    // ── Required: source IP ──────────────────────────────────────────────────
    const rawIp = findField(normalized, SRC_IP_ALIASES)
    if (!rawIp) {
      invalidRows.push({ rowIndex, reason: 'Missing or empty source IP', raw: rawRows[rowIndex] })
      continue
    }
    if (!isValidIpv4(rawIp)) {
      invalidRows.push({ rowIndex, reason: `Invalid IPv4 address: "${rawIp}"`, raw: rawRows[rowIndex] })
      continue
    }

    // ── Optional: destination ────────────────────────────────────────────────
    const destRaw = findField(normalized, DEST_ALIASES)
    const destination = destRaw && destRaw !== '' ? destRaw.toLowerCase().trim() : null
    if (destination === null) missingDestCount.count++

    // ── Optional: event type ─────────────────────────────────────────────────
    const rawEventType = findField(normalized, EVENT_TYPE_ALIASES)
    const eventType = rawEventType ? normalizeEventType(rawEventType) : 'authentication'

    // ── Optional: outcome (default 'unknown') ─────────────────────────────────
    const rawOutcome = findField(normalized, OUTCOME_ALIASES)
    const outcome = rawOutcome ? normalizeOutcome(rawOutcome) : 'unknown'

    // ── Optional: logon type ─────────────────────────────────────────────────
    const rawLogonType = findField(normalized, LOGON_TYPE_ALIASES)
    const logonType = rawLogonType ? normalizeLogonType(rawLogonType) : 'unknown'

    // ── Optional: location (if pre-populated in auth CSV) ────────────────────
    const rawLocation = findField(normalized, LOCATION_ALIASES)
    const location = rawLocation && rawLocation !== '' ? rawLocation.trim() : null

    // ── Optional: latitude & longitude ─────────────────────────────────────────
    const rawLat = findField(normalized, LATITUDE_ALIASES)
    const rawLon = findField(normalized, LONGITUDE_ALIASES)
    let latitude: number | null = null
    let longitude: number | null = null
    if (rawLat !== null && rawLat !== '' && rawLon !== null && rawLon !== '') {
      const latVal = parseFloat(rawLat)
      const lonVal = parseFloat(rawLon)
      if (isValidCoordinate(latVal, lonVal)) {
        latitude = latVal
        longitude = lonVal
      }
    }

    // ── Optional: raw event ID & failure reason ──────────────────────────────
    const rawEventId = findField(normalized, EVENT_ID_ALIASES)
    const rawFailureReason = findField(normalized, FAILURE_REASON_ALIASES)

    // ── Stable ID & deduplication ─────────────────────────────────────────────
    const id = rawEventId || stableEventId(username, rawIp, utcTs, outcome, destination ?? '')
    const prevCount = seenIds.get(id) ?? 0
    seenIds.set(id, prevCount + 1)
    const isDuplicate = prevCount > 0
    if (isDuplicate) duplicateCount++

    validEvents.push({
      id,
      timestamp: utcTs,
      username: username.toLowerCase().trim(),
      sourceIp: rawIp,
      destination,
      eventType,
      outcome,
      logonType,
      location: location ?? null, // filled by auth CSV or IP-location mapping
      latitude,
      longitude,
      rawRow: rowIndex,
      isDuplicate,
      rawEventId: rawEventId ?? undefined,
      failureReason: rawFailureReason ?? undefined,
    })
  }

  // ── 3. Sort by timestamp ascending ──────────────────────────────────────────
  validEvents.sort((a, b) => a.timestamp.localeCompare(b.timestamp))

  // ── 4. Build missing-field diagnostics ──────────────────────────────────────
  const missingFields: MissingFieldDiagnostic[] = []
  if (missingDestCount.count > 0) {
    missingFields.push({
      field: 'destination',
      requiredByRules: FIELD_RULE_REQUIREMENTS['destination'],
      affectedRowCount: missingDestCount.count,
    })
  }

  // ── 5. Build report ──────────────────────────────────────────────────────────
  const report: IngestionReport = {
    totalRows: rawRows.length,
    validEvents: validEvents.length,
    invalidRows,
    duplicateCount,
    missingFields,
    timezone,
  }

  return { events: validEvents, report }
}
