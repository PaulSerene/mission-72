/**
 * Impossible-Travel Detection — Comprehensive Unit & Integration Test Suite
 *
 * Validates:
 * 1. Distant successful logins within an implausibly short interval trigger impossible_travel.
 * 2. Plausible transcontinental travel intervals do NOT trigger the rule.
 * 3. Missing coordinates produce no impossible-travel claim.
 * 4. Invalid latitude or longitude is rejected or treated as unavailable.
 * 5. Missing, invalid, equal, or out-of-order timestamps are handled safely without crashing.
 * 6. Failed logins alone do not trigger impossible travel.
 * 7. Duplicate records do not create duplicate travel alerts.
 * 8. Approved VPN/proxy context suppresses false physical travel claims with an audit trail.
 * 9. VPN context does NOT suppress independent brute-force or password-spraying detections.
 * 10. Incident correlation includes both supporting event IDs and preserves account separation.
 * 11. Risk scoring remains deterministic, bounded within [0, 100], and mathematically reconcilable.
 * 12. End-to-end detection pipeline integration with custom IP-location CSVs.
 */

import { describe, it, expect } from 'vitest'
import {
  detectImpossibleTravel,
  detectBruteForce,
  detectPasswordSpray,
  type RuleContext,
} from '@/engine/rules'
import {
  haversineDistanceKm,
  calculateTravelSpeedKmH,
  isValidCoordinate,
} from '@/engine/geo'
import { parseIpLocations, lookupLocationRecord } from '@/engine/assets'
import { runDetectionPipeline, createDefaultConfig } from '@/engine/pipeline'
import { correlateIncidents, decomposeIncidentRiskScore } from '@/engine/incidents'
import { generateAssetsCsv } from '@/data/generate'
import type { AuthEvent, UserBaseline } from '@/types'

// ─── Deterministic Synthetic Coordinates ─────────────────────────────────────
// London HQ: 51.5074° N, 0.1278° W
const LONDON_COORDS = { lat: 51.5074, lon: -0.1278, label: 'London HQ' }
// Tokyo Branch: 35.6762° N, 139.6503° E (distance ~9560 km from London)
const TOKYO_COORDS = { lat: 35.6762, lon: 139.6503, label: 'Tokyo Branch' }
// New York Datacenter: 40.7128° N, 74.0060° W (distance ~5570 km from London)
const NYC_COORDS = { lat: 40.7128, lon: -74.0060, label: 'New York Datacenter' }
// Reading Branch: 51.4543° N, 0.9781° W (distance ~60 km from London — within metro threshold)
const READING_COORDS = { lat: 51.4543, lon: -0.9781, label: 'Reading Office' }

const assetsCsv = generateAssetsCsv()

function makeAuthEvent(overrides: Partial<AuthEvent> = {}): AuthEvent {
  return {
    id: 'ev-travel-' + Math.random().toString(36).slice(2, 9),
    timestamp: '2026-10-09T10:00:00Z',
    username: 'traveler_alice',
    sourceIp: '198.51.100.10',
    destination: 'app-web-01.corp.local',
    eventType: 'authentication',
    outcome: 'success',
    logonType: 'interactive',
    location: LONDON_COORDS.label,
    latitude: LONDON_COORDS.lat,
    longitude: LONDON_COORDS.lon,
    rawRow: 1,
    isDuplicate: false,
    ...overrides,
  }
}

function makeContext(configOverrides = {}): RuleContext {
  const config = createDefaultConfig(configOverrides)
  return {
    baselines: new Map<string, UserBaseline>(),
    config,
    ipLocations: [],
    vpnCidrs: [
      {
        network: 0xc0000200, // 192.0.2.0
        mask: 0xffffff00,    // /24
        cidr: '192.0.2.0/24',
        id: 'VPN-CORP-EAST',
        description: 'Approved Corporate VPN Gateway',
      },
    ],
    accountRoles: {},
    authorizedHelpdeskAccounts: new Set(),
    suppressedAlerts: [],
  }
}

describe('Impossible-Travel Detection Suite', () => {
  // ───────────────────────────────────────────────────────────────────────────
  // 1. Math & Coordinate Verification
  // ───────────────────────────────────────────────────────────────────────────
  describe('Geographic Math & Coordinate Verification', () => {
    it('validates coordinate boundaries accurately', () => {
      expect(isValidCoordinate(0, 0)).toBe(true)
      expect(isValidCoordinate(51.5074, -0.1278)).toBe(true)
      expect(isValidCoordinate(90, 180)).toBe(true)
      expect(isValidCoordinate(-90, -180)).toBe(true)

      // Invalid boundaries
      expect(isValidCoordinate(90.1, 0)).toBe(false)
      expect(isValidCoordinate(-90.1, 0)).toBe(false)
      expect(isValidCoordinate(0, 180.1)).toBe(false)
      expect(isValidCoordinate(0, -180.1)).toBe(false)
      expect(isValidCoordinate(NaN, 0)).toBe(false)
      expect(isValidCoordinate(0, NaN)).toBe(false)
      expect(isValidCoordinate(null, 0)).toBe(false)
      expect(isValidCoordinate(undefined, 0)).toBe(false)
    })

    it('calculates great-circle distance accurately via Haversine formula', () => {
      // London to Tokyo is approximately 9560 km (±50 km spherical tolerance)
      const distLondonTokyo = haversineDistanceKm(
        LONDON_COORDS.lat,
        LONDON_COORDS.lon,
        TOKYO_COORDS.lat,
        TOKYO_COORDS.lon,
      )
      expect(distLondonTokyo).toBeGreaterThan(9500)
      expect(distLondonTokyo).toBeLessThan(9650)

      // London to NYC is approximately 5570 km
      const distLondonNyc = haversineDistanceKm(
        LONDON_COORDS.lat,
        LONDON_COORDS.lon,
        NYC_COORDS.lat,
        NYC_COORDS.lon,
      )
      expect(distLondonNyc).toBeGreaterThan(5500)
      expect(distLondonNyc).toBeLessThan(5650)

      // Same point distance is 0 km
      const distSame = haversineDistanceKm(
        LONDON_COORDS.lat,
        LONDON_COORDS.lon,
        LONDON_COORDS.lat,
        LONDON_COORDS.lon,
      )
      expect(distSame).toBe(0)
    })

    it('calculates travel velocity and handles zero/negative elapsed times safely', () => {
      // 9560 km in 15 minutes (900,000 ms = 0.25 hours) -> 38,240 km/h
      const speed15m = calculateTravelSpeedKmH(9560, 15 * 60 * 1000)
      expect(speed15m).toBeCloseTo(38240, 0)

      // 9560 km in 16 hours (57,600,000 ms) -> 597.5 km/h
      const speed16h = calculateTravelSpeedKmH(9560, 16 * 3600 * 1000)
      expect(speed16h).toBeCloseTo(597.5, 0)

      // Zero or negative elapsed time returns 0 km/h
      expect(calculateTravelSpeedKmH(1000, 0)).toBe(0)
      expect(calculateTravelSpeedKmH(1000, -5000)).toBe(0)
      expect(calculateTravelSpeedKmH(0, 10000)).toBe(0)
    })
  })

  // ───────────────────────────────────────────────────────────────────────────
  // 2. Detection Rule Behavior
  // ───────────────────────────────────────────────────────────────────────────
  describe('Impossible-Travel Detection Rule', () => {
    it('1. triggers impossible_travel when distant successful logins occur in an implausibly short interval', () => {
      const ctx = makeContext()
      const ev1 = makeAuthEvent({
        id: 'ev-lon-01',
        timestamp: '2026-10-09T10:00:00Z',
        location: LONDON_COORDS.label,
        latitude: LONDON_COORDS.lat,
        longitude: LONDON_COORDS.lon,
        sourceIp: '198.51.100.10',
      })
      const ev2 = makeAuthEvent({
        id: 'ev-tok-02',
        timestamp: '2026-10-09T10:15:00Z', // 15 minutes later
        location: TOKYO_COORDS.label,
        latitude: TOKYO_COORDS.lat,
        longitude: TOKYO_COORDS.lon,
        sourceIp: '203.0.113.50',
      })

      const matches = detectImpossibleTravel([ev1, ev2], ctx)

      expect(matches).toHaveLength(1)
      const m = matches[0]
      expect(m.ruleId).toBe('impossible_travel')
      expect(m.ruleName).toBe('Impossible Travel Between Geographically Incompatible Logins')
      expect(m.severity).toBe('critical') // > 2000 km/h is critical
      expect(m.username).toBe('traveler_alice')
      expect(m.timestamp).toBe('2026-10-09T10:15:00Z')

      // References both source events
      expect(m.evidence.eventIds).toEqual(['ev-lon-01', 'ev-tok-02'])
      expect(m.evidence.data?.distanceKm).toBeGreaterThan(9500)
      expect(m.evidence.data?.speedKmH).toBeGreaterThan(30000)
      expect(m.evidence.data?.elapsedMinutes).toBe(15)
      expect(m.evidence.description).toContain('Impossible travel')
      expect(m.evidence.description).toContain('Tokyo Branch')
    })

    it('2. does NOT trigger when the same distant locations are separated by a plausible travel interval', () => {
      const ctx = makeContext()
      const ev1 = makeAuthEvent({
        id: 'ev-lon-01',
        timestamp: '2026-10-09T08:00:00Z',
        location: LONDON_COORDS.label,
        latitude: LONDON_COORDS.lat,
        longitude: LONDON_COORDS.lon,
      })
      const ev2 = makeAuthEvent({
        id: 'ev-tok-02',
        timestamp: '2026-10-10T02:00:00Z', // 18 hours later (~531 km/h <= 1000 km/h)
        location: TOKYO_COORDS.label,
        latitude: TOKYO_COORDS.lat,
        longitude: TOKYO_COORDS.lon,
      })

      const matches = detectImpossibleTravel([ev1, ev2], ctx)
      expect(matches).toHaveLength(0)
    })

    it('does NOT trigger when distance is within local metropolitan threshold (< 100 km)', () => {
      const ctx = makeContext()
      // London to Reading is ~60 km
      const ev1 = makeAuthEvent({
        timestamp: '2026-10-09T10:00:00Z',
        location: LONDON_COORDS.label,
        latitude: LONDON_COORDS.lat,
        longitude: LONDON_COORDS.lon,
      })
      const ev2 = makeAuthEvent({
        timestamp: '2026-10-09T10:02:00Z', // 2 minutes later
        location: READING_COORDS.label,
        latitude: READING_COORDS.lat,
        longitude: READING_COORDS.lon,
      })

      const matches = detectImpossibleTravel([ev1, ev2], ctx)
      // Filtered out by minDistanceKm threshold (100 km) to prevent local ISP jitter false alerts
      expect(matches).toHaveLength(0)
    })

    it('3. does NOT claim impossible travel when coordinates are missing or incomplete', () => {
      const ctx = makeContext()
      // First event has coordinates, second has none
      const ev1 = makeAuthEvent({
        timestamp: '2026-10-09T10:00:00Z',
        latitude: LONDON_COORDS.lat,
        longitude: LONDON_COORDS.lon,
      })
      const ev2 = makeAuthEvent({
        timestamp: '2026-10-09T10:15:00Z',
        latitude: null,
        longitude: null,
      })

      expect(detectImpossibleTravel([ev1, ev2], ctx)).toHaveLength(0)
    })

    it('4. rejects or treats invalid latitude/longitude as unavailable', () => {
      // Test parseIpLocations handling of invalid coordinates
      const ipCsv = [
        'cidr,location,latitude,longitude',
        '198.51.100.0/24,Valid London,51.5074,-0.1278',
        '203.0.113.0/24,Invalid Lat,105.0,139.6503',      // invalid lat > 90
        '172.16.0.0/16,Invalid Lon,35.6762,-195.0',       // invalid lon < -180
        '10.0.0.0/16,Malformed Coords,abc,def',           // non-numeric
      ].join('\n')

      const { locations, invalidRows } = parseIpLocations(ipCsv)
      expect(invalidRows).toHaveLength(0) // CIDR and location remain valid
      expect(locations).toHaveLength(4)

      // Valid entry retains coordinates
      const validLoc = lookupLocationRecord('198.51.100.15', locations)
      expect(validLoc?.latitude).toBe(51.5074)
      expect(validLoc?.longitude).toBe(-0.1278)

      // Malformed entries have coordinates treated as unavailable (undefined)
      const invalidLatLoc = lookupLocationRecord('203.0.113.15', locations)
      expect(invalidLatLoc?.latitude).toBeUndefined()
      expect(invalidLatLoc?.longitude).toBeUndefined()

      const invalidLonLoc = lookupLocationRecord('172.16.5.5', locations)
      expect(invalidLonLoc?.latitude).toBeUndefined()

      const malformedLoc = lookupLocationRecord('10.0.1.1', locations)
      expect(malformedLoc?.latitude).toBeUndefined()

      // When used in rule evaluation, unavailable coordinates produce no impossible travel
      const ctx = makeContext()
      const ev1 = makeAuthEvent({
        timestamp: '2026-10-09T10:00:00Z',
        latitude: 51.5074,
        longitude: -0.1278,
      })
      const ev2 = makeAuthEvent({
        timestamp: '2026-10-09T10:15:00Z',
        latitude: invalidLatLoc?.latitude, // undefined
        longitude: invalidLatLoc?.longitude,
      })
      expect(detectImpossibleTravel([ev1, ev2], ctx)).toHaveLength(0)
    })

    it('5. handles missing, invalid, equal, or out-of-order timestamps safely without crashing', () => {
      const ctx = makeContext()

      // Equal timestamps (0 ms elapsed)
      const evEqual1 = makeAuthEvent({
        timestamp: '2026-10-09T10:00:00Z',
        latitude: LONDON_COORDS.lat,
        longitude: LONDON_COORDS.lon,
      })
      const evEqual2 = makeAuthEvent({
        timestamp: '2026-10-09T10:00:00Z',
        latitude: TOKYO_COORDS.lat,
        longitude: TOKYO_COORDS.lon,
      })
      expect(detectImpossibleTravel([evEqual1, evEqual2], ctx)).toHaveLength(0)

      // Unparseable timestamp
      const evInvalidTs = makeAuthEvent({
        timestamp: 'INVALID_TIMESTAMP',
        latitude: TOKYO_COORDS.lat,
        longitude: TOKYO_COORDS.lon,
      })
      expect(detectImpossibleTravel([evEqual1, evInvalidTs], ctx)).toHaveLength(0)

      // Reversed / out-of-order events are sorted ascending by the rule before comparison
      const evEarlier = makeAuthEvent({
        id: 'ev-early',
        timestamp: '2026-10-09T10:00:00Z',
        latitude: LONDON_COORDS.lat,
        longitude: LONDON_COORDS.lon,
      })
      const evLater = makeAuthEvent({
        id: 'ev-late',
        timestamp: '2026-10-09T10:15:00Z',
        latitude: TOKYO_COORDS.lat,
        longitude: TOKYO_COORDS.lon,
      })
      // Pass in reverse order: [evLater, evEarlier]
      const sortedMatches = detectImpossibleTravel([evLater, evEarlier], ctx)
      expect(sortedMatches).toHaveLength(1)
      expect(sortedMatches[0].evidence.eventIds).toEqual(['ev-early', 'ev-late'])
    })

    it('6. failed logins alone do NOT trigger impossible travel', () => {
      const ctx = makeContext()
      // Consecutive failed logins across transcontinental distances
      const ev1 = makeAuthEvent({
        timestamp: '2026-10-09T10:00:00Z',
        outcome: 'failure',
        latitude: LONDON_COORDS.lat,
        longitude: LONDON_COORDS.lon,
      })
      const ev2 = makeAuthEvent({
        timestamp: '2026-10-09T10:10:00Z',
        outcome: 'failure',
        latitude: TOKYO_COORDS.lat,
        longitude: TOKYO_COORDS.lon,
      })

      expect(detectImpossibleTravel([ev1, ev2], ctx)).toHaveLength(0)
    })

    it('7. duplicate records do not create duplicate travel alerts', () => {
      const ctx = makeContext()
      const ev1 = makeAuthEvent({
        id: 'ev-1',
        timestamp: '2026-10-09T10:00:00Z',
        latitude: LONDON_COORDS.lat,
        longitude: LONDON_COORDS.lon,
      })
      const ev2 = makeAuthEvent({
        id: 'ev-2',
        timestamp: '2026-10-09T10:15:00Z',
        latitude: TOKYO_COORDS.lat,
        longitude: TOKYO_COORDS.lon,
      })
      // Duplicate of ev2
      const ev2Dup = makeAuthEvent({
        id: 'ev-2',
        timestamp: '2026-10-09T10:15:00Z',
        latitude: TOKYO_COORDS.lat,
        longitude: TOKYO_COORDS.lon,
        isDuplicate: true,
      })

      const matches = detectImpossibleTravel([ev1, ev2, ev2Dup], ctx)
      expect(matches).toHaveLength(1)
    })

    it('8. approved VPN/proxy context suppresses false physical travel claims and records audit trail', () => {
      const ctx = makeContext()
      // User logs in from London branch office
      const ev1 = makeAuthEvent({
        id: 'ev-lon-01',
        timestamp: '2026-10-09T10:00:00Z',
        sourceIp: '198.51.100.10',
        location: LONDON_COORDS.label,
        latitude: LONDON_COORDS.lat,
        longitude: LONDON_COORDS.lon,
      })
      // 5 minutes later, user establishes VPN connection egressing from NYC Datacenter (192.0.2.88)
      const ev2 = makeAuthEvent({
        id: 'ev-vpn-02',
        timestamp: '2026-10-09T10:05:00Z',
        sourceIp: '192.0.2.88', // inside approved VPN 192.0.2.0/24
        location: 'Approved Corporate VPN',
        latitude: NYC_COORDS.lat,
        longitude: NYC_COORDS.lon,
      })

      const matches = detectImpossibleTravel([ev1, ev2], ctx)

      // Must be suppressed — no unsuppressed alert
      expect(matches).toHaveLength(0)

      // Must record suppression audit record
      expect(ctx.suppressedAlerts).toHaveLength(1)
      const audit = ctx.suppressedAlerts![0]
      expect(audit.policyType).toBe('approved_vpn')
      expect(audit.ruleId).toBe('impossible_travel')
      expect(audit.reason).toContain('approved corporate VPN')
      expect(audit.evidence.eventIds).toEqual(['ev-lon-01', 'ev-vpn-02'])
    })

    it('9. VPN context does NOT suppress independent brute-force or password-spraying detections', () => {
      const ctx = makeContext()
      // 5 brute force failures from approved VPN IP (192.0.2.88)
      const bfEvents: AuthEvent[] = Array.from({ length: 5 }, (_, i) =>
        makeAuthEvent({
          id: `ev-bf-${i}`,
          timestamp: `2026-10-09T14:00:${String(i * 10).padStart(2, '0')}Z`,
          username: 'victim_account',
          sourceIp: '192.0.2.88',
          outcome: 'failure',
        })
      )

      const bfMatches = detectBruteForce(bfEvents, ctx)
      expect(bfMatches).toHaveLength(1)
      expect(bfMatches[0].ruleId).toBe('brute_force')

      // Password spray across 5 accounts from approved VPN IP
      const sprayEvents: AuthEvent[] = ['u1', 'u2', 'u3', 'u4', 'u5'].map((u, i) =>
        makeAuthEvent({
          id: `ev-sp-${i}`,
          timestamp: `2026-10-09T15:00:${String(i * 10).padStart(2, '0')}Z`,
          username: u,
          sourceIp: '192.0.2.88',
          outcome: 'failure',
        })
      )

      const sprayMatches = detectPasswordSpray(sprayEvents, ctx)
      expect(sprayMatches).toHaveLength(5)
    })

    it('10. incident correlation includes both supporting events and preserves account separation', () => {
      const ctx = makeContext()
      // User Alice has impossible travel between London and Tokyo
      const evA1 = makeAuthEvent({
        id: 'ev-alice-1',
        username: 'alice',
        timestamp: '2026-10-09T10:00:00Z',
        latitude: LONDON_COORDS.lat,
        longitude: LONDON_COORDS.lon,
      })
      const evA2 = makeAuthEvent({
        id: 'ev-alice-2',
        username: 'alice',
        timestamp: '2026-10-09T10:15:00Z',
        latitude: TOKYO_COORDS.lat,
        longitude: TOKYO_COORDS.lon,
      })

      // User Bob has concurrent login in NYC
      const evB1 = makeAuthEvent({
        id: 'ev-bob-1',
        username: 'bob',
        timestamp: '2026-10-09T10:10:00Z',
        latitude: NYC_COORDS.lat,
        longitude: NYC_COORDS.lon,
      })

      const matches = [
        ...detectImpossibleTravel([evA1, evA2], ctx),
        ...detectImpossibleTravel([evB1], ctx),
      ]

      expect(matches).toHaveLength(1)
      expect(matches[0].username).toBe('alice')
      expect(matches[0].evidence.eventIds).toEqual(['ev-alice-1', 'ev-alice-2'])

      // Correlate into incidents
      const incidents = correlateIncidents(matches)
      expect(incidents).toHaveLength(1)
      expect(incidents[0].username).toBe('alice')
      expect(incidents[0].ruleMatches[0].evidence.eventIds).toContain('ev-alice-1')
      expect(incidents[0].ruleMatches[0].evidence.eventIds).toContain('ev-alice-2')
    })

    it('11. risk scoring remains deterministic, bounded in [0, 100], and reconcilable with impossible travel', () => {
      const ctx = makeContext()
      const ev1 = makeAuthEvent({
        id: 'ev-1',
        timestamp: '2026-10-09T10:00:00Z',
        latitude: LONDON_COORDS.lat,
        longitude: LONDON_COORDS.lon,
      })
      const ev2 = makeAuthEvent({
        id: 'ev-2',
        timestamp: '2026-10-09T10:15:00Z',
        latitude: TOKYO_COORDS.lat,
        longitude: TOKYO_COORDS.lon,
      })

      const travelMatches = detectImpossibleTravel([ev1, ev2], ctx)
      expect(travelMatches).toHaveLength(1)

      const decomposition = decomposeIncidentRiskScore(travelMatches)
      // Base score for impossible_travel is 50
      expect(decomposition.finalScore).toBe(50)
      expect(decomposition.contributions[0].ruleId).toBe('impossible_travel')
      expect(decomposition.contributions[0].finalContribution).toBe(50)
      expect(decomposition.rawCalculatedScore).toBe(50)
      expect(decomposition.cappedAt100).toBe(false)

      // When combined with multiple other high-severity detections, score caps at 100
      const multiMatches = [
        ...travelMatches,
        { ...travelMatches[0], ruleId: 'burst_success', ruleName: 'Burst Success' },
        { ...travelMatches[0], ruleId: 'brute_force', ruleName: 'Brute Force' },
      ]
      const multiDecomp = decomposeIncidentRiskScore(multiMatches)
      expect(multiDecomp.finalScore).toBe(100)
      expect(multiDecomp.cappedAt100).toBe(true)
      expect(multiDecomp.synergyBonus).toBe(15) // >= 3 distinct rules
    })
  })

  // ───────────────────────────────────────────────────────────────────────────
  // 3. End-to-End Pipeline Integration with IP-Location CSV
  // ───────────────────────────────────────────────────────────────────────────
  describe('End-to-End Pipeline Integration', () => {
    it('12. detects impossible travel end-to-end when IP-location CSV provides valid coordinates', () => {
      const ipLocationCsvWithCoords = [
        'cidr,location,latitude,longitude',
        '10.0.0.0/16,London Corporate LAN,51.5074,-0.1278',
        '198.51.100.0/24,Tokyo Branch Office,35.6762,139.6503',
        '192.0.2.0/24,Approved Corporate VPN,40.7128,-74.0060',
      ].join('\n')

      const authCsv = [
        'timestamp,username,src_ip,dest,result,logon_type',
        // Training period (clean business hours in London)
        '2026-10-02T09:00:00Z,exec_user,10.0.1.10,app-web-01.corp.local,success,interactive',
        '2026-10-03T09:00:00Z,exec_user,10.0.1.10,app-web-01.corp.local,success,interactive',
        '2026-10-04T09:00:00Z,exec_user,10.0.1.10,app-web-01.corp.local,success,interactive',
        '2026-10-05T09:00:00Z,exec_user,10.0.1.10,app-web-01.corp.local,success,interactive',
        '2026-10-06T09:00:00Z,exec_user,10.0.1.10,app-web-01.corp.local,success,interactive',
        // Analysis period: London login followed by Tokyo login 10 minutes later!
        '2026-10-09T10:00:00Z,exec_user,10.0.1.10,app-web-01.corp.local,success,interactive',
        '2026-10-09T10:10:00Z,exec_user,198.51.100.44,app-web-01.corp.local,success,interactive',
      ].join('\n')

      const result = runDetectionPipeline({
        authData: authCsv,
        assetData: assetsCsv,
        ipLocationData: ipLocationCsvWithCoords,
      })

      // Verify that events were enriched with coordinates
      const analysisEvents = result.events.filter(e => e.timestamp >= '2026-10-08T00:00:00Z')
      expect(analysisEvents[0].latitude).toBe(51.5074)
      expect(analysisEvents[0].longitude).toBe(-0.1278)
      expect(analysisEvents[1].latitude).toBe(35.6762)
      expect(analysisEvents[1].longitude).toBe(139.6503)

      // Verify impossible travel rule fired
      const travelMatches = result.ruleMatches.filter(r => r.ruleId === 'impossible_travel')
      expect(travelMatches).toHaveLength(1)
      expect(travelMatches[0].evidence.data?.distanceKm).toBeGreaterThan(9500)
      expect(travelMatches[0].evidence.data?.speedKmH).toBeGreaterThan(50000)

      // Verify correlated incident generated
      const incident = result.incidents.find(inc => inc.username === 'exec_user')
      expect(incident).toBeDefined()
      expect(incident?.severity).toBe('critical')
      expect(incident?.riskScore).toBe(85)
      expect(incident?.ruleMatches.some(r => r.ruleId === 'impossible_travel')).toBe(true)
    })
  })
})
