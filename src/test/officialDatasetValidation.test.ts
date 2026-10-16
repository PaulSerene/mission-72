import { describe, it, expect, beforeAll } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import { runDetectionPipeline } from '@/engine/pipeline'
import { parseAuthCsv } from '@/engine/ingest'
import type { AnalysisConfig } from '@/types'

const DATA_DIR = path.resolve(__dirname, '../../PS2_Suspicious_Login_Detector')

function readData(subpath: string): string {
  const full = path.join(DATA_DIR, subpath)
  return fs.readFileSync(full, 'utf-8')
}

// ─── Environment Helpers ─────────────────────────────────────────────────────

function createVariantAConfig(overrides: Partial<AnalysisConfig> = {}): AnalysisConfig {
  return {
    timezone: 'Asia/Kolkata',
    trainingPeriod: {
      start: '2026-11-02T00:00:00+05:30',
      end: '2026-11-07T00:00:00+05:30',
    },
    analysisPeriod: {
      start: '2026-11-07T00:00:00+05:30',
      end: '2026-11-09T00:00:00+05:30',
    },
    approvedVpnCidrs: ['172.16.50.0/24'],
    maintenanceWindows: [
      {
        id: 'MW-A-01',
        start: '2026-11-07T13:00:00+05:30',
        end: '2026-11-07T17:00:00+05:30',
        approvedAccounts: ['helpdesk.svc'],
        scope: 'All workstations - quarterly patch verification',
        timezone: 'Asia/Kolkata',
      },
    ],
    accountRoles: {
      'helpdesk.svc': 'helpdesk',
      'adm.meera': 'admin',
      'svc.backup': 'service',
    },
    authorizedHelpdeskAccounts: ['helpdesk.svc'],
    rules: {
      bruteForce: {
        failureCount: 5,
        windowSeconds: 600, // 10 minutes
      },
      burstSuccess: {
        failureCount: 4, // 3 typos is benign lookalike (< 4)
        windowSeconds: 900, // 15 minutes
      },
      passwordSpray: {
        userCount: 10,
        windowSeconds: 1800, // 30 minutes
      },
      unusualHours: {
        offHoursStart: 22,
        offHoursEnd: 6,
      },
      newHosts: {
        newHostCount: 5,
        windowHours: 1, // 60 minutes
      },
      impossibleTravel: {
        maxSpeedKmH: 900,
        minDistanceKm: 100,
      },
    },
    ...overrides,
  }
}

function createVariantBConfig(overrides: Partial<AnalysisConfig> = {}): AnalysisConfig {
  return {
    timezone: 'Asia/Kolkata',
    trainingPeriod: {
      // Days 1-5 in Asia/Kolkata (2026-11-09T00:00:00+05:30 to 2026-11-14T00:00:00+05:30)
      start: '2026-11-08T18:30:00Z',
      end: '2026-11-13T18:30:00Z',
    },
    analysisPeriod: {
      // Days 6-7 in Asia/Kolkata (2026-11-14T00:00:00+05:30 to 2026-11-16T00:00:00+05:30)
      start: '2026-11-13T18:30:00Z',
      end: '2026-11-15T18:30:00Z',
    },
    approvedVpnCidrs: ['172.16.60.0/24'],
    maintenanceWindows: [
      {
        id: 'MW-B-01',
        start: '2026-11-14T13:00:00+05:30',
        end: '2026-11-14T17:00:00+05:30',
        approvedAccounts: ['helpdesk_svc'],
        scope: 'All workstations - quarterly patch verification',
        timezone: 'Asia/Kolkata',
      },
    ],
    accountRoles: {
      'helpdesk_svc': 'helpdesk',
      'adm_chetan': 'admin',
      'svc_backup': 'service',
    },
    authorizedHelpdeskAccounts: ['helpdesk_svc'],
    rules: {
      bruteForce: {
        failureCount: 5,
        windowSeconds: 600,
      },
      burstSuccess: {
        failureCount: 4,
        windowSeconds: 900,
      },
      passwordSpray: {
        userCount: 10,
        windowSeconds: 1800,
      },
      unusualHours: {
        offHoursStart: 22,
        offHoursEnd: 6,
      },
      newHosts: {
        newHostCount: 5,
        windowHours: 1,
      },
      impossibleTravel: {
        maxSpeedKmH: 900,
        minDistanceKm: 100,
      },
    },
    ...overrides,
  }
}

describe('Official Organizer Dataset Validation (PS2_Suspicious_Login_Detector)', () => {
  let ipLocationsA: string
  let ipLocationsB: string
  let assetListA: string
  let assetListB: string
  let trainingLogsA: string
  let trainingLogsB: string

  beforeAll(() => {
    ipLocationsA = readData('reference/ip_locations_A.csv')
    ipLocationsB = readData('reference/ip_locations_B.csv')
    assetListA = readData('reference/asset_list_A.csv')
    assetListB = readData('reference/asset_list_B.csv')
    trainingLogsA = readData('data/training_auth_logs_days1-5_A.csv')
    trainingLogsB = readData('data/training_auth_logs_days1-5_B.csv')
  })

  // ─── TC01: Normal Logins ───────────────────────────────────────────────────
  describe('TC01: Normal Logins', () => {
    it('TC01_A: produces zero alerts when evaluated against trained baseline', () => {
      const config = createVariantAConfig()
      const trainingParsed = parseAuthCsv(trainingLogsA, config)
      const testParsed = parseAuthCsv(readData('data/mission04_tests/TC01_normal_logins_A.csv'), config)

      const result = runDetectionPipeline({
        authData: [...trainingParsed.events, ...testParsed.events],
        assetData: assetListA,
        ipLocationData: ipLocationsA,
        config,
      })

      const attacks = result.ruleMatches.filter(
        m => ['brute_force', 'burst_success', 'password_spray', 'impossible_travel', 'new_hosts'].includes(m.ruleId)
      )
      expect(attacks).toHaveLength(0)
    })

    it('TC01_B: produces zero alerts when evaluated against trained baseline', () => {
      const config = createVariantBConfig()
      const trainingParsed = parseAuthCsv(trainingLogsB, config)
      const testParsed = parseAuthCsv(readData('data/mission04_tests/TC01_normal_logins_B.csv'), config)

      const result = runDetectionPipeline({
        authData: [...trainingParsed.events, ...testParsed.events],
        assetData: assetListB,
        ipLocationData: ipLocationsB,
        config,
      })

      const attacks = result.ruleMatches.filter(
        m => ['brute_force', 'burst_success', 'password_spray', 'impossible_travel', 'new_hosts'].includes(m.ruleId)
      )
      expect(attacks).toHaveLength(0)
    })
  })

  // ─── TC02: Repeated Failures ───────────────────────────────────────────────
  describe('TC02: Repeated Failures', () => {
    it('TC02_A: detects repeated failures (brute_force) for pooja.reddy', () => {
      const config = createVariantAConfig()
      const testCsv = readData('data/mission04_tests/TC02_repeated_failures_A.csv')
      const result = runDetectionPipeline({
        authData: testCsv,
        assetData: assetListA,
        ipLocationData: ipLocationsA,
        config,
      })

      const bfMatches = result.ruleMatches.filter(m => m.ruleId === 'brute_force')
      expect(bfMatches.length).toBeGreaterThanOrEqual(1)
      expect(bfMatches[0].username).toBe('pooja.reddy')
      expect(bfMatches[0].evidence.eventIds.length).toBeGreaterThanOrEqual(5)
    })

    it('TC02_B: detects repeated failures (brute_force) for leela_pillai', () => {
      const config = createVariantBConfig()
      const testCsv = readData('data/mission04_tests/TC02_repeated_failures_B.csv')
      const result = runDetectionPipeline({
        authData: testCsv,
        assetData: assetListB,
        ipLocationData: ipLocationsB,
        config,
      })

      const bfMatches = result.ruleMatches.filter(m => m.ruleId === 'brute_force')
      expect(bfMatches.length).toBeGreaterThanOrEqual(1)
      expect(bfMatches[0].username).toBe('leela_pillai')
      expect(bfMatches[0].evidence.eventIds.length).toBeGreaterThanOrEqual(5)
    })
  })

  // ─── TC03: Failure Followed by Success ─────────────────────────────────────
  describe('TC03: Failure Followed by Success', () => {
    it('TC03_A: detects burst_success for rahul.gupta', () => {
      const config = createVariantAConfig()
      const testCsv = readData('data/mission04_tests/TC03_failure_then_success_A.csv')
      const result = runDetectionPipeline({
        authData: testCsv,
        assetData: assetListA,
        ipLocationData: ipLocationsA,
        config,
      })

      const bsMatches = result.ruleMatches.filter(m => m.ruleId === 'burst_success')
      expect(bsMatches.length).toBeGreaterThanOrEqual(1)
      expect(bsMatches[0].username).toBe('rahul.gupta')
      expect(bsMatches[0].evidence.eventIds).toContain('A-E001799')
    })

    it('TC03_B: detects burst_success for mohan_das', () => {
      const config = createVariantBConfig()
      const testCsv = readData('data/mission04_tests/TC03_failure_then_success_B.csv')
      const result = runDetectionPipeline({
        authData: testCsv,
        assetData: assetListB,
        ipLocationData: ipLocationsB,
        config,
      })

      const bsMatches = result.ruleMatches.filter(m => m.ruleId === 'burst_success')
      expect(bsMatches.length).toBeGreaterThanOrEqual(1)
      expect(bsMatches[0].username).toBe('mohan_das')
      expect(bsMatches[0].evidence.eventIds).toContain('B-E001783')
    })
  })

  // ─── TC04: Password Spraying ───────────────────────────────────────────────
  describe('TC04: Password Spraying', () => {
    it('TC04_A: detects password_spray from single IP against multiple accounts', () => {
      const config = createVariantAConfig()
      const testCsv = readData('data/mission04_tests/TC04_password_spraying_A.csv')
      const result = runDetectionPipeline({
        authData: testCsv,
        assetData: assetListA,
        ipLocationData: ipLocationsA,
        config,
      })

      const sprayMatches = result.ruleMatches.filter(m => m.ruleId === 'password_spray')
      expect(sprayMatches.length).toBeGreaterThanOrEqual(10)
      const data = sprayMatches[0].evidence.data as Record<string, unknown>
      expect(data.sourceIp).toBe('198.51.100.200')
    })

    it('TC04_B: detects password_spray from single IP in variant B', () => {
      const config = createVariantBConfig()
      const testCsv = readData('data/mission04_tests/TC04_password_spraying_B.csv')
      const result = runDetectionPipeline({
        authData: testCsv,
        assetData: assetListB,
        ipLocationData: ipLocationsB,
        config,
      })

      const sprayMatches = result.ruleMatches.filter(m => m.ruleId === 'password_spray')
      expect(sprayMatches.length).toBeGreaterThanOrEqual(10)
      const data = sprayMatches[0].evidence.data as Record<string, unknown>
      expect(data.sourceIp).toBe('198.51.100.200')
    })
  })

  // ─── TC05: Impossible Travel vs Approved VPN ───────────────────────────────
  describe('TC05: Impossible Travel vs Approved VPN', () => {
    it('TC05_A: detects impossible travel for sneha.nair and raises no false claim for aditya.iyer', () => {
      const config = createVariantAConfig()
      const testCsv = readData('data/mission04_tests/TC05_impossible_travel_vs_vpn_A.csv')
      const result = runDetectionPipeline({
        authData: testCsv,
        assetData: assetListA,
        ipLocationData: ipLocationsA,
        config,
      })

      // sneha.nair: Hyderabad to Singapore (~3300 km in 20 min, speed > 9900 km/h) -> impossible travel
      const travelMatches = result.ruleMatches.filter(m => m.ruleId === 'impossible_travel')
      expect(travelMatches).toHaveLength(1)
      expect(travelMatches[0].username).toBe('sneha.nair')
      expect(travelMatches[0].evidence.eventIds).toEqual(['A-E001815', 'A-E001816'])
      const travelData = travelMatches[0].evidence.data as Record<string, unknown>
      expect(Number(travelData.speedKmH)).toBeGreaterThan(900)

      // aditya.iyer: Campus to VPN Gateway (172.16.50.44) -> No impossible travel alert
      const adityaAlert = travelMatches.find(m => m.username === 'aditya.iyer')
      expect(adityaAlert).toBeUndefined()
    })

    it('TC05_B: detects impossible travel for neha_das and raises no false claim for om_khan', () => {
      const config = createVariantBConfig()
      const testCsv = readData('data/mission04_tests/TC05_impossible_travel_vs_vpn_B.csv')
      const result = runDetectionPipeline({
        authData: testCsv,
        assetData: assetListB,
        ipLocationData: ipLocationsB,
        config,
      })

      const travelMatches = result.ruleMatches.filter(m => m.ruleId === 'impossible_travel')
      expect(travelMatches).toHaveLength(1)
      expect(travelMatches[0].username).toBe('neha_das')
      expect(travelMatches[0].evidence.eventIds).toEqual(['B-E001799', 'B-E001800'])

      const omAlert = travelMatches.find(m => m.username === 'om_khan')
      expect(omAlert).toBeUndefined()
    })
  })

  // ─── TC06: Host Fan-Out vs Maintenance ─────────────────────────────────────
  describe('TC06: Host Fan-Out vs Maintenance', () => {
    it('TC06_A: suppresses helpdesk.svc within maintenance window and alerts kavya.reddy outside window', () => {
      const config = createVariantAConfig()
      const trainingParsed = parseAuthCsv(trainingLogsA, config)
      const testParsed = parseAuthCsv(readData('data/mission04_tests/TC06_fan_out_vs_maintenance_A.csv'), config)

      const result = runDetectionPipeline({
        authData: [...trainingParsed.events, ...testParsed.events],
        assetData: assetListA,
        ipLocationData: ipLocationsA,
        config,
      })

      // kavya.reddy accessed WS-021..WS-028 (8 hosts outside maintenance) -> alert
      const kavyaAlert = result.ruleMatches.find(
        m => m.username === 'kavya.reddy' && m.ruleId === 'new_hosts'
      )
      expect(kavyaAlert).toBeDefined()
      expect(kavyaAlert!.evidence.eventIds.length).toBeGreaterThanOrEqual(5)

      // helpdesk.svc within maintenance window MW-A-01 -> NO new_hosts alert
      const helpdeskAlert = result.ruleMatches.find(
        m => m.username === 'helpdesk.svc' && m.ruleId === 'new_hosts'
      )
      expect(helpdeskAlert).toBeUndefined()

      // Suppressed helpdesk audit log present
      const helpdeskAudit = result.suppressedAlerts.filter(
        s => s.username === 'helpdesk.svc' && s.ruleId === 'new_hosts'
      )
      expect(helpdeskAudit.length).toBeGreaterThan(0)
    })

    it('TC06_B: suppresses helpdesk_svc within maintenance and alerts priya_das outside window', () => {
      const config = createVariantBConfig()
      const trainingParsed = parseAuthCsv(trainingLogsB, config)
      const testParsed = parseAuthCsv(readData('data/mission04_tests/TC06_fan_out_vs_maintenance_B.csv'), config)

      const result = runDetectionPipeline({
        authData: [...trainingParsed.events, ...testParsed.events],
        assetData: assetListB,
        ipLocationData: ipLocationsB,
        config,
      })

      const priyaAlert = result.ruleMatches.find(
        m => m.username === 'priya_das' && m.ruleId === 'new_hosts'
      )
      expect(priyaAlert).toBeDefined()

      const helpdeskAlert = result.ruleMatches.find(
        m => m.username === 'helpdesk_svc' && m.ruleId === 'new_hosts'
      )
      expect(helpdeskAlert).toBeUndefined()

      const helpdeskAudit = result.suppressedAlerts.filter(
        s => s.username === 'helpdesk_svc' && s.ruleId === 'new_hosts'
      )
      expect(helpdeskAudit.length).toBeGreaterThan(0)
    })
  })

  // ─── TC07: Duplicate Rows ──────────────────────────────────────────────────
  describe('TC07: Duplicate Rows', () => {
    it('TC07_A: deduplicates 8 duplicate rows and avoids double-counting', () => {
      const config = createVariantAConfig()
      const testCsv = readData('data/mission04_tests/TC07_duplicated_rows_A.csv')
      const ingest = parseAuthCsv(testCsv, config)

      expect(ingest.report.duplicateCount).toBe(8)
      expect(ingest.events.length).toBe(33)
      const uniqueEvents = ingest.events.filter(e => !e.isDuplicate)
      expect(uniqueEvents.length).toBe(25)

      const result = runDetectionPipeline({
        authData: ingest.events,
        assetData: assetListA,
        ipLocationData: ipLocationsA,
        config,
      })
      // Nikhil has only 2 unique failures then success, below threshold 4
      const nikhilAttacks = result.ruleMatches.filter(
        m => m.username === 'nikhil.verma' && ['brute_force', 'burst_success'].includes(m.ruleId)
      )
      expect(nikhilAttacks).toHaveLength(0)
    })

    it('TC07_B: deduplicates 8 duplicate rows in variant B', () => {
      const config = createVariantBConfig()
      const testCsv = readData('data/mission04_tests/TC07_duplicated_rows_B.csv')
      const ingest = parseAuthCsv(testCsv, config)

      expect(ingest.report.duplicateCount).toBe(8)
      expect(ingest.events.length).toBe(37)
    })
  })

  // ─── TC08: Out-of-Order and Invalid Timestamps ─────────────────────────────
  describe('TC08: Out-of-Order and Invalid Timestamps', () => {
    it('TC08_A: rejects invalid timestamp line and sorts out-of-order events safely', () => {
      const config = createVariantAConfig()
      const testCsv = readData('data/mission04_tests/TC08_out_of_order_and_invalid_timestamps_A.csv')
      const ingest = parseAuthCsv(testCsv, config)

      expect(ingest.report.invalidRows.length).toBe(1)
      expect(ingest.report.invalidRows[0].reason).toContain('Unparseable timestamp')

      for (let i = 1; i < ingest.events.length; i++) {
        expect(ingest.events[i].timestamp >= ingest.events[i - 1].timestamp).toBe(true)
      }
    })

    it('TC08_B: rejects invalid timestamp line and sorts out-of-order events safely in B', () => {
      const config = createVariantBConfig()
      const testCsv = readData('data/mission04_tests/TC08_out_of_order_and_invalid_timestamps_B.csv')
      const ingest = parseAuthCsv(testCsv, config)

      expect(ingest.report.invalidRows.length).toBe(1)
      for (let i = 1; i < ingest.events.length; i++) {
        expect(ingest.events[i].timestamp >= ingest.events[i - 1].timestamp).toBe(true)
      }
    })
  })

  // ─── TC09: Missing IPs ─────────────────────────────────────────────────────
  describe('TC09: Missing IPs', () => {
    it('TC09_A: rejects rows with missing IPs as invalid rows without crashing', () => {
      const config = createVariantAConfig()
      const testCsv = readData('data/mission04_tests/TC09_missing_ips_A.csv')
      const ingest = parseAuthCsv(testCsv, config)

      expect(ingest.report.invalidRows.length).toBe(4)
      for (const inv of ingest.report.invalidRows) {
        expect(inv.reason).toContain('Missing or empty source IP')
      }

      const result = runDetectionPipeline({
        authData: ingest.events,
        assetData: assetListA,
        ipLocationData: ipLocationsA,
        config,
      })
      const farhanBf = result.ruleMatches.filter(m => m.username === 'farhan.nair' && m.ruleId === 'brute_force')
      expect(farhanBf).toHaveLength(0)
    })

    it('TC09_B: rejects rows with missing IPs in variant B', () => {
      const config = createVariantBConfig()
      const testCsv = readData('data/mission04_tests/TC09_missing_ips_B.csv')
      const ingest = parseAuthCsv(testCsv, config)

      expect(ingest.report.invalidRows.length).toBe(4)
    })
  })

  // ─── TC10: Malformed Columns ───────────────────────────────────────────────
  describe('TC10: Malformed Columns', () => {
    it('TC10_A: handles malformed header columns and invalid fields gracefully', () => {
      const config = createVariantAConfig()
      const testCsv = readData('data/mission04_tests/TC10_malformed_columns_A.csv')
      const ingest = parseAuthCsv(testCsv, config)

      expect(ingest.report.invalidRows.length).toBeGreaterThan(0)
    })

    it('TC10_B: handles malformed header columns in variant B gracefully', () => {
      const config = createVariantBConfig()
      const testCsv = readData('data/mission04_tests/TC10_malformed_columns_B.csv')
      const ingest = parseAuthCsv(testCsv, config)

      expect(ingest.report.invalidRows.length).toBeGreaterThan(0)
    })
  })

  // ─── TC11: Empty File ──────────────────────────────────────────────────────
  describe('TC11: Empty File', () => {
    it('TC11_A: safely parses header-only CSV and produces 0 events and 0 alerts', () => {
      const config = createVariantAConfig()
      const testCsv = readData('data/mission04_tests/TC11_empty_file_A.csv')
      const result = runDetectionPipeline({
        authData: testCsv,
        assetData: assetListA,
        ipLocationData: ipLocationsA,
        config,
      })

      expect(result.events).toHaveLength(0)
      expect(result.ruleMatches).toHaveLength(0)
      expect(result.incidents).toHaveLength(0)
      expect(result.ingestionReport?.validEvents).toBe(0)
    })

    it('TC11_B: safely parses header-only CSV in variant B', () => {
      const config = createVariantBConfig()
      const testCsv = readData('data/mission04_tests/TC11_empty_file_B.csv')
      const result = runDetectionPipeline({
        authData: testCsv,
        assetData: assetListB,
        ipLocationData: ipLocationsB,
        config,
      })

      expect(result.events).toHaveLength(0)
      expect(result.ruleMatches).toHaveLength(0)
      expect(result.incidents).toHaveLength(0)
    })
  })

  // ─── Ground-Truth Validation: Mission 01 Scenarios ─────────────────────────
  describe('Mission 01 Official Scenarios Ground Truth Validation', () => {
    it('accurately evaluates all labeled scenarios in mission01_scenarios_A.csv', () => {
      const config = createVariantAConfig()
      const trainingParsed = parseAuthCsv(trainingLogsA, config)
      const m1Parsed = parseAuthCsv(readData('data/mission01_auth_logs_days6-7_A.csv'), config)

      const result = runDetectionPipeline({
        authData: [...trainingParsed.events, ...m1Parsed.events],
        assetData: assetListA,
        ipLocationData: ipLocationsA,
        config,
      })

      // M1-S01: meera.sharma -> failure_burst (brute_force)
      const s01 = result.ruleMatches.find(m => m.username === 'meera.sharma' && m.ruleId === 'brute_force')
      expect(s01).toBeDefined()

      // M1-S02: rahul.gupta -> failure_then_success (burst_success) and new_ip_or_location
      const s02Success = result.ruleMatches.find(m => m.username === 'rahul.gupta' && m.ruleId === 'burst_success')
      expect(s02Success).toBeDefined()
      const s02Location = result.ruleMatches.find(m => m.username === 'rahul.gupta' && m.ruleId === 'new_ip_location')
      expect(s02Location).toBeDefined()

      // M1-S03: 198.51.100.62 -> password_spraying (password_spray)
      const s03 = result.ruleMatches.filter(m => m.ruleId === 'password_spray')
      expect(s03.length).toBeGreaterThanOrEqual(10)

      // M1-S04: gauri.reddy -> 3 typos then success (benign lookalike, below threshold)
      const s04Bf = result.ruleMatches.find(m => m.username === 'gauri.reddy' && (m.ruleId === 'brute_force' || m.ruleId === 'burst_success'))
      expect(s04Bf).toBeUndefined()

      // M1-DATA: 6 exact duplicate rows deduplicated
      expect(m1Parsed.report.duplicateCount).toBe(6)
    })

    it('accurately evaluates all labeled scenarios in mission01_scenarios_B.csv', () => {
      const config = createVariantBConfig()
      const trainingParsed = parseAuthCsv(trainingLogsB, config)
      const m1Parsed = parseAuthCsv(readData('data/mission01_auth_logs_days6-7_B.csv'), config)

      const result = runDetectionPipeline({
        authData: [...trainingParsed.events, ...m1Parsed.events],
        assetData: assetListB,
        ipLocationData: ipLocationsB,
        config,
      })

      // M1-S01: chetan_bose -> failure_burst
      const s01 = result.ruleMatches.find(m => m.username === 'chetan_bose' && m.ruleId === 'brute_force')
      expect(s01).toBeDefined()

      // M1-S02: tara_singh -> failure_then_success & new_ip_location
      const s02Success = result.ruleMatches.find(m => m.username === 'tara_singh' && m.ruleId === 'burst_success')
      expect(s02Success).toBeDefined()

      // M1-S03: 198.51.100.62 -> password_spray
      const s03 = result.ruleMatches.filter(m => m.ruleId === 'password_spray')
      expect(s03.length).toBeGreaterThanOrEqual(10)

      // M1-S04: yamini_das -> 3 typos (benign lookalike)
      const s04 = result.ruleMatches.find(m => m.username === 'yamini_das' && (m.ruleId === 'brute_force' || m.ruleId === 'burst_success'))
      expect(s04).toBeUndefined()

      // M1-DATA: 6 duplicate rows deduplicated
      expect(m1Parsed.report.duplicateCount).toBe(6)
    })
  })

  // ─── Ground-Truth Validation: Mission 02 Scenarios ─────────────────────────
  describe('Mission 02 Official Scenarios Ground Truth Validation', () => {
    it('accurately detects impossible travel for sneha.nair and suppresses benign VPN login in mission02_auth_logs_days6-7_A.csv', () => {
      const config = createVariantAConfig()
      const trainingParsed = parseAuthCsv(trainingLogsA, config)
      const m2Parsed = parseAuthCsv(readData('data/mission02_auth_logs_days6-7_A.csv'), config)

      const result = runDetectionPipeline({
        authData: [...trainingParsed.events, ...m2Parsed.events],
        assetData: assetListA,
        ipLocationData: ipLocationsA,
        config,
      })

      // sneha.nair logs in from Hyderabad (10.10.10.33) at 09:24, then Frankfurt (198.51.100.82) at 09:37
      // Distance is ~7200 km in 13 minutes (>33,000 km/h) -> triggers impossible travel
      const snehaTravel = result.ruleMatches.find(
        m => m.username === 'sneha.nair' && m.ruleId === 'impossible_travel'
      )
      expect(snehaTravel).toBeDefined()
      expect(snehaTravel!.evidence.eventIds).toContain('A-E001729')

      // diya.rao logs in via company VPN (172.16.50.53, 172.16.50.132) -> suppressed by approved VPN
      const diyaTravel = result.ruleMatches.find(
        m => m.username === 'diya.rao' && m.ruleId === 'impossible_travel'
      )
      expect(diyaTravel).toBeUndefined()
    })

    it('accurately detects impossible travel and context handling in mission02_auth_logs_days6-7_B.csv', () => {
      const config = createVariantBConfig()
      const trainingParsed = parseAuthCsv(trainingLogsB, config)
      const m2Parsed = parseAuthCsv(readData('data/mission02_auth_logs_days6-7_B.csv'), config)

      const result = runDetectionPipeline({
        authData: [...trainingParsed.events, ...m2Parsed.events],
        assetData: assetListB,
        ipLocationData: ipLocationsB,
        config,
      })

      // kunal_patel triggers impossible travel in Variant B (Bengaluru -> Frankfurt in 22 min)
      const kunalTravel = result.ruleMatches.find(
        m => m.username === 'kunal_patel' && m.ruleId === 'impossible_travel'
      )
      expect(kunalTravel).toBeDefined()
    })
  })
})
