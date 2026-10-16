/**
 * Detection Pipeline — Mission 72
 *
 * Coordinates the full analysis pipeline:
 *   1. CSV Ingestion & normalization (or pre-parsed AuthEvents)
 *   2. Asset inventory & IP-location mapping parsing
 *   3. IP-to-location enrichment
 *   4. Behavioral baseline construction (exclusively from training period)
 *   5. Rule execution across analysis period
 *   6. Incident correlation and heuristic risk scoring
 *   7. Baseline coverage tracking
 *
 * Pure, deterministic, framework-agnostic.
 */

import type {
  AuthEvent,
  AnalysisConfig,
  AnalysisResult,
  AssetRecord,
  AssetParseResult,
  IpLocationRecord,
  IpLocationParseResult,
  IngestionReport,
  RuleMatch,
  Incident,
  UserBaseline,
} from '@/types'
import { parseAuthCsv } from './ingest'
import { parseAssets, parseIpLocations, lookupLocation } from './assets'
import { buildBaselines } from './baseline'
import { runAllRules, type RuleContext } from './rules'
import { correlateIncidents } from './incidents'

// ─── Default Configuration ───────────────────────────────────────────────────

export function createDefaultConfig(overrides: Partial<AnalysisConfig> = {}): AnalysisConfig {
  return {
    timezone: 'UTC',
    trainingPeriod: {
      start: '2026-10-01T00:00:00Z',
      end: '2026-10-08T00:00:00Z',
    },
    analysisPeriod: {
      start: '2026-10-08T00:00:00Z',
      end: '2026-10-15T00:00:00Z',
    },
    approvedVpnCidrs: [
      '192.0.2.0/24', // RFC 5737 TEST-NET-1 (used for approved corporate VPN in synthetic data)
    ],
    maintenanceWindows: [
      {
        daysOfWeek: [0], // Sunday
        startHour: 2,
        endHour: 4,
        allowedUsers: ['svc_backup'],
      },
    ],
    rules: {
      bruteForce: {
        failureCount: 5,
        windowSeconds: 120,
      },
      burstSuccess: {
        failureCount: 3,
        windowSeconds: 180,
      },
      passwordSpray: {
        userCount: 4,
        windowSeconds: 300,
      },
      unusualHours: {
        offHoursStart: 22,
        offHoursEnd: 6,
      },
      newHosts: {
        newHostCount: 4,
        windowHours: 4,
      },
    },
    ...overrides,
  }
}

// ─── Pipeline Input & Output ──────────────────────────────────────────────────

export interface PipelineInput {
  /** Raw CSV string of authentication events, or pre-parsed AuthEvents. */
  authData: string | AuthEvent[]
  /** Raw CSV string of assets, or pre-parsed AssetRecords. */
  assetData?: string | AssetRecord[]
  /** Raw CSV string of IP-location mappings, or pre-parsed IpLocationRecords. */
  ipLocationData?: string | IpLocationRecord[]
  /** Optional analysis configuration overrides. */
  config?: Partial<AnalysisConfig>
}

export interface PipelineResult {
  /** Parsed asset inventory. */
  assets: AssetRecord[]
  /** Parsed IP-location records. */
  ipLocations: IpLocationRecord[]
  /** Enriched AuthEvents sorted ascending by timestamp. */
  events: AuthEvent[]
  /** Report from CSV parsing (null if pre-parsed events were supplied). */
  ingestionReport: IngestionReport | null
  /** Asset parse result (null if pre-parsed or empty). */
  assetParseResult: AssetParseResult | null
  /** IP location parse result (null if pre-parsed or empty). */
  ipLocationParseResult: IpLocationParseResult | null
  /** Per-user behavioral baselines learned from the training period. */
  baselines: Map<string, UserBaseline>
  /** All raw rule firings before incident correlation. */
  ruleMatches: RuleMatch[]
  /** Correlated incidents with bounded heuristic risk scores. */
  incidents: Incident[]
  /** Users without sufficient baseline coverage in the training period. */
  insufficientBaselineUsers: string[]
  /** Combined AnalysisResult conforming to domain type. */
  analysisResult: AnalysisResult
  /** The effective configuration used for analysis. */
  config: AnalysisConfig
}

// ─── Main Pipeline Execution ──────────────────────────────────────────────────

/**
 * Execute the full detection pipeline.
 */
export function runDetectionPipeline(input: PipelineInput): PipelineResult {
  const config = createDefaultConfig(input.config)

  // 1. Parse or accept assets
  let assets: AssetRecord[] = []
  let assetParseResult: AssetParseResult | null = null
  if (typeof input.assetData === 'string') {
    assetParseResult = parseAssets(input.assetData)
    assets = assetParseResult.assets
  } else if (Array.isArray(input.assetData)) {
    assets = input.assetData
  }

  // 2. Parse or accept IP-location mappings
  let ipLocations: IpLocationRecord[] = []
  let ipLocationParseResult: IpLocationParseResult | null = null
  if (typeof input.ipLocationData === 'string') {
    ipLocationParseResult = parseIpLocations(input.ipLocationData)
    ipLocations = ipLocationParseResult.locations
  } else if (Array.isArray(input.ipLocationData)) {
    ipLocations = input.ipLocationData
  }

  // 3. Ingest and normalize AuthEvents
  let events: AuthEvent[]
  let ingestionReport: IngestionReport | null = null

  if (typeof input.authData === 'string') {
    const ingestResult = parseAuthCsv(input.authData, config)
    events = ingestResult.events
    ingestionReport = ingestResult.report
  } else {
    events = [...input.authData].sort((a, b) => a.timestamp.localeCompare(b.timestamp))
  }

  // 4. Enrich events with geographic/network location from IP mappings
  if (ipLocations.length > 0) {
    for (const ev of events) {
      if (!ev.location) {
        ev.location = lookupLocation(ev.sourceIp, ipLocations)
      }
    }
  }

  // 5. Build behavioral baselines strictly from the training period
  const baselines = buildBaselines(events, config)

  // Identify users with insufficient baseline coverage
  const insufficientBaselineUsers: string[] = []
  for (const [username, baseline] of baselines) {
    if (baseline.status === 'none' || baseline.status === 'limited') {
      insufficientBaselineUsers.push(username)
    }
  }

  // 6. Execute all detection rules
  const ruleContext: RuleContext = {
    baselines,
    config,
    ipLocations,
    vpnCidrs: [], // populated inside runAllRules via parseVpnCidrs
  }

  const ruleMatches = runAllRules(events, ruleContext)

  // 7. Correlate rule matches into incidents with heuristic risk scoring
  const incidents = correlateIncidents(ruleMatches)

  const analysisResult: AnalysisResult = {
    incidents,
    ruleMatches,
    insufficientBaselineUsers,
  }

  return {
    assets,
    ipLocations,
    events,
    ingestionReport,
    assetParseResult,
    ipLocationParseResult,
    baselines,
    ruleMatches,
    incidents,
    insufficientBaselineUsers,
    analysisResult,
    config,
  }
}
