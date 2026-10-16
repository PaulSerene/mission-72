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
  SuppressedAlert,
} from '@/types'
import { parseAuthCsv } from './ingest'
import { parseAssets, parseIpLocations, lookupLocationRecord } from './assets'
import { buildBaselines } from './baseline'
import { runAllRules, type RuleContext } from './rules'
import { correlateIncidents } from './incidents'
import { validateConfig } from './configValidation'

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
      {
        cidr: '192.0.2.0/24', // RFC 5737 TEST-NET-1 (used for approved corporate VPN in synthetic data)
        id: 'VPN-CORP-EAST',
        description: 'Approved Corporate VPN (Remote Workforce)',
      },
    ],
    maintenanceWindows: [
      {
        id: 'MW-WEEKLY-SUNDAY',
        description: 'Weekly scheduled off-hours system backup and IT maintenance',
        daysOfWeek: [0], // Sunday
        startHour: 2,
        endHour: 4,
        timezone: 'UTC',
        allowedUsers: ['svc_backup'],
        authorizedHelpdeskAccounts: ['helpdesk1', 'helpdesk2', 'it_support', 'helpdesk_bob'],
      },
    ],
    accountRoles: {
      svc_backup: 'service',
      helpdesk1: 'helpdesk',
      helpdesk2: 'helpdesk',
      it_support: 'helpdesk',
      helpdesk_bob: 'helpdesk',
      alice: 'regular',
      bob: 'regular',
      victor: 'regular',
      charlie: 'regular',
      david: 'regular',
      diana: 'regular',
      edward: 'developer',
      frank: 'regular',
    },
    authorizedHelpdeskAccounts: ['helpdesk1', 'helpdesk2', 'it_support', 'helpdesk_bob'],
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
      impossibleTravel: {
        maxSpeedKmH: 1000,
        minDistanceKm: 100,
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
  /** Contextual exceptions / signals suppressed by security policies (audit trail). */
  suppressedAlerts: SuppressedAlert[]
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

  // Validate configuration before execution
  const validation = validateConfig(config)
  if (!validation.valid) {
    throw new Error(`Configuration validation failed:\n- ${validation.errors.join('\n- ')}`)
  }

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
      const match = lookupLocationRecord(ev.sourceIp, ipLocations)
      if (match) {
        if (!ev.location) {
          ev.location = match.location
        }
        if (ev.latitude === undefined || ev.latitude === null) {
          if (match.latitude !== undefined) {
            ev.latitude = match.latitude
          }
        }
        if (ev.longitude === undefined || ev.longitude === null) {
          if (match.longitude !== undefined) {
            ev.longitude = match.longitude
          }
        }
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

  // 6. Execute all detection rules with context suppression audit log
  const suppressedAlerts: SuppressedAlert[] = []
  const ruleContext: RuleContext = {
    baselines,
    config,
    ipLocations,
    vpnCidrs: [], // populated inside runAllRules via parseVpnCidrs
    accountRoles: config.accountRoles ?? {},
    authorizedHelpdeskAccounts: new Set(config.authorizedHelpdeskAccounts ?? []),
    suppressedAlerts,
  }

  const ruleMatches = runAllRules(events, ruleContext)

  // 7. Correlate rule matches into incidents with heuristic risk scoring
  const incidents = correlateIncidents(ruleMatches)

  const analysisResult: AnalysisResult = {
    incidents,
    ruleMatches,
    insufficientBaselineUsers,
    suppressedAlerts,
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
    suppressedAlerts,
    analysisResult,
    config,
  }
}
