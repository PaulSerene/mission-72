/**
 * Engine module barrel export — Mission 72
 */
export { DetectionEngine, buildAlert, generateId } from './DetectionEngine'
export type { EngineOptions, RuleEvaluator } from './DetectionEngine'

// Pipeline
export { runDetectionPipeline, createDefaultConfig } from './pipeline'
export type { PipelineInput, PipelineResult } from './pipeline'

// CSV Ingestion
export {
  parseAuthCsv,
  parseTimestamp,
  parseNaiveDatetime,
  parseZonedDatetime,
  parseUnixTimestamp,
  isValidIpv4,
  stableEventId,
} from './ingest'

// Assets and IP Locations
export {
  parseAssets,
  parseIpLocations,
  lookupLocation,
  lookupAsset,
  parseCidrV4,
  isIpv4InCidr,
  isIpInAnyCidr,
  parseVpnCidrs,
  ipv4ToInt,
} from './assets'

// Behavioral Baselines
export {
  buildBaselines,
  makeEmptyBaseline,
  isUnusualHour,
} from './baseline'

// Detection Rules
export {
  detectBruteForce,
  detectBurstSuccess,
  detectPasswordSpray,
  detectUnusualHours,
  detectNewIpOrLocation,
  detectNewHosts,
  runAllRules,
  RULE_SCORES,
} from './rules'
export type { RuleContext } from './rules'

// Incident Correlation
export {
  correlateIncidents,
  calculateIncidentRiskScore,
  scoreToSeverity,
  generateExplanation,
  generateRecommendedTriage,
} from './incidents'
