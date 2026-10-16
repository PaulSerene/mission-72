/**
 * End-to-End Pipeline & Synthetic Dataset Verification Tests — Mission 72
 *
 * Verifies the entire data processing and detection engine pipeline
 * using the seeded synthetic dataset, asserting each planted threat
 * and benign scenario explicitly without importing expected.json into
 * the detection engine.
 */

import { describe, expect, it } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { runDetectionPipeline, createDefaultConfig } from './pipeline'
import { DetectionEngine } from './DetectionEngine'
import { generateSyntheticDataset } from '@/data/generate'

describe('Synthetic Dataset Determinism & Generator Independence', () => {
  it('generates 100% deterministic, bit-for-bit identical data with the same seed', () => {
    const ds1 = generateSyntheticDataset(42)
    const ds2 = generateSyntheticDataset(42)

    expect(ds1.authCsv).toBe(ds2.authCsv)
    expect(ds1.assetsCsv).toBe(ds2.assetsCsv)
    expect(ds1.ipLocationsCsv).toBe(ds2.ipLocationsCsv)
    expect(ds1.manifest.scenarios).toEqual(ds2.manifest.scenarios)
  })

  it('guarantees separation: detection engine source files never import expected.json', () => {
    const engineFiles = [
      'DetectionEngine.ts',
      'pipeline.ts',
      'rules.ts',
      'baseline.ts',
      'ingest.ts',
      'assets.ts',
      'incidents.ts',
    ]

    for (const filename of engineFiles) {
      const filePath = path.resolve(process.cwd(), 'src/engine', filename)
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf-8')
        expect(content).not.toContain('expected.json')
      }
    }
  })
})

describe('End-to-End Pipeline Execution on Synthetic Dataset', () => {
  // Generate reproducible synthetic dataset with fixed seed 42
  const dataset = generateSyntheticDataset(42)
  const config = createDefaultConfig()

  // Run the real detection pipeline
  const result = runDetectionPipeline({
    authData: dataset.authCsv,
    assetData: dataset.assetsCsv,
    ipLocationData: dataset.ipLocationsCsv,
    config,
  })

  it('produces a complete IngestionReport with correct data hygiene diagnostics', () => {
    const { ingestionReport } = result
    expect(ingestionReport).not.toBeNull()

    // Total rows = 280 (275 valid/duplicate rows + 5 malformed rows)
    expect(ingestionReport!.totalRows).toBe(280)

    // Scenario 10: 5 malformed rows rejected safely into invalidRows
    expect(ingestionReport!.invalidRows).toHaveLength(5)
    const reasons = ingestionReport!.invalidRows.map(r => r.reason)
    expect(reasons.some(r => r.includes('Missing or empty timestamp'))).toBe(true)
    expect(reasons.some(r => r.includes('Unparseable timestamp'))).toBe(true)
    expect(reasons.some(r => r.includes('Missing or empty username'))).toBe(true)
    expect(reasons.some(r => r.includes('Invalid IPv4 address'))).toBe(true)
    expect(reasons.some(r => r.includes('Missing or empty source IP'))).toBe(true)

    // Scenario 9: 3 duplicate records detected by stable content hash
    expect(ingestionReport!.duplicateCount).toBe(3)
  })

  it('Scenario 1: Detects repeated authentication failures (brute force) for victor', () => {
    const bfMatches = result.ruleMatches.filter(
      m => m.ruleId === 'brute_force' && m.username === 'victor',
    )
    expect(bfMatches.length).toBeGreaterThanOrEqual(1)
    expect(bfMatches[0].evidence.eventIds).toHaveLength(6)
    expect(bfMatches[0].severity).toBe('high')
  })

  it('Scenario 2: Detects burst of failures followed by success for charlie', () => {
    const burstMatches = result.ruleMatches.filter(
      m => m.ruleId === 'burst_success' && m.username === 'charlie',
    )
    expect(burstMatches.length).toBeGreaterThanOrEqual(1)
    expect(burstMatches[0].username).toBe('charlie')
    expect(burstMatches[0].evidence.data?.failureCount).toBe(4)
    expect(burstMatches[0].severity).toBe('high')
  })

  it('Scenario 3: Detects password spraying across 5 accounts from 198.51.100.99', () => {
    const sprayMatches = result.ruleMatches.filter(m => m.ruleId === 'password_spray')
    expect(sprayMatches.length).toBeGreaterThanOrEqual(5)

    const targetedUsers = sprayMatches.map(m => m.username)
    expect(targetedUsers).toContain('david')
    expect(targetedUsers).toContain('emma')
    expect(targetedUsers).toContain('grace')
    expect(targetedUsers).toContain('hannah')
    expect(targetedUsers).toContain('ian')

    // Offending IP
    expect(sprayMatches[0].evidence.data?.sourceIp).toBe('198.51.100.99')
  })

  it('Scenario 4: Detects unusual nighttime login for diana', () => {
    const dianaMatches = result.ruleMatches.filter(
      m => m.ruleId === 'unusual_hours' && m.username === 'diana',
    )
    expect(dianaMatches.length).toBeGreaterThanOrEqual(1)
    expect(dianaMatches[0].evidence.description).toContain('never logged in at 03:00 UTC')
  })

  it('Scenario 5: Detects successful login from new IP and location for edward', () => {
    const edwardMatches = result.ruleMatches.filter(
      m => m.ruleId === 'new_ip_location' && m.username === 'edward',
    )
    expect(edwardMatches.length).toBeGreaterThanOrEqual(1)
    expect(edwardMatches[0].evidence.data?.sourceIp).toBe('203.0.113.190')
    expect(edwardMatches[0].evidence.data?.location).toBe('External / Remote Access')
  })

  it('Scenario 6: Detects sudden access to 5 unfamiliar hosts for frank', () => {
    const frankMatches = result.ruleMatches.filter(
      m => m.ruleId === 'new_hosts' && m.username === 'frank',
    )
    expect(frankMatches.length).toBeGreaterThanOrEqual(1)
    expect(frankMatches[0].evidence.data?.newHostCount).toBe(5)
  })

  it('Scenario 7: Suppresses unusual_hours alert for benign maintenance-window activity (svc_backup)', () => {
    // svc_backup logged in at 02:30 UTC on Sunday, which is inside the maintenance window
    const svcMatches = result.ruleMatches.filter(m => m.username === 'svc_backup')
    expect(svcMatches).toHaveLength(0)
  })

  it('Scenario 8: Suppresses new_ip_location alert for approved corporate VPN (alice_vpn)', () => {
    // alice_vpn logged in from 192.0.2.88 (inside approved VPN 192.0.2.0/24)
    const vpnMatches = result.ruleMatches.filter(
      m => m.ruleId === 'new_ip_location' && m.username === 'alice_vpn',
    )
    expect(vpnMatches).toHaveLength(0)
  })

  it('Correlates detections into valid Incidents with bounded heuristic risk scores [0, 100]', () => {
    expect(result.incidents.length).toBeGreaterThan(0)

    for (const incident of result.incidents) {
      expect(incident.riskScore).toBeGreaterThanOrEqual(0)
      expect(incident.riskScore).toBeLessThanOrEqual(100)
      expect(['critical', 'high', 'medium', 'low']).toContain(incident.severity)
      expect(incident.explanation.length).toBeGreaterThan(10)
      expect(incident.recommendedTriage.length).toBeGreaterThan(10)
      expect(incident.ruleMatches.length).toBeGreaterThan(0)
    }

    // High severity incident for charlie (burst_success)
    const charlieIncident = result.incidents.find(i => i.username === 'charlie')
    expect(charlieIncident).toBeDefined()
    expect(charlieIncident!.riskScore).toBeGreaterThanOrEqual(55)
    expect(charlieIncident!.recommendedTriage).toContain('Critical compromise indicator')
  })

  it('DetectionEngine.analyze() produces equivalent result', () => {
    const engine = new DetectionEngine()
    const engineResult = engine.analyze({
      authData: dataset.authCsv,
      assetData: dataset.assetsCsv,
      ipLocationData: dataset.ipLocationsCsv,
      config,
    })

    expect(engineResult.incidents.length).toBe(result.incidents.length)
    expect(engineResult.ruleMatches.length).toBe(result.ruleMatches.length)
    expect(engineResult.ingestionReport?.totalRows).toBe(result.ingestionReport?.totalRows)
  })
})
