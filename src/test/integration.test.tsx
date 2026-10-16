import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { runDetectionPipeline, createDefaultConfig } from '@/engine/pipeline'
import { generateSyntheticDataset } from '@/data/generate'
import { StatCard } from '@/components/StatCard'
import { SeverityBadge } from '@/components/SeverityBadge'
import { IncidentTable } from '@/components/IncidentFeed/IncidentTable'
import { AppProvider } from '@/state/AppState'
import DashboardPage from '@/pages/DashboardPage'

describe('Milestone 3 Integration Tests', () => {
  // Generate seeded synthetic data
  const dataset = generateSyntheticDataset(42)

  let container: HTMLDivElement | null = null
  let root: Root | null = null

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })

  afterEach(() => {
    if (root && container) {
      act(() => {
        root!.unmount()
      })
      container.remove()
      container = null
      root = null
    }
  })

  describe('End-to-end Pipeline & Metrics Derivation', () => {
    it('processes synthetic demo dataset and extracts valid metrics', () => {
      const result = runDetectionPipeline({
        authData: dataset.authCsv,
        assetData: dataset.assetsCsv,
        ipLocationData: dataset.ipLocationsCsv,
      })

      // Ingestion quality metrics
      expect(result.ingestionReport).not.toBeNull()
      expect(result.ingestionReport!.validEvents).toBeGreaterThan(200)
      expect(result.ingestionReport!.invalidRows.length).toBeGreaterThan(0) // Has planted malformed rows
      expect(result.ingestionReport!.duplicateCount).toBeGreaterThan(0) // Has planted duplicates

      // Detection results
      expect(result.incidents.length).toBeGreaterThan(0)
      expect(result.ruleMatches.length).toBeGreaterThan(0)

      // Severity classification
      const validSeverities = new Set(['critical', 'high', 'medium', 'low'])
      for (const incident of result.incidents) {
        expect(validSeverities.has(incident.severity)).toBe(true)
      }
      expect(result.incidents.some(i => i.severity === 'critical')).toBe(true)

      // Verify incident risk scores are bounded [0, 100]
      for (const incident of result.incidents) {
        expect(incident.riskScore).toBeGreaterThanOrEqual(0)
        expect(incident.riskScore).toBeLessThanOrEqual(100)
        expect(incident.ruleMatches.length).toBeGreaterThan(0)
        expect(incident.explanation).toBeTruthy()
        expect(incident.recommendedTriage).toBeTruthy()
      }
    })

    it('re-analyzes with custom configuration and changes detection behavior', () => {
      // Run with default brute-force threshold (5 failures)
      const defaultResult = runDetectionPipeline({
        authData: dataset.authCsv,
        assetData: dataset.assetsCsv,
        ipLocationData: dataset.ipLocationsCsv,
      })

      // Run with relaxed brute-force threshold (50 failures)
      const customConfig = createDefaultConfig({
        rules: {
          bruteForce: { failureCount: 50, windowSeconds: 60 },
          burstSuccess: { failureCount: 3, windowSeconds: 600 },
          passwordSpray: { userCount: 5, windowSeconds: 900 },
          unusualHours: { offHoursStart: 20, offHoursEnd: 6 },
          newHosts: { newHostCount: 3, windowHours: 24 },
        },
      })

      const reanalyzedResult = runDetectionPipeline({
        authData: dataset.authCsv,
        assetData: dataset.assetsCsv,
        ipLocationData: dataset.ipLocationsCsv,
        config: customConfig,
      })

      const defaultBf = defaultResult.ruleMatches.filter(r => r.ruleId === 'brute_force')
      const reanalyzedBf = reanalyzedResult.ruleMatches.filter(r => r.ruleId === 'brute_force')

      // A threshold of 50 failures should result in fewer or zero brute force detections
      expect(reanalyzedBf.length).toBeLessThanOrEqual(defaultBf.length)
    })

    it('gracefully handles malformed input and produces invalidRow diagnostics', () => {
      const malformedCsv = `timestamp,user,ip,status\nnot-a-date,baduser,999.999.999.999,invalid`
      const result = runDetectionPipeline({
        authData: malformedCsv,
      })

      expect(result.events).toHaveLength(0)
      expect(result.ingestionReport).not.toBeNull()
      expect(result.ingestionReport!.validEvents).toBe(0)
      expect(result.ingestionReport!.invalidRows.length).toBeGreaterThan(0)
      expect(result.incidents).toHaveLength(0)
    })

    it('gracefully handles empty CSV content without throwing', () => {
      const result = runDetectionPipeline({
        authData: '',
      })

      expect(result.events).toHaveLength(0)
      expect(result.ingestionReport).not.toBeNull()
      expect(result.ingestionReport!.totalRows).toBe(0)
      expect(result.incidents).toHaveLength(0)
    })
  })

  describe('Component Rendering in DOM Context', () => {
    it('renders StatCard with label and value', () => {
      act(() => {
        root!.render(
          <StatCard
            id="test-card"
            label="Active Incidents"
            value={42}
            variant="accent"
          />
        )
      })
      expect(container!.textContent).toContain('Active Incidents')
      expect(container!.textContent).toContain('42')
    })

    it('renders SeverityBadge with correct text', () => {
      act(() => {
        root!.render(<SeverityBadge severity="critical" />)
      })
      expect(container!.textContent).toContain('CRITICAL')
    })

    it('renders IncidentTable empty state when incident list is empty', () => {
      act(() => {
        root!.render(
          <AppProvider>
            <IncidentTable incidents={[]} />
          </AppProvider>
        )
      })
      expect(container!.textContent).toContain('No incidents match the active filters')
    })

    it('renders DashboardPage onboarding state on initial load', () => {
      act(() => {
        root!.render(
          <AppProvider>
            <DashboardPage />
          </AppProvider>
        )
      })

      // Dashboard title
      expect(container!.textContent).toContain('Security Operations')
      // Onboarding welcome
      expect(container!.textContent).toContain('Welcome to SignalForge')
      // Quick demo action button
      expect(container!.textContent).toContain('Load Synthetic Demo Dataset')
      // Step guides
      expect(container!.textContent).toContain('Import Authentication Logs')
      expect(container!.textContent).toContain('Multi-Rule Correlation')
    })
  })
})
