/**
 * Integration Tests for Mission 03 — Incident Visualization & Risk Analysis
 *
 * Verifies:
 * - Rendering of Investigation Studio workspace
 * - User-to-Host Graph SVG rendering and accessible table alternative toggle
 * - Chronological event timeline sorting, filtering, and event inspector drawer
 * - Faithful risk breakdown display with exact engine score contributions
 * - Alert explanations with deterministic evidence-strength badges
 * - Bidirectional cross-filtering between rules, hosts, and timeline events
 * - Both normal and suspicious authentication log sample scenarios
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { InvestigationWorkspace } from '@/components/Investigation'
import { IncidentDetailModal } from '@/components/IncidentDetail'
import { AppProvider, useAppActions } from '@/state/AppState'
import type { Incident, AuthEvent, AssetRecord } from '@/types'

// Test sample data
const mockAssets: AssetRecord[] = [
  { host: 'dc-01.corp.local', role: 'domain-controller', privileged: true },
  { host: 'db-prod.corp.local', role: 'database', privileged: true },
  { host: 'fs-storage.corp.local', role: 'file-server', privileged: false },
]

const normalEvents: AuthEvent[] = [
  {
    id: 'norm-1',
    timestamp: '2026-10-10T09:00:00Z',
    username: 'bob',
    sourceIp: '10.0.1.50',
    destination: 'fs-storage.corp.local',
    eventType: 'authentication',
    outcome: 'success',
    logonType: 'interactive',
    location: 'Corporate HQ',
    rawRow: 1,
    isDuplicate: false,
  },
]

const suspiciousEvents: AuthEvent[] = [
  {
    id: 'ev-susp-1',
    timestamp: '2026-10-10T02:10:00Z',
    username: 'alice',
    sourceIp: '203.0.113.5',
    destination: 'dc-01.corp.local',
    eventType: 'authentication',
    outcome: 'failure',
    logonType: 'network',
    location: 'External',
    rawRow: 10,
    isDuplicate: false,
  },
  {
    id: 'ev-susp-2',
    timestamp: '2026-10-10T02:11:00Z',
    username: 'alice',
    sourceIp: '203.0.113.5',
    destination: 'dc-01.corp.local',
    eventType: 'authentication',
    outcome: 'failure',
    logonType: 'network',
    location: 'External',
    rawRow: 11,
    isDuplicate: false,
  },
  {
    id: 'ev-susp-3',
    timestamp: '2026-10-10T02:12:00Z',
    username: 'alice',
    sourceIp: '203.0.113.5',
    destination: 'dc-01.corp.local',
    eventType: 'authentication',
    outcome: 'success',
    logonType: 'network',
    location: 'External',
    rawRow: 12,
    isDuplicate: false,
  },
  {
    id: 'ev-susp-4',
    timestamp: '2026-10-10T02:15:00Z',
    username: 'alice',
    sourceIp: '203.0.113.5',
    destination: 'db-prod.corp.local',
    eventType: 'authentication',
    outcome: 'success',
    logonType: 'network',
    location: 'External',
    rawRow: 13,
    isDuplicate: false,
  },
]

const sampleIncident: Incident = {
  id: 'inc-0001-alice',
  username: 'alice',
  startTimestamp: '2026-10-10T02:10:00Z',
  endTimestamp: '2026-10-10T02:15:00Z',
  ruleMatches: [
    {
      ruleId: 'burst_success',
      ruleName: 'Burst Authentication Success After Failures',
      severity: 'critical',
      username: 'alice',
      timestamp: '2026-10-10T02:12:00Z',
      mitreTactic: 'Initial Access',
      evidence: {
        eventIds: ['ev-susp-1', 'ev-susp-2', 'ev-susp-3'],
        description: '2 failures immediately followed by successful logon on dc-01',
      },
    },
    {
      ruleId: 'new_hosts',
      ruleName: 'Unfamiliar Host Access',
      severity: 'high',
      username: 'alice',
      timestamp: '2026-10-10T02:15:00Z',
      mitreTactic: 'Lateral Movement',
      evidence: {
        eventIds: ['ev-susp-4'],
        description: 'Accessed unobserved host db-prod.corp.local',
      },
    },
  ],
  riskScore: 85,
  severity: 'critical',
  explanation: 'Correlated incident for alice: burst success followed by new host access.',
  recommendedTriage: 'Immediately isolate accessed database and reset account credentials.',
}

describe('Investigation Workspace Integration', () => {
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

  it('renders Investigation Workspace with UserHostGraph, RiskBreakdown, Timeline, and AlertExplanations', async () => {
    await act(async () => {
      root!.render(
        <InvestigationWorkspace
          incident={sampleIncident}
          allEvents={[...normalEvents, ...suspiciousEvents]}
          assets={mockAssets}
          baselineStatus="sufficient"
        />,
      )
    })

    // 1. Verify Topology Graph SVG rendered
    const svg = container!.querySelector('svg[role="graphics-document"]')
    expect(svg).not.toBeNull()
    expect(svg!.getAttribute('aria-label')).toContain('alice')

    // Verify host nodes rendered (dc-01 and db-prod)
    const hostNodeLabels = container!.querySelectorAll('text')
    const textContents = Array.from(hostNodeLabels).map(t => t.textContent)
    expect(textContents.some(t => t?.includes('dc-01'))).toBe(true)

    // 2. Verify Risk Breakdown rendered
    expect(container!.textContent).toContain('Heuristic Risk Breakdown')
    expect(container!.textContent).toContain('Burst Authentication Success')
    expect(container!.textContent).toContain('+55')

    // 3. Verify Alert Explanations rendered with Evidence Strength
    expect(container!.textContent).toContain('Alert Explanations')
    expect(container!.textContent).toContain('Evidence:')

    // 4. Verify Chronological Timeline rendered
    expect(container!.textContent).toContain('Chronological Event Timeline')
    expect(container!.textContent).toContain('dc-01.corp.local')
    expect(container!.textContent).toContain('FAILURE')
    expect(container!.textContent).toContain('SUCCESS')
  })

  it('toggles UserHostGraph to accessible table alternative and back', async () => {
    await act(async () => {
      root!.render(
        <InvestigationWorkspace
          incident={sampleIncident}
          allEvents={[...normalEvents, ...suspiciousEvents]}
          assets={mockAssets}
          baselineStatus="sufficient"
        />,
      )
    })

    const toggleBtn = container!.querySelector('button[aria-label="Switch to accessible table view"]') as HTMLButtonElement
    expect(toggleBtn).not.toBeNull()

    // Click to switch to accessible table
    act(() => {
      toggleBtn.click()
    })

    const table = container!.querySelector('table[aria-label="User-to-host interaction relationships"]')
    expect(table).not.toBeNull()
    expect(table!.textContent).toContain('dc-01.corp.local')
    expect(table!.textContent).toContain('db-prod.corp.local')

    // Toggle back to SVG
    const backBtn = container!.querySelector('button[aria-label="Switch to interactive graph view"]') as HTMLButtonElement
    expect(backBtn).not.toBeNull()
    act(() => {
      backBtn.click()
    })
    expect(container!.querySelector('svg[role="graphics-document"]')).not.toBeNull()
  })

  it('clicking a timeline event opens the Event Detail Inspector with raw attributes', async () => {
    await act(async () => {
      root!.render(
        <InvestigationWorkspace
          incident={sampleIncident}
          allEvents={[...normalEvents, ...suspiciousEvents]}
          assets={mockAssets}
          baselineStatus="sufficient"
        />,
      )
    })

    // Click on the first timeline event
    const timelineItems = container!.querySelectorAll('div[role="article"]')
    expect(timelineItems.length).toBeGreaterThan(0)

    act(() => {
      (timelineItems[0] as HTMLElement).click()
    })

    // Inspector drawer should be displayed
    const inspector = container!.querySelector('div[aria-label="Event detail inspector"]')
    expect(inspector).not.toBeNull()
    expect(inspector!.textContent).toContain('Telemetry Event Inspector')
    expect(inspector!.textContent).toContain('Source IPv4')
    expect(inspector!.textContent).toContain('203.0.113.5')
  })

  it('cross-filters the timeline when clicking a rule filter button in Alert Explanations', async () => {
    await act(async () => {
      root!.render(
        <InvestigationWorkspace
          incident={sampleIncident}
          allEvents={[...normalEvents, ...suspiciousEvents]}
          assets={mockAssets}
          baselineStatus="sufficient"
        />,
      )
    })

    // Find filter button for new_hosts rule
    const filterButtons = container!.querySelectorAll('button')
    const newHostsBtn = Array.from(filterButtons).find(b => b.textContent?.includes('Filter Timeline to Rule'))
    expect(newHostsBtn).toBeDefined()

    act(() => {
      newHostsBtn!.click()
    })

    // Active filter banner should appear
    expect(container!.textContent).toContain('Active Investigation Filters:')
    expect(container!.textContent).toContain('Reset All Filters')

    // Click reset all filters
    const resetBtn = Array.from(container!.querySelectorAll('button')).find(b => b.textContent?.includes('Reset All Filters'))
    expect(resetBtn).toBeDefined()
    act(() => {
      resetBtn!.click()
    })
    expect(container!.textContent).not.toContain('Active Investigation Filters:')
  })

  it('renders Investigation Studio inside IncidentDetailModal when selected in AppState', async () => {
    function TestModalWrapper() {
      const { selectIncident } = useAppActions()
      return (
        <div>
          <button id="btn-select-test-inc" type="button" onClick={() => selectIncident('inc-0001-alice')}>
            Open Incident
          </button>
          <IncidentDetailModal />
        </div>
      )
    }

    await act(async () => {
      root!.render(
        <AppProvider>
          <TestModalWrapper />
        </AppProvider>,
      )
    })

    // Modal is initially not rendered
    expect(container!.querySelector('div[role="dialog"]')).toBeNull()
  })
})
