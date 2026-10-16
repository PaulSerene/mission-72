import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { AppProvider } from '@/state/AppState'
import DashboardPage from '@/pages/DashboardPage'
import { parseAuthCsv } from '@/engine/ingest'
import { runDetectionPipeline, createDefaultConfig } from '@/engine/pipeline'

const SAMPLE_CSV = `timestamp,username,source_ip,destination_host,event_type,status,location
2026-10-12T10:00:00+00:00Z,frank,203.0.113.88,db-prod-01,login,success,"Hyderabad, IN"
2026-10-12T10:03:00+00:00Z,frank,203.0.113.88,dc-primary,login,success,"Hyderabad, IN"
2026-10-12T10:06:00+00:00Z,frank,203.0.113.88,backup-vault-01,login,success,"Hyderabad, IN"
2026-10-12T10:09:00+00:00Z,frank,203.0.113.88,payroll-db-02,login,success,"Hyderabad, IN"
2026-10-12T10:12:00+00:00Z,frank,203.0.113.88,admin-console-01,login,success,"Hyderabad, IN"
2026-10-12T10:15:00+00:00Z,frank,203.0.113.88,build-runner-03,login,success,"Hyderabad, IN"
2026-10-13T03:00:00+00:00Z,diana,198.51.100.201,hr-system-01,login,success,"Frankfurt, DE"
`

describe('Custom CSV Analysis & Navigation Lifecycle Regressions', () => {
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

  it('exercises real CSV parser and pipeline on the exact custom CSV format', () => {
    const config = createDefaultConfig()
    const ingest = parseAuthCsv(SAMPLE_CSV, config)

    expect(ingest.events.length).toBe(7)
    expect(ingest.report.invalidRows.length).toBe(0)

    // Verify destination_host was resolved
    expect(ingest.events[0].destination).toBe('db-prod-01')
    expect(ingest.events[0].username).toBe('frank')
    expect(ingest.events[0].location).toBe('Hyderabad, IN')

    // Run real pipeline
    const pipelineResult = runDetectionPipeline({ authData: SAMPLE_CSV })
    expect(pipelineResult.events.length).toBe(7)
    expect(pipelineResult.ruleMatches.length).toBeGreaterThan(0)
    expect(pipelineResult.incidents.length).toBeGreaterThan(0)

    // Confirms unfamiliar hosts and unusual hours detections
    const frankIncidents = pipelineResult.incidents.filter(i => i.username === 'frank')
    expect(frankIncidents.length).toBeGreaterThan(0)
    expect(frankIncidents[0].ruleMatches.some(r => r.ruleId === 'new_hosts')).toBe(true)

    const dianaIncidents = pipelineResult.incidents.filter(i => i.username === 'diana')
    expect(dianaIncidents.length).toBeGreaterThan(0)
    expect(dianaIncidents[0].ruleMatches.some(r => r.ruleId === 'unusual_hours')).toBe(true)
  })

  it('selecting a valid custom CSV enables Run Analysis button', async () => {
    await act(async () => {
      root!.render(
        <AppProvider>
          <DashboardPage />
        </AppProvider>
      )
    })

    // Before selection, Run Analysis button does not exist
    expect(container!.querySelector('#btn-run-analysis')).toBeNull()

    const authInput = container!.querySelector('#input-auth-csv') as HTMLInputElement
    expect(authInput).not.toBeNull()

    const mockFile = new File([SAMPLE_CSV], '04_unfamiliar_hosts_and_unusual_hours.csv', {
      type: 'text/csv',
    })

    Object.defineProperty(authInput, 'files', {
      value: [mockFile],
      writable: true,
    })

    act(() => {
      authInput.dispatchEvent(new Event('change', { bubbles: true }))
    })

    // Now Run Analysis button is enabled and visible
    const runBtn = container!.querySelector('#btn-run-analysis') as HTMLButtonElement
    expect(runBtn).not.toBeNull()
    expect(runBtn.disabled).toBe(false)
  })

  it('clicking Run Analysis executes pipeline and transitions to active investigation workspace without falling back to demo', async () => {
    await act(async () => {
      root!.render(
        <AppProvider>
          <DashboardPage />
        </AppProvider>
      )
    })

    const authInput = container!.querySelector('#input-auth-csv') as HTMLInputElement
    const mockFile = new File([SAMPLE_CSV], '04_unfamiliar_hosts_and_unusual_hours.csv', {
      type: 'text/csv',
    })

    Object.defineProperty(authInput, 'files', {
      value: [mockFile],
      writable: true,
    })

    act(() => {
      authInput.dispatchEvent(new Event('change', { bubbles: true }))
    })

    const runBtn = container!.querySelector('#btn-run-analysis') as HTMLButtonElement
    expect(runBtn).not.toBeNull()

    await act(async () => {
      runBtn.click()
      await new Promise(r => setTimeout(r, 100))
    })

    // App must NOT be on onboarding screen
    expect(container!.querySelector('#btn-onboarding-demo')).toBeNull()

    // App must be on active workspace with tabs
    const incidentsTab = container!.querySelector('#tab-incidents')
    expect(incidentsTab).not.toBeNull()

    // Data source label must show uploaded filename, NOT synthetic demo
    expect(container!.textContent).toContain('04_unfamiliar_hosts_and_unusual_hours.csv')
    expect(container!.textContent).not.toContain('Synthetic Demo Dataset')

    // Valid events count must reflect uploaded CSV (7 events)
    expect(container!.textContent).toContain('7')
    expect(container!.textContent).toContain('frank')
    expect(container!.textContent).toContain('diana')
  })

  it('invalid CSV with zero usable rows shows an actionable error and resets loading state', async () => {
    await act(async () => {
      root!.render(
        <AppProvider>
          <DashboardPage />
        </AppProvider>
      )
    })

    const authInput = container!.querySelector('#input-auth-csv') as HTMLInputElement
    const invalidCsv = `invalid_header_a,invalid_header_b\nfoo,bar\nbaz,qux\n`
    const mockFile = new File([invalidCsv], 'invalid_auth.csv', { type: 'text/csv' })

    Object.defineProperty(authInput, 'files', {
      value: [mockFile],
      writable: true,
    })

    act(() => {
      authInput.dispatchEvent(new Event('change', { bubbles: true }))
    })

    const runBtn = container!.querySelector('#btn-run-analysis') as HTMLButtonElement

    await act(async () => {
      runBtn.click()
      await new Promise(r => setTimeout(r, 100))
    })

    // Actionable error banner must be rendered
    const errorBanner = container!.querySelector('[role="alert"]')
    expect(errorBanner).not.toBeNull()
    expect(errorBanner!.textContent).toContain('No valid authentication events found in "invalid_auth.csv"')
    expect(errorBanner!.textContent).toContain('invalid row(s) detected')

    // Loading indicator is cleared, button is re-enabled for retry
    expect(container!.textContent).not.toContain('Parsing CSV…')
    expect(container!.textContent).not.toContain('Running detection pipeline…')
  })

  it('allows user to retry and succeed after a previous failure', async () => {
    await act(async () => {
      root!.render(
        <AppProvider>
          <DashboardPage />
        </AppProvider>
      )
    })

    const authInput = container!.querySelector('#input-auth-csv') as HTMLInputElement

    // 1. First run with invalid CSV
    const invalidFile = new File(['col1,col2\nval1,val2'], 'corrupted.csv', { type: 'text/csv' })
    Object.defineProperty(authInput, 'files', { value: [invalidFile], writable: true })
    act(() => {
      authInput.dispatchEvent(new Event('change', { bubbles: true }))
    })

    const runBtn = container!.querySelector('#btn-run-analysis') as HTMLButtonElement
    await act(async () => {
      runBtn.click()
      await new Promise(r => setTimeout(r, 100))
    })

    expect(container!.querySelector('[role="alert"]')).not.toBeNull()

    // 2. Retry with valid CSV
    const freshAuthInput = container!.querySelector('#input-auth-csv') as HTMLInputElement
    expect(freshAuthInput).not.toBeNull()

    const validFile = new File([SAMPLE_CSV], 'recovered.csv', { type: 'text/csv' })
    Object.defineProperty(freshAuthInput, 'files', { value: [validFile], writable: true })
    act(() => {
      freshAuthInput.dispatchEvent(new Event('change', { bubbles: true }))
    })

    const retryRunBtn = container!.querySelector('#btn-run-analysis') as HTMLButtonElement
    expect(retryRunBtn).not.toBeNull()
    await act(async () => {
      retryRunBtn.click()
      await new Promise(r => setTimeout(r, 100))
    })

    // Error banner is gone and dashboard is loaded with the recovered dataset
    expect(container!.querySelector('[role="alert"]')).toBeNull()
    expect(container!.querySelector('#tab-incidents')).not.toBeNull()
    expect(container!.textContent).toContain('recovered.csv')
  })
})
