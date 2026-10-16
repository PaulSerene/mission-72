/**
 * DashboardPage — Mission 72: Suspicious Login and Activity Detector
 *
 * Integrated cybersecurity operations center (SOC) dashboard:
 * - Engine status, UTC clock, and quick-action navigation
 * - Real-time statistics derived from actual pipeline results
 * - Data loading (CSV upload, synthetic demo dataset, timezone & config)
 * - Ingestion diagnostics and data quality reports
 * - Interactive incident feed with search, severity, rule, and risk filters + sorting
 * - Detailed incident investigation panel with normalized evidence events & triage
 * - Interactive visualizations (severity breakdown, timeline, top accounts, top rules, 24h activity)
 * - Baseline transparency and operational limitations disclaimers
 * - Self-contained HTML investigation report & CSV exports
 */

import { useState } from 'react'
import { TopNav } from '@/components/TopNav'
import { StatCard } from '@/components/StatCard'
import { LoadDataPanel } from '@/components/LoadDataPanel'
import { IngestionSummary } from '@/components/IngestionSummary'
import { IncidentFilterBar, IncidentTable } from '@/components/IncidentFeed'
import { IncidentDetailModal } from '@/components/IncidentDetail'
import { Visualizations } from '@/components/Visualizations'
import { ConfigPanel } from '@/components/ConfigPanel'
import { ContextExceptions } from '@/components/ContextExceptions'
import { ExportBar } from '@/components/ExportBar'
import { useAppState, useFilteredIncidents } from '@/state/AppState'
import { usePipeline } from '@/hooks/usePipeline'
import type { EngineStatus } from '@/types'
import styles from './DashboardPage.module.css'

type ActiveTab = 'feed' | 'visualizations' | 'quality' | 'load'

export default function DashboardPage() {
  const { state, dispatch } = useAppState()
  const filteredIncidents = useFilteredIncidents()
  const { loadDemoData } = usePipeline()

  const [activeTab, setActiveTab] = useState<ActiveTab>('feed')
  const [showLoadPanel, setShowLoadPanel] = useState(false)

  const {
    status,
    errorMessage,
    events,
    incidents,
    ruleMatches,
    ingestionReport,
    insufficientBaselineUsers,
    acknowledgedIds,
    lastAnalysisAt,
    dataSourceLabel,
  } = state

  const hasData = incidents.length > 0 || events.length > 0
  const isLoading = status === 'parsing' || status === 'analyzing'

  // Map app status to TopNav engine status
  const engineStatus: EngineStatus = isLoading
    ? 'running'
    : status === 'error'
    ? 'error'
    : 'idle'

  // Summary statistics derived from real pipeline results
  const eventsCount = ingestionReport ? ingestionReport.validEvents : events.length
  const criticalCount = incidents.filter(i => i.severity === 'critical').length
  const highCount = incidents.filter(i => i.severity === 'high').length
  const unacknowledgedCount = incidents.filter(i => !acknowledgedIds.has(i.id)).length
  const issuesCount = ingestionReport
    ? ingestionReport.invalidRows.length + ingestionReport.duplicateCount
    : 0

  async function handleQuickDemo() {
    await loadDemoData()
  }

  return (
    <div className={`${styles.page} scanline-bg`}>
      <TopNav engineStatus={engineStatus} />

      <main className={styles.main} id="main-content">
        {/* ── Error Banner ───────────────────────────────────────────── */}
        {errorMessage && (
          <div className={styles.errorBanner} role="alert">
            <span className={styles.errorIcon}>⚠</span>
            <div className={styles.errorText}>
              <strong>Analysis Error:</strong> {errorMessage}
            </div>
            <button
              type="button"
              className={styles.dismissErrorBtn}
              onClick={() => dispatch({ type: 'SET_ERROR', message: '' })}
              aria-label="Dismiss error banner"
            >
              ×
            </button>
          </div>
        )}

        {/* ── Page Header ───────────────────────────────────────────── */}
        <section className={styles.pageHeader} aria-label="Dashboard header">
          <div>
            <h1 className={styles.pageTitle}>Security Operations Dashboard</h1>
            <p className={styles.pageSubtitle}>
              Suspicious login, credential abuse & lateral movement detection — Mission 72
            </p>
          </div>

          <div className={styles.headerActions}>
            <button
              id="btn-load-logs"
              className={styles.btnPrimary}
              type="button"
              onClick={() => {
                setShowLoadPanel(prev => !prev)
                if (!showLoadPanel) setActiveTab('load')
              }}
              disabled={isLoading}
            >
              <svg className={styles.btnSvg} viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              {showLoadPanel ? 'Hide Import' : 'Import Logs'}
            </button>

            <button
              id="btn-header-demo"
              className={styles.btnAccent}
              type="button"
              onClick={handleQuickDemo}
              disabled={isLoading}
            >
              {isLoading ? 'Processing…' : 'Load Demo Data'}
            </button>
          </div>
        </section>

        {/* ── Stat Cards ────────────────────────────────────────────── */}
        <section className={styles.statsGrid} aria-label="Summary statistics">
          <StatCard
            id="stat-events"
            label="Valid Events Processed"
            value={hasData ? eventsCount.toLocaleString() : '—'}
            variant="default"
          />
          <StatCard
            id="stat-incidents"
            label={`Incidents (${hasData ? `${unacknowledgedCount} Active` : '—'})`}
            value={hasData ? incidents.length : '—'}
            variant="accent"
          />
          <StatCard
            id="stat-critical"
            label="Critical Incidents"
            value={hasData ? criticalCount : '—'}
            variant="critical"
          />
          <StatCard
            id="stat-high"
            label="High Severity"
            value={hasData ? highCount : '—'}
            variant="high"
          />
          <StatCard
            id="stat-rules"
            label="Rule Matches"
            value={hasData ? ruleMatches.length : '—'}
            variant="medium"
          />
          <StatCard
            id="stat-issues"
            label="Data Quality Issues"
            value={hasData ? issuesCount : '—'}
            variant={issuesCount > 0 ? 'medium' : 'low'}
          />
        </section>

        {/* ── Export & Session Bar ──────────────────────────────────── */}
        {hasData && <ExportBar />}

        {/* ── Collapsible Load Panel ────────────────────────────────── */}
        {(showLoadPanel || (!hasData && activeTab === 'load')) && (
          <section className={styles.loadSection} aria-label="Log file import">
            <LoadDataPanel />
          </section>
        )}

        {/* ── Initial Empty State / Onboarding (When No Data Loaded) ─── */}
        {!hasData && !isLoading && (
          <div className={styles.onboardingCard}>
            <div className={styles.onboardingHeader}>
              <div className={styles.onboardingIconWrapper}>
                <svg className={styles.onboardingIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V6L12 2z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
                  <path d="M12 8v4m0 4h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                </svg>
              </div>
              <div>
                <h2 className={styles.onboardingTitle}>Welcome to Mission 72 Detection Engine</h2>
                <p className={styles.onboardingSubtitle}>
                  Offline-first authentication anomaly and suspicious activity analyzer.
                  Load an authentication log CSV to construct behavioral baselines and evaluate multi-rule incidents.
                </p>
              </div>
            </div>

            <div className={styles.onboardingActions}>
              <button
                id="btn-onboarding-demo"
                type="button"
                className={styles.onboardingPrimaryBtn}
                onClick={handleQuickDemo}
              >
                ▶ Load Synthetic Demo Dataset (10 Attack Scenarios · 280 Events)
              </button>
            </div>

            <div className={styles.onboardingSteps}>
              <div className={styles.stepItem}>
                <span className={styles.stepNumber}>1</span>
                <div>
                  <strong>Import Authentication Logs</strong>
                  <p>Load CSV logs containing timestamps, users, source IPs, status, and destination hosts.</p>
                </div>
              </div>
              <div className={styles.stepItem}>
                <span className={styles.stepNumber}>2</span>
                <div>
                  <strong>Behavioral Baselines & Enrichment</strong>
                  <p>The engine builds user profiles (normal hours, known IPs, typical hosts) and matches CIDRs.</p>
                </div>
              </div>
              <div className={styles.stepItem}>
                <span className={styles.stepNumber}>3</span>
                <div>
                  <strong>Multi-Rule Correlation</strong>
                  <p>Evaluates brute force, password spray, impossible travel, unusual hours, and new hosts.</p>
                </div>
              </div>
              <div className={styles.stepItem}>
                <span className={styles.stepNumber}>4</span>
                <div>
                  <strong>SOC Triage & Export</strong>
                  <p>Investigate evidence events, acknowledge verified items, and export self-contained reports.</p>
                </div>
              </div>
            </div>

            {/* Display LoadDataPanel directly in onboarding */}
            <div className={styles.onboardingPanelWrapper}>
              <LoadDataPanel />
            </div>
          </div>
        )}

        {/* ── Active Investigation Workspace (When Data is Loaded) ──── */}
        {hasData && (
          <div className={styles.workspace}>
            {/* Navigation Tabs */}
            <nav className={styles.tabs} aria-label="Investigation views">
              <button
                id="tab-incidents"
                type="button"
                className={`${styles.tabBtn} ${activeTab === 'feed' ? styles.activeTab : ''}`}
                onClick={() => setActiveTab('feed')}
              >
                Incident Feed
                <span className={styles.tabBadge}>{filteredIncidents.length}</span>
              </button>
              <button
                id="tab-visualizations"
                type="button"
                className={`${styles.tabBtn} ${activeTab === 'visualizations' ? styles.activeTab : ''}`}
                onClick={() => setActiveTab('visualizations')}
              >
                Visualizations & Analytics
              </button>
              <button
                id="tab-quality"
                type="button"
                className={`${styles.tabBtn} ${activeTab === 'quality' ? styles.activeTab : ''}`}
                onClick={() => setActiveTab('quality')}
              >
                Data Quality & Config
                {issuesCount > 0 && <span className={styles.tabWarnBadge}>!</span>}
              </button>
            </nav>

            {/* Tab 1: Incident Feed */}
            {activeTab === 'feed' && (
              <section className={styles.section} aria-labelledby="incidents-heading">
                <header className={styles.sectionHeader}>
                  <div>
                    <h2 id="incidents-heading" className={styles.sectionTitle}>
                      Detected Security Incidents
                    </h2>
                    <span className={styles.sectionSubtitle}>
                      Correlated multi-event anomalies ranked by composite risk score [0–100]
                    </span>
                  </div>
                </header>

                <IncidentFilterBar
                  totalCount={incidents.length}
                  filteredCount={filteredIncidents.length}
                />

                <IncidentTable incidents={filteredIncidents} />
              </section>
            )}

            {/* Tab 2: Visualizations */}
            {activeTab === 'visualizations' && (
              <section className={styles.sectionPadded} aria-label="Incident and activity charts">
                <Visualizations
                  incidents={filteredIncidents}
                  events={events}
                  ruleMatches={ruleMatches}
                />
              </section>
            )}

            {/* Tab 3: Data Quality & Engine Configuration */}
            {activeTab === 'quality' && (
              <div className={styles.qualityView}>
                {ingestionReport && (
                  <IngestionSummary
                    report={ingestionReport}
                    insufficientBaselineUsers={insufficientBaselineUsers}
                  />
                )}
                <ContextExceptions
                  suppressedAlerts={state.suppressedAlerts ?? state.pipelineResult?.suppressedAlerts ?? []}
                />
                <ConfigPanel />
              </div>
            )}
          </div>
        )}

        {/* ── Incident Detail Modal ─────────────────────────────────── */}
        <IncidentDetailModal />
      </main>

      <footer className={styles.footer} role="contentinfo">
        <div className={styles.footerLeft}>
          <span>Mission 72 — Suspicious Login and Activity Detector</span>
          <span className={styles.footerSep}>•</span>
          <span>Offline SOC Analysis Engine</span>
        </div>
        <div className={styles.footerRight}>
          {dataSourceLabel && <span>Source: {dataSourceLabel}</span>}
          {lastAnalysisAt && (
            <span className={styles.footerMono}>
              Analyzed: {new Date(lastAnalysisAt).toISOString().slice(0, 19)}Z
            </span>
          )}
        </div>
      </footer>
    </div>
  )
}
