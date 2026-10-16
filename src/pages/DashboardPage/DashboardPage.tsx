/**
 * DashboardPage — SignalForge: Context-Aware Security Log Analysis
 *
 * Main SOC investigation workspace:
 * - Real-time statistics from actual pipeline results
 * - Data loading (CSV upload, synthetic demo, timezone & config)
 * - Ingestion diagnostics and data quality reports
 * - Interactive incident feed with filters + sorting
 * - Detailed incident investigation modal with evidence events
 * - Visualizations: severity breakdown, timeline, top accounts, rules, 24h activity
 * - Context exception audit log, export bar
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
    suppressedAlerts,
    ingestionReport,
    insufficientBaselineUsers,
    acknowledgedIds,
    lastAnalysisAt,
    dataSourceLabel,
  } = state

  const hasData = incidents.length > 0 || events.length > 0
  const isLoading = status === 'parsing' || status === 'analyzing'
  const effectiveTab = activeTab === 'load' && hasData ? 'feed' : activeTab

  const engineStatus: EngineStatus = isLoading
    ? 'running'
    : status === 'error'
    ? 'error'
    : 'idle'

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
        {/* ── Error Banner ─────────────────────────────────────────── */}
        {errorMessage && (
          <div className={styles.errorBanner} role="alert">
            <svg className={styles.errorIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path
                d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"
                stroke="currentColor"
                strokeWidth="1.75"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <div className={styles.errorText}>
              <strong>Analysis Error:</strong> {errorMessage}
            </div>
            <button
              type="button"
              className={styles.dismissErrorBtn}
              onClick={() => dispatch({ type: 'SET_ERROR', message: '' })}
              aria-label="Dismiss error banner"
            >
              <svg viewBox="0 0 24 24" fill="none" width="14" height="14" aria-hidden="true">
                <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              </svg>
            </button>
          </div>
        )}

        {/* ── Page Header ──────────────────────────────────────────── */}
        <section className={styles.pageHeader} aria-label="Dashboard header">
          <div className={styles.pageHeaderLeft}>
            <div className={styles.breadcrumbBadge}>
              <span className={styles.breadcrumbDot} />
              <span>SOC WORKSPACE / THREAT INVESTIGATION</span>
            </div>
            <h1 className={styles.pageTitle}>Security Operations</h1>
            <p className={styles.pageSubtitle}>
              Context-aware suspicious login &amp; lateral movement analysis
              {dataSourceLabel && (
                <span className={styles.sourceLabel}>
                  <span className={styles.sourceDot} aria-hidden="true">·</span>
                  {dataSourceLabel}
                </span>
              )}
            </p>
          </div>

          <div className={styles.headerActions}>
            <button
              id="btn-load-logs"
              className={`${styles.btn} ${styles.btnSecondary} ${showLoadPanel ? styles.btnActive : ''}`}
              type="button"
              onClick={() => {
                setShowLoadPanel(prev => !prev)
                if (!showLoadPanel) setActiveTab('load')
              }}
              disabled={isLoading}
            >
              <svg className={styles.btnIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path
                  d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"
                  stroke="currentColor"
                  strokeWidth="1.75"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              {showLoadPanel ? 'Hide Import' : 'Import Logs'}
            </button>

            <button
              id="btn-header-demo"
              className={`${styles.btn} ${styles.btnPrimary}`}
              type="button"
              onClick={handleQuickDemo}
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <span className={styles.loadingSpinnerInline} aria-hidden="true" />
                  Processing…
                </>
              ) : (
                <>
                  <svg className={styles.btnIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <polygon points="5 3 19 12 5 21 5 3" fill="currentColor" />
                  </svg>
                  Load Demo
                </>
              )}
            </button>
          </div>
        </section>

        {/* ── Differentiated Stat Cards ─────────────────────────────── */}
        <section className={styles.statsGrid} aria-label="Summary statistics">
          <StatCard
            id="stat-events"
            label="Events Processed"
            value={hasData ? eventsCount.toLocaleString() : '—'}
            variant="default"
            subtext={hasData ? 'Normalized telemetry logs' : 'Awaiting data'}
            icon={
              <svg viewBox="0 0 24 24" fill="none">
                <ellipse cx="12" cy="5" rx="9" ry="3" stroke="currentColor" strokeWidth="1.75" />
                <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" stroke="currentColor" strokeWidth="1.75" />
                <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" stroke="currentColor" strokeWidth="1.75" />
              </svg>
            }
          />
          <StatCard
            id="stat-incidents"
            label={`Incidents${hasData ? ` · ${unacknowledgedCount} Active` : ''}`}
            value={hasData ? incidents.length : '—'}
            variant="accent"
            subtext={hasData ? `${unacknowledgedCount} to triage` : 'Awaiting data'}
            icon={
              <svg viewBox="0 0 24 24" fill="none">
                <path
                  d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
                  stroke="currentColor"
                  strokeWidth="1.75"
                  strokeLinejoin="round"
                />
              </svg>
            }
          />
          <StatCard
            id="stat-critical"
            label="Critical"
            value={hasData ? criticalCount : '—'}
            variant="critical"
            subtext={hasData && criticalCount > 0 ? 'Immediate containment required' : 'No critical breaches'}
            icon={
              <svg viewBox="0 0 24 24" fill="none">
                <path
                  d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"
                  stroke="currentColor"
                  strokeWidth="1.75"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            }
          />
          <StatCard
            id="stat-high"
            label="High Severity"
            value={hasData ? highCount : '—'}
            variant="high"
            subtext={hasData && highCount > 0 ? 'Priority review' : 'No high anomalies'}
            icon={
              <svg viewBox="0 0 24 24" fill="none">
                <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.75" />
                <path d="M12 8v4m0 4h.01" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
              </svg>
            }
          />
          <StatCard
            id="stat-rules"
            label="Rule Matches"
            value={hasData ? ruleMatches.length : '—'}
            variant="medium"
            subtext={hasData ? 'Heuristic detections' : 'Awaiting data'}
            icon={
              <svg viewBox="0 0 24 24" fill="none">
                <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.75" />
                <path d="M12 2v3m0 14v3M2 12h3m14 0h3" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
              </svg>
            }
          />
          <StatCard
            id="stat-issues"
            label="Data Quality Issues"
            value={hasData ? issuesCount : '—'}
            variant={issuesCount > 0 ? 'medium' : 'low'}
            subtext={hasData ? (issuesCount > 0 ? `${issuesCount} dropped / duplicate rows` : 'Clean data stream') : 'Awaiting data'}
            icon={
              <svg viewBox="0 0 24 24" fill="none">
                <path d="M22 11.08V12a10 10 0 11-5.93-9.14" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
                <path d="M22 4L12 14.01l-3-3" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            }
          />
        </section>

        {/* ── Export & Session Bar ─────────────────────────────────── */}
        {hasData && <ExportBar />}

        {/* ── Collapsible Import Panel ─────────────────────────────── */}
        {hasData && showLoadPanel && (
          <section className={styles.loadSection} aria-label="Log file import">
            <LoadDataPanel />
          </section>
        )}

        {/* ── Onboarding / Empty State ─────────────────────────────── */}
        {!hasData && !isLoading && (
          <div className={styles.onboardingCard}>
            <div className={styles.onboardingHero}>
              <div className={styles.onboardingIconRing} aria-hidden="true">
                <svg viewBox="0 0 48 48" fill="none" className={styles.onboardingIconSvg}>
                  <defs>
                    <linearGradient id="heroGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stopColor="#60a5fa" />
                      <stop offset="100%" stopColor="#2563eb" />
                    </linearGradient>
                  </defs>
                  <path
                    d="M10 13L24 7L38 13V27C38 35.5 31.5 42.5 24 44.5C16.5 42.5 10 35.5 10 27V13Z"
                    stroke="url(#heroGrad)"
                    strokeWidth="2.5"
                    strokeLinejoin="round"
                    fill="rgba(37, 99, 235, 0.08)"
                  />
                  <path
                    d="M17 24L21.5 28.5L31 19"
                    stroke="#60a5fa"
                    strokeWidth="2.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>
              <div className={styles.onboardingHeroText}>
                <div className={styles.onboardingBadge}>RAPID SOC DEPLOYMENT</div>
                <h2 className={styles.onboardingTitle}>Welcome to SignalForge</h2>
                <p className={styles.onboardingSubtitle}>
                  Context-aware security log analysis. Load authentication CSV logs to build
                  behavioral baselines, evaluate risk across six detection rules, and reduce false positives with maintenance window and VPN awareness.
                </p>
              </div>
            </div>

            <div className={styles.onboardingCtaGroup}>
              <button
                id="btn-onboarding-demo"
                type="button"
                className={styles.onboardingPrimaryBtn}
                onClick={handleQuickDemo}
              >
                <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" width="18" height="18">
                  <polygon points="5 3 19 12 5 21 5 3" fill="currentColor" />
                </svg>
                Load Synthetic Demo Dataset
                <span className={styles.demoBadge}>10 scenarios · 280 events</span>
              </button>
            </div>

            <div className={styles.onboardingGrid}>
              {[
                {
                  n: '1',
                  title: 'Import Authentication Logs',
                  desc: 'Load CSV logs with timestamps, users, source IPs, status, and destination hosts.',
                  tag: 'CSV INGESTION',
                },
                {
                  n: '2',
                  title: 'Behavioral Baselines',
                  desc: 'Engine builds user profiles: normal hours, known IPs, typical hosts, and CIDR matching.',
                  tag: 'PROFILING',
                },
                {
                  n: '3',
                  title: 'Multi-Rule Correlation',
                  desc: 'Evaluates brute force, password spray, impossible travel, unusual hours, and new hosts.',
                  tag: 'CORRELATION',
                },
                {
                  n: '4',
                  title: 'SOC Triage & Export',
                  desc: 'Investigate evidence events, acknowledge items, and export self-contained HTML reports.',
                  tag: 'CONTAINMENT',
                },
              ].map(step => (
                <div className={styles.stepCard} key={step.n}>
                  <div className={styles.stepHeader}>
                    <span className={styles.stepNumber} aria-hidden="true">{step.n}</span>
                    <span className={styles.stepTag}>{step.tag}</span>
                  </div>
                  <div>
                    <strong className={styles.stepTitle}>{step.title}</strong>
                    <p className={styles.stepDesc}>{step.desc}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className={styles.onboardingPanelWrapper}>
              <div className={styles.panelSectionTitle}>Or Ingest Custom Log Telemetry</div>
              <LoadDataPanel />
            </div>
          </div>
        )}

        {/* ── Active Investigation Workspace ───────────────────────── */}
        {hasData && (
          <div className={styles.workspace}>
            {/* Tab Navigation */}
            <nav className={styles.tabs} aria-label="Investigation views">
              <button
                id="tab-incidents"
                type="button"
                role="tab"
                aria-selected={effectiveTab === 'feed'}
                className={`${styles.tabBtn} ${effectiveTab === 'feed' ? styles.activeTab : ''}`}
                onClick={() => setActiveTab('feed')}
              >
                <svg viewBox="0 0 24 24" fill="none" className={styles.tabIcon} aria-hidden="true">
                  <path
                    d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
                    stroke="currentColor"
                    strokeWidth="1.75"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
                Incident Feed
                <span className={styles.tabBadge}>{filteredIncidents.length}</span>
              </button>

              <button
                id="tab-visualizations"
                type="button"
                role="tab"
                aria-selected={effectiveTab === 'visualizations'}
                className={`${styles.tabBtn} ${effectiveTab === 'visualizations' ? styles.activeTab : ''}`}
                onClick={() => setActiveTab('visualizations')}
              >
                <svg viewBox="0 0 24 24" fill="none" className={styles.tabIcon} aria-hidden="true">
                  <path d="M18 20V10M12 20V4M6 20v-6" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
                </svg>
                Analytics
              </button>

              <button
                id="tab-quality"
                type="button"
                role="tab"
                aria-selected={effectiveTab === 'quality'}
                className={`${styles.tabBtn} ${effectiveTab === 'quality' ? styles.activeTab : ''}`}
                onClick={() => setActiveTab('quality')}
              >
                <svg viewBox="0 0 24 24" fill="none" className={styles.tabIcon} aria-hidden="true">
                  <path
                    d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"
                    stroke="currentColor"
                    strokeWidth="1.75"
                    strokeLinejoin="round"
                  />
                </svg>
                Quality &amp; Config
                {issuesCount > 0 && (
                  <span className={styles.tabWarnBadge} title={`${issuesCount} data quality issue(s)`}>
                    {issuesCount}
                  </span>
                )}
              </button>
            </nav>

            {/* Tab 1: Incident Feed */}
            {effectiveTab === 'feed' && (
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
            {effectiveTab === 'visualizations' && (
              <section className={styles.sectionPadded} aria-label="Incident and activity analytics">
                <Visualizations
                  incidents={filteredIncidents}
                  events={events}
                  ruleMatches={ruleMatches}
                />
              </section>
            )}

            {/* Tab 3: Data Quality & Configuration */}
            {effectiveTab === 'quality' && (
              <div className={styles.qualityStack}>
                {ingestionReport && (
                  <section className={styles.sectionPadded} aria-label="Ingestion diagnostics">
                    <IngestionSummary
                      report={ingestionReport}
                      insufficientBaselineUsers={insufficientBaselineUsers}
                    />
                  </section>
                )}

                <section className={styles.sectionPadded} aria-label="Detection rules configuration">
                  <ConfigPanel />
                </section>

                <section className={styles.sectionPadded} aria-label="Context exception audit log">
                  <ContextExceptions suppressedAlerts={suppressedAlerts} />
                </section>
              </div>
            )}
          </div>
        )}
      </main>

      {/* ── Investigation Modal ─────────────────────────────────────── */}
      <IncidentDetailModal />

      {/* ── Footer ─────────────────────────────────────────────────── */}
      <footer className={styles.footer} role="contentinfo">
        <div className={styles.footerLeft}>
          <span className={styles.footerBrand}>SignalForge</span>
          <span className={styles.footerSep}>·</span>
          <span>Context-Aware Security Analysis Engine</span>
        </div>
        <div className={styles.footerRight}>
          {lastAnalysisAt && (
            <span>
              Last analysis:{' '}
              <time className={styles.footerMono} dateTime={lastAnalysisAt}>
                {lastAnalysisAt}
              </time>
            </span>
          )}
        </div>
      </footer>
    </div>
  )
}
