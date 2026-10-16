/**
 * DashboardPage — Mission 72 landing shell.
 *
 * Currently shows a minimal SOC dashboard skeleton with:
 *  - TopNav with engine status
 *  - Summary stat cards (all zeroed — awaiting detection engine data)
 *  - Placeholder alert table section
 *  - "Getting Started" onboarding prompt
 *
 * Full detection features (log ingestion, live alerts, charts) will be
 * wired in subsequent milestones.
 */

import { TopNav } from '@/components/TopNav'
import { StatCard } from '@/components/StatCard'
import { SeverityBadge } from '@/components/SeverityBadge'
import styles from './DashboardPage.module.css'

// ─── Placeholder data (will be replaced by real engine output) ───────────────

const PLACEHOLDER_STATS = [
  { id: 'stat-events',      label: 'Events Processed', value: 0,   variant: 'default'  as const },
  { id: 'stat-alerts',      label: 'Active Alerts',    value: 0,   variant: 'accent'   as const },
  { id: 'stat-critical',    label: 'Critical',         value: 0,   variant: 'critical' as const },
  { id: 'stat-high',        label: 'High',             value: 0,   variant: 'high'     as const },
]

export default function DashboardPage() {
  return (
    <div className={`${styles.page} scanline-bg`}>
      <TopNav engineStatus="idle" />

      <main className={styles.main} id="main-content">
        {/* ── Page Header ─────────────────────────────────────────────── */}
        <section className={styles.pageHeader} aria-label="Dashboard header">
          <div>
            <h1 className={styles.pageTitle}>Security Operations Dashboard</h1>
            <p className={styles.pageSubtitle}>
              Real-time suspicious login and activity detection — Mission 72
            </p>
          </div>
          <div className={styles.headerActions}>
            <button
              id="btn-load-logs"
              className={styles.btnPrimary}
              type="button"
              disabled
              aria-disabled="true"
              title="Available in next milestone"
            >
              Load Logs
            </button>
          </div>
        </section>

        {/* ── Stat Cards ──────────────────────────────────────────────── */}
        <section
          className={styles.statsGrid}
          aria-label="Summary statistics"
        >
          {PLACEHOLDER_STATS.map((s) => (
            <StatCard key={s.id} {...s} />
          ))}
        </section>

        {/* ── Alert Feed (placeholder) ─────────────────────────────────── */}
        <section className={styles.section} aria-labelledby="alerts-heading">
          <header className={styles.sectionHeader}>
            <h2 id="alerts-heading" className={styles.sectionTitle}>
              Alert Feed
            </h2>
            <SeverityBadge severity="info" />
          </header>

          <div className={styles.emptyState} id="alerts-empty-state">
            <svg
              className={styles.emptyIcon}
              viewBox="0 0 24 24"
              fill="none"
              aria-hidden="true"
            >
              <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.5" />
              <path d="M12 8v4m0 4h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            <p className={styles.emptyTitle}>No alerts yet</p>
            <p className={styles.emptyDesc}>
              Load a log file or connect a live data source to start detection.
            </p>
          </div>
        </section>

        {/* ── Getting Started ──────────────────────────────────────────── */}
        <section className={styles.section} aria-labelledby="onboarding-heading">
          <header className={styles.sectionHeader}>
            <h2 id="onboarding-heading" className={styles.sectionTitle}>
              Getting Started
            </h2>
          </header>
          <ol className={styles.onboardingList}>
            {[
              { step: 1, text: 'Load a structured log file (JSON, CSV, or raw syslog).' },
              { step: 2, text: 'The detection engine analyses events against built-in rules.' },
              { step: 3, text: 'Review alerts sorted by severity in the Alert Feed.' },
              { step: 4, text: 'Acknowledge and annotate alerts to track investigation status.' },
            ].map(({ step, text }) => (
              <li key={step} className={styles.onboardingItem}>
                <span className={styles.onboardingStep}>{step}</span>
                <span>{text}</span>
              </li>
            ))}
          </ol>
        </section>
      </main>

      <footer className={styles.footer} role="contentinfo">
        <span>Mission 72 — Suspicious Activity Detector</span>
        <span className={styles.footerMono}>
          Hackathon build · {new Date().getUTCFullYear()}
        </span>
      </footer>
    </div>
  )
}
