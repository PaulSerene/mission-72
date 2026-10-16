/**
 * TopNav — SignalForge application shell navigation bar.
 *
 * Displays brand identity, engine status, UTC clock, and theme toggle.
 */

import { useEffect, useState } from 'react'
import type { EngineStatus } from '@/types'
import { useTheme } from '@/hooks/useTheme'
import styles from './TopNav.module.css'

interface TopNavProps {
  engineStatus?: EngineStatus
}

const STATUS_LABELS: Record<EngineStatus, string> = {
  idle:    'STANDBY',
  running: 'ANALYZING',
  paused:  'PAUSED',
  error:   'ERROR',
}

const STATUS_DESC: Record<EngineStatus, string> = {
  idle:    'Engine ready for log ingestion',
  running: 'Processing security events & correlation',
  paused:  'Log stream analysis paused',
  error:   'Pipeline analysis encountered an error',
}

export function TopNav({ engineStatus = 'idle' }: TopNavProps) {
  const [clock, setClock] = useState(() => new Date().toISOString())
  const { theme, toggleTheme } = useTheme()

  useEffect(() => {
    const id = setInterval(() => setClock(new Date().toISOString()), 1000)
    return () => clearInterval(id)
  }, [])

  const isLive = engineStatus === 'running'
  const clockDisplay = clock.replace('T', ' ').slice(0, 19)

  return (
    <header className={styles.nav} role="banner">
      {/* Brand & Wordmark */}
      <div className={styles.brand}>
        <div className={styles.logoMark} aria-hidden="true">
          <svg viewBox="0 0 32 32" fill="none" className={styles.logoSvg}>
            <defs>
              <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#60a5fa" />
                <stop offset="100%" stopColor="#2563eb" />
              </linearGradient>
            </defs>
            <path
              d="M16 3L5 7v10c0 7.5 4.7 12.3 11 14 6.3-1.7 11-6.5 11-14V7L16 3z"
              stroke="url(#shieldGrad)"
              strokeWidth="2"
              fill="rgba(37, 99, 235, 0.12)"
              strokeLinejoin="round"
            />
            <path
              d="M16 8v16M8 16h16"
              stroke="#60a5fa"
              strokeWidth="1.2"
              strokeDasharray="2 3"
              opacity="0.6"
            />
            <circle cx="16" cy="16" r="3.5" fill="#60a5fa" />
            <circle cx="16" cy="16" r="7" stroke="#60a5fa" strokeWidth="1" opacity="0.4" />
          </svg>
        </div>

        <div className={styles.brandText}>
          <div className={styles.brandRow}>
            <span className={styles.brandName}>
              Signal<span className={styles.brandAccent}>Forge</span>
            </span>
            <span className={styles.brandTag}>SOC PLATFORM</span>
          </div>
          <span className={styles.brandTagline}>From raw logs to clear action</span>
        </div>
      </div>

      {/* Center Environment Badge */}
      <div className={styles.centerMeta}>
        <span className={styles.envPill}>
          <span className={styles.envDot} />
          <span>MISSION 72 TELEMETRY</span>
        </span>
      </div>

      {/* Right Controls */}
      <div className={styles.controls}>
        {/* Engine status pill */}
        <div
          className={`${styles.statusPill} ${styles[engineStatus]}`}
          role="status"
          aria-label={`${STATUS_DESC[engineStatus]}: ${STATUS_LABELS[engineStatus]}`}
          title={STATUS_DESC[engineStatus]}
        >
          <span className={`${styles.dot} ${isLive ? styles.pulseDot : ''}`} aria-hidden="true" />
          <span className={styles.statusLabel}>{STATUS_LABELS[engineStatus]}</span>
        </div>

        {/* UTC clock */}
        <time
          className={styles.clock}
          dateTime={clock}
          aria-label={`Current UTC time: ${clockDisplay}`}
        >
          <svg className={styles.clockIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.75" />
            <path d="M12 7v5l3 2" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
          </svg>
          <span className={styles.clockText}>{clockDisplay}</span>
          <span className={styles.clockUtc}>UTC</span>
        </time>

        {/* Theme toggle */}
        <button
          type="button"
          className={styles.themeToggle}
          onClick={toggleTheme}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          id="btn-theme-toggle"
        >
          {theme === 'dark' ? (
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" className={styles.themeIcon}>
              <circle cx="12" cy="12" r="4.5" stroke="currentColor" strokeWidth="1.75" />
              <path
                d="M12 2v2.5M12 19.5V22M4.22 4.22l1.77 1.77M18.01 18.01l1.77 1.77M2 12h2.5M19.5 12H22M4.22 19.78l1.77-1.77M18.01 5.99l1.77-1.77"
                stroke="currentColor"
                strokeWidth="1.75"
                strokeLinecap="round"
              />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" className={styles.themeIcon}>
              <path
                d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
                stroke="currentColor"
                strokeWidth="1.75"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          )}
        </button>
      </div>
    </header>
  )
}
