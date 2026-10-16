/**
 * Top-navigation bar for Mission 72.
 *
 * Displays the application identity, status indicator, and timestamp.
 */

import { useEffect, useState } from 'react'
import type { EngineStatus } from '@/types'
import styles from './TopNav.module.css'

interface TopNavProps {
  engineStatus?: EngineStatus
}

const STATUS_LABELS: Record<EngineStatus, string> = {
  idle:    'STANDBY',
  running: 'LIVE',
  paused:  'PAUSED',
  error:   'ERROR',
}

export function TopNav({ engineStatus = 'idle' }: TopNavProps) {
  const [clock, setClock] = useState(() => new Date().toISOString())

  useEffect(() => {
    const id = setInterval(() => setClock(new Date().toISOString()), 1000)
    return () => clearInterval(id)
  }, [])

  const isLive = engineStatus === 'running'

  return (
    <header className={styles.nav} role="banner">
      <div className={styles.brand}>
        {/* Shield icon inline SVG */}
        <svg
          className={styles.logo}
          viewBox="0 0 24 24"
          fill="none"
          aria-hidden="true"
          focusable="false"
        >
          <path
            d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V6L12 2z"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinejoin="round"
            fill="none"
          />
          <path
            d="M9 12l2 2 4-4"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
        <span className={styles.brandName}>
          MISSION<span className={styles.brandAccent}> 72</span>
        </span>
        <span className={styles.subtitle}>Suspicious Activity Detector</span>
      </div>

      <div className={styles.controls}>
        {/* Engine status pill */}
        <div
          className={`${styles.statusPill} ${styles[engineStatus]}`}
          aria-label={`Engine status: ${STATUS_LABELS[engineStatus]}`}
        >
          <span className={`${styles.dot} ${isLive ? styles.pulseDot : ''}`} />
          {STATUS_LABELS[engineStatus]}
        </div>

        {/* UTC clock */}
        <time
          className={styles.clock}
          dateTime={clock}
          aria-label="Current UTC time"
        >
          {clock.replace('T', ' ').slice(0, 19)} UTC
        </time>
      </div>
    </header>
  )
}
