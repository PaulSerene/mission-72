/**
 * IncidentTable — SignalForge Security Operations
 *
 * Full-featured SOC incident investigation table:
 * - Severity badge with pulse indicator
 * - Risk score [0-100] with score meter & gradient
 * - User avatar bubble & account details
 * - Time range (start - end UTC)
 * - Triggered rules with MITRE badges
 * - Evidence event count
 * - Actionable triage snippet
 * - Acknowledged status toggle
 * - Row selection to open IncidentDetailModal
 */

import type { Incident } from '@/types'
import { SeverityBadge } from '@/components/SeverityBadge'
import { useAppState, useAppActions } from '@/state/AppState'
import styles from './IncidentTable.module.css'

interface IncidentTableProps {
  incidents: Incident[]
}

function formatUtcRange(start: string, end: string): string {
  const s = new Date(start)
  const e = new Date(end)
  const pad = (n: number) => String(n).padStart(2, '0')
  const timeStr = (d: Date) =>
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`
  const dateStr = `${s.getUTCFullYear()}-${pad(s.getUTCMonth() + 1)}-${pad(s.getUTCDate())}`

  if (s.toDateString() === e.toDateString()) {
    return `${dateStr} ${timeStr(s)} → ${timeStr(e)} UTC`
  }
  return `${s.toISOString().slice(0, 16)} → ${e.toISOString().slice(0, 16)} UTC`
}

function getRiskColor(score: number): string {
  if (score >= 85) return 'var(--color-critical)'
  if (score >= 65) return 'var(--color-high)'
  if (score >= 40) return 'var(--color-medium)'
  return 'var(--color-low)'
}

function getUserInitials(username: string): string {
  if (!username) return '?'
  const parts = username.replace(/[^a-zA-Z0-9]/g, ' ').trim().split(/\s+/)
  if (parts.length > 1) {
    return (parts[0][0] + parts[1][0]).toUpperCase()
  }
  return username.slice(0, 2).toUpperCase()
}

export function IncidentTable({ incidents }: IncidentTableProps) {
  const { state } = useAppState()
  const { acknowledgedIds, selectedIncidentId } = state
  const { selectIncident, acknowledgeIncident, unacknowledgeIncident } = useAppActions()

  if (incidents.length === 0) {
    return (
      <div className={styles.emptyContainer} id="incident-table-empty">
        <div className={styles.emptyIconRing} aria-hidden="true">
          <svg className={styles.emptyIcon} viewBox="0 0 24 24" fill="none">
            <path
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              stroke="currentColor"
              strokeWidth="1.75"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
        <p className={styles.emptyTitle}>No incidents match the active filters</p>
        <p className={styles.emptyDesc}>Try adjusting the severity, rule, or username filters above.</p>
      </div>
    )
  }

  return (
    <div className={styles.tableWrapper}>
      <table className={styles.table} aria-label="Detected security incidents">
        <thead>
          <tr>
            <th scope="col" className={styles.thSeverity}>Severity</th>
            <th scope="col" className={styles.thRisk}>Risk Score</th>
            <th scope="col" className={styles.thUser}>Account / Identity</th>
            <th scope="col" className={styles.thRules}>Triggered Rules</th>
            <th scope="col" className={styles.thTime}>Timeline (UTC)</th>
            <th scope="col" className={styles.thEvents}>Evidence</th>
            <th scope="col" className={styles.thTriage}>Triage Action</th>
            <th scope="col" className={styles.thStatus}>Status</th>
            <th scope="col" className={styles.thActions}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => {
            const isAck = acknowledgedIds.has(incident.id)
            const isSelected = selectedIncidentId === incident.id
            const totalEvents = incident.ruleMatches.reduce(
              (sum, m) => sum + m.evidence.eventIds.length,
              0
            )
            const distinctRules = Array.from(
              new Set(incident.ruleMatches.map(m => m.ruleName))
            )
            const riskColor = getRiskColor(incident.riskScore)
            const initials = getUserInitials(incident.username)

            return (
              <tr
                key={incident.id}
                className={`${styles.row} ${styles[`sev_${incident.severity}`]} ${
                  isAck ? styles.acknowledgedRow : ''
                } ${isSelected ? styles.selectedRow : ''}`}
                onClick={() => selectIncident(incident.id)}
                tabIndex={0}
                onKeyDown={e => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    selectIncident(incident.id)
                  }
                }}
                aria-label={`Incident ${incident.id} for ${incident.username}`}
              >
                {/* Severity */}
                <td className={styles.cellSeverity}>
                  <div className={styles.severityWrapper}>
                    <SeverityBadge severity={incident.severity} />
                  </div>
                </td>

                {/* Risk Score */}
                <td className={styles.cellRisk}>
                  <div className={styles.riskContainer}>
                    <div className={styles.riskHeader}>
                      <span className={styles.riskNumber} style={{ color: riskColor }}>
                        {incident.riskScore}
                      </span>
                      <span className={styles.riskMax}>/ 100</span>
                    </div>
                    <div className={styles.riskBarTrack} aria-hidden="true">
                      <div
                        className={styles.riskBarFill}
                        style={{
                          width: `${Math.min(incident.riskScore, 100)}%`,
                          backgroundColor: riskColor,
                        }}
                      />
                    </div>
                  </div>
                </td>

                {/* Account / Identity */}
                <td className={styles.cellUser}>
                  <div className={styles.userCard}>
                    <div className={styles.userAvatar} aria-hidden="true">
                      {initials}
                    </div>
                    <div className={styles.userMeta}>
                      <span className={styles.username}>{incident.username}</span>
                      <span className={styles.incidentId}>{incident.id}</span>
                    </div>
                  </div>
                </td>

                {/* Triggered Rules */}
                <td className={styles.cellRules}>
                  <div className={styles.ruleBadges}>
                    {distinctRules.map(ruleName => (
                      <span key={ruleName} className={styles.ruleBadge} title={ruleName}>
                        <span className={styles.ruleBadgeDot} />
                        {ruleName}
                      </span>
                    ))}
                  </div>
                </td>

                {/* Time Range */}
                <td className={styles.cellTime}>
                  <div className={styles.timeWrapper}>
                    <svg className={styles.timeIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.5" />
                      <path d="M12 7v5l3 2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                    </svg>
                    <span className={styles.timeText}>
                      {formatUtcRange(incident.startTimestamp, incident.endTimestamp)}
                    </span>
                  </div>
                </td>

                {/* Evidence Events Count */}
                <td className={styles.cellEvents}>
                  <span className={styles.eventCountBadge} title={`${totalEvents} total evidence events`}>
                    <svg className={styles.eventIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path d="M4 6h16M4 12h16M4 18h10" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
                    </svg>
                    {totalEvents}
                  </span>
                </td>

                {/* Recommended Triage snippet */}
                <td className={styles.cellTriage}>
                  <div className={styles.triageCallout} title={incident.recommendedTriage}>
                    <span className={styles.triageIcon} aria-hidden="true">⚡</span>
                    <span className={styles.triageText}>
                      {incident.recommendedTriage}
                    </span>
                  </div>
                </td>

                {/* Status / Acknowledged */}
                <td className={styles.cellStatus}>
                  {isAck ? (
                    <span className={styles.ackBadge}>
                      <svg viewBox="0 0 24 24" fill="none" width="12" height="12" aria-hidden="true">
                        <path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                      ACK
                    </span>
                  ) : (
                    <span className={styles.activeBadge}>
                      <span className={styles.activeDot} />
                      ACTIVE
                    </span>
                  )}
                </td>

                {/* Actions */}
                <td
                  className={styles.cellActions}
                  onClick={e => e.stopPropagation() /* Prevent row select */}
                >
                  <div className={styles.actionButtonGroup}>
                    <button
                      type="button"
                      className={styles.inspectBtn}
                      onClick={() => selectIncident(incident.id)}
                      title="Inspect incident details"
                      aria-label={`Inspect incident ${incident.id}`}
                    >
                      <svg viewBox="0 0 24 24" fill="none" width="13" height="13" aria-hidden="true">
                        <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="2" />
                        <path d="M20 20l-4-4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                      </svg>
                      Inspect
                    </button>
                    {isAck ? (
                      <button
                        type="button"
                        className={styles.unackBtn}
                        onClick={() => unacknowledgeIncident(incident.id)}
                        title="Reopen incident"
                        aria-label={`Reopen incident ${incident.id}`}
                      >
                        Reopen
                      </button>
                    ) : (
                      <button
                        type="button"
                        className={styles.ackBtn}
                        onClick={() => acknowledgeIncident(incident.id)}
                        title="Acknowledge incident"
                        aria-label={`Acknowledge incident ${incident.id}`}
                      >
                        Ack
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
