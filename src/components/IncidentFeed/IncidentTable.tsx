/**
 * IncidentTable — Mission 72
 *
 * Full-featured incident table displaying:
 * - Severity badge
 * - Risk score [0-100] with score meter
 * - Primary username
 * - Time range (start - end UTC)
 * - Triggered rules (with count & tags)
 * - Evidence event count
 * - Recommended triage action snippet
 * - Acknowledged status & toggle
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

export function IncidentTable({ incidents }: IncidentTableProps) {
  const { state } = useAppState()
  const { acknowledgedIds, selectedIncidentId } = state
  const { selectIncident, acknowledgeIncident, unacknowledgeIncident } = useAppActions()

  if (incidents.length === 0) {
    return (
      <div className={styles.emptyContainer} id="incident-table-empty">
        <svg className={styles.emptyIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.5" />
          <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
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
            <th scope="col" className={styles.thRisk}>Risk</th>
            <th scope="col" className={styles.thUser}>Account / User</th>
            <th scope="col" className={styles.thRules}>Triggered Rules</th>
            <th scope="col" className={styles.thTime}>Time Range (UTC)</th>
            <th scope="col" className={styles.thEvents}>Events</th>
            <th scope="col" className={styles.thTriage}>Recommended Triage</th>
            <th scope="col" className={styles.thStatus}>Status</th>
            <th scope="col" className={styles.thActions}>Action</th>
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

            return (
              <tr
                key={incident.id}
                className={`${styles.row} ${isAck ? styles.acknowledgedRow : ''} ${
                  isSelected ? styles.selectedRow : ''
                }`}
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
                  <SeverityBadge severity={incident.severity} />
                </td>

                {/* Risk Score */}
                <td className={styles.cellRisk}>
                  <div className={styles.riskContainer}>
                    <span className={styles.riskNumber} style={{ color: riskColor }}>
                      {incident.riskScore}
                    </span>
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

                {/* Username */}
                <td className={styles.cellUser}>
                  <span className={styles.username}>{incident.username}</span>
                  <span className={styles.incidentId}>{incident.id}</span>
                </td>

                {/* Triggered Rules */}
                <td className={styles.cellRules}>
                  <div className={styles.ruleBadges}>
                    {distinctRules.map(ruleName => (
                      <span key={ruleName} className={styles.ruleBadge} title={ruleName}>
                        {ruleName}
                      </span>
                    ))}
                  </div>
                </td>

                {/* Time Range */}
                <td className={styles.cellTime}>
                  <span className={styles.timeText}>
                    {formatUtcRange(incident.startTimestamp, incident.endTimestamp)}
                  </span>
                </td>

                {/* Event Count */}
                <td className={styles.cellEvents}>
                  <span className={styles.eventCountBadge} title={`${totalEvents} total evidence events`}>
                    {totalEvents}
                  </span>
                </td>

                {/* Recommended Triage snippet */}
                <td className={styles.cellTriage}>
                  <span className={styles.triageText} title={incident.recommendedTriage}>
                    {incident.recommendedTriage}
                  </span>
                </td>

                {/* Status / Acknowledged */}
                <td className={styles.cellStatus}>
                  {isAck ? (
                    <span className={styles.ackBadge}>Acknowledged</span>
                  ) : (
                    <span className={styles.activeBadge}>Active</span>
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
