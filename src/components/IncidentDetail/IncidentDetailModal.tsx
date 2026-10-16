/**
 * IncidentDetailModal — SignalForge Incident Investigation
 *
 * Full investigation panel for a selected incident:
 * - Incident header with ID, severity, risk score & qualitative interpretation
 * - Primary account, time range, event count
 * - Structured narrative explanation & behavioral observations
 * - Recommended triage steps
 * - Triggered rules with MITRE tactics & descriptions
 * - Normalized evidence events table (resolved against state.events)
 * - Clear limitation notice (anomaly != compromise)
 * - Acknowledge / unacknowledge action
 * - Close button + keyboard Escape listener
 */

import { useEffect, useMemo } from 'react'
import type { AuthEvent } from '@/types'
import { SeverityBadge } from '@/components/SeverityBadge'
import { useAppState, useAppActions } from '@/state/AppState'
import styles from './IncidentDetailModal.module.css'

function getRiskInterpretation(score: number): { label: string; text: string; color: string } {
  if (score >= 85) {
    return {
      label: 'CRITICAL SEVERITY',
      text: 'High-confidence multi-rule anomaly. Immediate triage and credential/session containment recommended.',
      color: 'var(--color-critical)',
    }
  }
  if (score >= 65) {
    return {
      label: 'HIGH SEVERITY',
      text: 'Significant deviation from established baseline or high-frequency failure pattern. Priority investigation required.',
      color: 'var(--color-high)',
    }
  }
  if (score >= 40) {
    return {
      label: 'MEDIUM SEVERITY',
      text: 'Notable anomaly signal. Review against business operations, travel requests, or authorized maintenance windows.',
      color: 'var(--color-medium)',
    }
  }
  return {
    label: 'LOW SEVERITY',
    text: 'Minor behavioral deviation or single-rule trigger. Monitor and correlate with secondary telemetry.',
    color: 'var(--color-low)',
  }
}

export function IncidentDetailModal() {
  const { state } = useAppState()
  const { selectedIncidentId, incidents, events, acknowledgedIds } = state
  const { selectIncident, acknowledgeIncident, unacknowledgeIncident } = useAppActions()

  const incident = useMemo(() => {
    if (!selectedIncidentId) return null
    return incidents.find(i => i.id === selectedIncidentId) ?? null
  }, [selectedIncidentId, incidents])

  // Lookup map for fast event resolution
  const eventMap = useMemo(() => {
    const map = new Map<string, AuthEvent>()
    for (const ev of events) {
      map.set(ev.id, ev)
    }
    return map
  }, [events])

  // Aggregate all unique evidence event IDs across rule matches
  const evidenceEvents = useMemo(() => {
    if (!incident) return []
    const allIds = new Set<string>()
    for (const rm of incident.ruleMatches) {
      for (const id of rm.evidence.eventIds) {
        allIds.add(id)
      }
    }
    const resolved: { id: string; event?: AuthEvent }[] = []
    for (const id of allIds) {
      resolved.push({ id, event: eventMap.get(id) })
    }
    // Sort chronologically by timestamp if available
    return resolved.sort((a, b) => {
      const timeA = a.event ? new Date(a.event.timestamp).getTime() : 0
      const timeB = b.event ? new Date(b.event.timestamp).getTime() : 0
      return timeA - timeB
    })
  }, [incident, eventMap])

  // Split narrative into summary and observations
  const { summaryText, observations } = useMemo(() => {
    if (!incident) return { summaryText: '', observations: [] }
    const expl = incident.explanation
    if (expl.includes('Observations:')) {
      const [sumPart, obsPart] = expl.split('Observations:')
      const obsList = obsPart
        .split(';')
        .map(s => s.trim())
        .filter(Boolean)
      return { summaryText: sumPart.trim(), observations: obsList }
    }
    return { summaryText: expl, observations: [] }
  }, [incident])

  // Close on Escape key
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        selectIncident(null)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [selectIncident])

  if (!incident) return null

  const isAck = acknowledgedIds.has(incident.id)
  const riskInfo = getRiskInterpretation(incident.riskScore)
  const totalEvents = incident.ruleMatches.reduce(
    (sum, m) => sum + m.evidence.eventIds.length,
    0
  )

  return (
    <div
      className={styles.backdrop}
      role="dialog"
      aria-modal="true"
      aria-labelledby="incident-detail-title"
      onClick={() => selectIncident(null)}
    >
      <div className={styles.modal} onClick={e => e.stopPropagation()}>
        {/* Modal Header */}
        <header className={styles.header}>
          <div className={styles.headerTop}>
            <div className={styles.headerBadges}>
              <SeverityBadge severity={incident.severity} />
              <span className={styles.incidentIdBadge}>{incident.id}</span>
              {isAck ? (
                <span className={styles.ackBadge}>ACKNOWLEDGED</span>
              ) : (
                <span className={styles.activePill}>ACTIVE INVESTIGATION</span>
              )}
            </div>
            <button
              id="btn-close-incident-detail"
              type="button"
              className={styles.closeBtn}
              onClick={() => selectIncident(null)}
              aria-label="Close investigation panel"
            >
              <svg viewBox="0 0 24 24" fill="none" width="16" height="16" aria-hidden="true">
                <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              </svg>
            </button>
          </div>

          <h2 id="incident-detail-title" className={styles.title}>
            Suspicious Activity on <span className={styles.userHighlight}>{incident.username}</span>
          </h2>

          <div className={styles.metaRow}>
            <span className={styles.metaItem}>
              <span className={styles.metaLabel}>TIMELINE START:</span> {new Date(incident.startTimestamp).toUTCString()}
            </span>
            <span className={styles.metaSep}>•</span>
            <span className={styles.metaItem}>
              <span className={styles.metaLabel}>TIMELINE END:</span> {new Date(incident.endTimestamp).toUTCString()}
            </span>
            <span className={styles.metaSep}>•</span>
            <span className={styles.metaItem}>
              <span className={styles.metaLabel}>EVIDENCE EVENTS:</span> {totalEvents}
            </span>
          </div>
        </header>

        {/* Modal Body */}
        <div className={styles.body}>
          {/* Risk Score Meter & Interpretation */}
          <section className={styles.riskCard}>
            <div className={styles.riskHeader}>
              <div className={styles.riskScoreGroup}>
                <span className={styles.riskScoreLabel}>COMPOSITE RISK SCORE</span>
                <span className={styles.riskScoreVal} style={{ color: riskInfo.color }}>
                  {incident.riskScore} <span className={styles.riskScoreMax}>/ 100</span>
                </span>
              </div>
              <span className={styles.riskTierBadge} style={{ color: riskInfo.color, borderColor: riskInfo.color }}>
                {riskInfo.label}
              </span>
            </div>
            <div className={styles.riskMeterTrack} aria-hidden="true">
              <div
                className={styles.riskMeterFill}
                style={{
                  width: `${Math.min(incident.riskScore, 100)}%`,
                  backgroundColor: riskInfo.color,
                }}
              />
            </div>
            <p className={styles.riskInterpretation}>{riskInfo.text}</p>
          </section>

          {/* Explanation & Structured Observations */}
          <section className={styles.section}>
            <h3 className={styles.sectionHeading}>Incident Narrative &amp; Findings</h3>
            <div className={styles.explanationBox}>
              <p className={styles.summaryParagraph}>{summaryText}</p>
              {observations.length > 0 && (
                <div className={styles.observationsContainer}>
                  <div className={styles.obsHeading}>Observed Telemetry Deviations:</div>
                  <ul className={styles.obsList}>
                    {observations.map((obs, idx) => (
                      <li key={idx} className={styles.obsItem}>
                        <span className={styles.obsBullet} />
                        <span>{obs}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </section>

          {/* Recommended Triage Steps */}
          <section className={styles.section}>
            <h3 className={styles.sectionHeading}>Recommended SOC Triage</h3>
            <div className={styles.triageBox}>
              <div className={styles.triageIconRing}>
                <svg className={styles.triageIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" strokeWidth="2" />
                </svg>
              </div>
              <p className={styles.triageTextContent}>{incident.recommendedTriage}</p>
            </div>
          </section>

          {/* Triggered Rule Matches */}
          <section className={styles.section}>
            <h3 className={styles.sectionHeading}>
              Triggered Detection Rules ({incident.ruleMatches.length})
            </h3>
            <div className={styles.ruleMatchesList}>
              {incident.ruleMatches.map((rm, idx) => (
                <div key={idx} className={styles.ruleMatchItem}>
                  <div className={styles.ruleMatchHeader}>
                    <span className={styles.ruleMatchName}>{rm.ruleName}</span>
                    <span className={styles.ruleMatchId}>[{rm.ruleId}]</span>
                    {rm.mitreTactic && (
                      <span className={styles.mitreTag}>{rm.mitreTactic}</span>
                    )}
                    {rm.contextSuppression && (
                      <span
                        className={styles.ctxSuppressionTag}
                        title={rm.contextSuppression.reason}
                      >
                        Context Adjusted ({Math.round(rm.contextSuppression.scoreMultiplier * 100)}% weight)
                      </span>
                    )}
                    <span className={styles.ruleEventCount}>
                      {rm.evidence.eventIds.length} event{rm.evidence.eventIds.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                  <p className={styles.ruleMatchDesc}>{rm.evidence.description}</p>
                  {rm.contextSuppression && (
                    <p className={styles.ctxSuppressionReason}>
                      ℹ {rm.contextSuppression.reason}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </section>

          {/* Normalized Evidence Events */}
          <section className={styles.section}>
            <h3 className={styles.sectionHeading}>
              Correlated Evidence Events ({evidenceEvents.length})
            </h3>
            {evidenceEvents.length === 0 ? (
              <p className={styles.noEventsText}>No event references found.</p>
            ) : (
              <div className={styles.eventsTableWrapper}>
                <table className={styles.eventsTable} aria-label="Evidence events">
                  <thead>
                    <tr>
                      <th scope="col">Timestamp (UTC)</th>
                      <th scope="col">Source IP</th>
                      <th scope="col">Location</th>
                      <th scope="col">Destination Host</th>
                      <th scope="col">Logon Type</th>
                      <th scope="col">Outcome</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evidenceEvents.map(({ id, event }) => {
                      if (!event) {
                        return (
                          <tr key={id}>
                            <td colSpan={6} className={styles.unresolvedEvent}>
                              Event ID: <code>{id}</code> (details not found in loaded events)
                            </td>
                          </tr>
                        )
                      }
                      return (
                        <tr key={id}>
                          <td className={styles.monoCell}>
                            {event.timestamp.replace('T', ' ').slice(0, 19)}
                          </td>
                          <td className={styles.monoCell}>
                            {event.sourceIp}
                          </td>
                          <td>
                            {event.location ? (
                              <span className={styles.geoTag}>{event.location}</span>
                            ) : (
                              '—'
                            )}
                          </td>
                          <td className={styles.monoCell}>
                            {event.destination || '—'}
                          </td>
                          <td>{event.logonType}</td>
                          <td>
                            <span
                              className={
                                event.outcome === 'success'
                                  ? styles.statusSuccess
                                  : styles.statusFailure
                              }
                            >
                              {event.outcome.toUpperCase()}
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {/* Operational Limitation Notice */}
          <div className={styles.limitationNotice}>
            <span className={styles.limitationIcon} aria-hidden="true">⚠</span>
            <div className={styles.limitationContent}>
              <strong>SOC Operational Disclaimer:</strong> Heuristic anomaly signal only.
              This detection identifies statistical and pattern-based deviations from baseline
              behavior. It is not conclusive proof of compromise. Legitimate administrative tasks,
              credential resets, VPN changes, or network changes can produce similar signals.
              Always verify against directory logs, endpoint telemetry, and user confirmation
              prior to initiating containment.
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <footer className={styles.footer}>
          <div className={styles.footerActions}>
            {isAck ? (
              <button
                type="button"
                className={styles.unackBtn}
                onClick={() => unacknowledgeIncident(incident.id)}
              >
                Reopen Incident
              </button>
            ) : (
              <button
                type="button"
                className={styles.ackBtn}
                onClick={() => acknowledgeIncident(incident.id)}
              >
                <svg viewBox="0 0 24 24" fill="none" width="14" height="14" aria-hidden="true">
                  <path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                Acknowledge Incident
              </button>
            )}
            <button
              type="button"
              className={styles.doneBtn}
              onClick={() => selectIncident(null)}
            >
              Done
            </button>
          </div>
        </footer>
      </div>
    </div>
  )
}
