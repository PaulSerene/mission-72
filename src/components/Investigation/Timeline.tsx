/**
 * Timeline — SignalForge Chronological Authentication Event Stream
 *
 * Chronological timeline of suspicious authentication events and related alerts.
 * - Safely handles valid, missing, or malformed timestamps
 * - Displays event type, account, source IP, destination host, outcome, and linked rules
 * - Interactive event selection with deep-dive inspection drawer
 * - Filter by outcome, host, and linked rule
 */

import { useState, useMemo } from 'react'
import type { AuthEvent, RuleMatch } from '@/types'
import { sortEventsChronologically, safeParseTime } from '@/engine/investigation'
import styles from './Investigation.module.css'

interface TimelineProps {
  events: AuthEvent[]
  ruleMatches: RuleMatch[]
  selectedEventId: string | null
  selectedHost: string | null
  selectedRuleId: string | null
  onSelectEvent: (eventId: string | null) => void
  onSelectRule?: (ruleId: string | null) => void
  onSelectHost?: (host: string | null) => void
}

export function Timeline({
  events,
  ruleMatches,
  selectedEventId,
  selectedHost,
  selectedRuleId,
  onSelectEvent,
  onSelectRule,
  onSelectHost,
}: TimelineProps) {
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc')
  const [outcomeFilter, setOutcomeFilter] = useState<'all' | 'failure' | 'success'>('all')

  // Map each event ID to the set of rules that flagged it
  const eventToRulesMap = useMemo(() => {
    const map = new Map<string, { id: string; name: string }[]>()
    for (const rm of ruleMatches) {
      for (const id of rm.evidence.eventIds) {
        const list = map.get(id) ?? []
        list.push({ id: rm.ruleId, name: rm.ruleName })
        map.set(id, list)
      }
    }
    return map
  }, [ruleMatches])

  // Apply filters
  const filteredEvents = useMemo(() => {
    let result = events

    if (outcomeFilter !== 'all') {
      result = result.filter(e => e.outcome === outcomeFilter)
    }

    if (selectedHost) {
      result = result.filter(
        e => (e.destination ?? '').toLowerCase() === selectedHost.toLowerCase(),
      )
    }

    if (selectedRuleId) {
      const matchEventIds = new Set<string>()
      for (const rm of ruleMatches) {
        if (rm.ruleId === selectedRuleId) {
          for (const id of rm.evidence.eventIds) matchEventIds.add(id)
        }
      }
      result = result.filter(e => matchEventIds.has(e.id))
    }

    return sortEventsChronologically(result, sortOrder)
  }, [events, outcomeFilter, selectedHost, selectedRuleId, sortOrder, ruleMatches])

  // Selected event for detail drawer
  const selectedEvent = useMemo(() => {
    if (!selectedEventId) return null
    return events.find(e => e.id === selectedEventId) ?? null
  }, [selectedEventId, events])

  return (
    <div className={styles.card} aria-labelledby="timeline-title">
      <header className={styles.cardHeader}>
        <h3 id="timeline-title" className={styles.cardTitle}>
          <svg className={styles.cardIcon} viewBox="0 0 24 24" fill="none" width="18" height="18" aria-hidden="true">
            <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2" />
            <path d="M12 7v5l3 3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
          Chronological Event Timeline
        </h3>
        <span className={styles.cardBadge}>
          {filteredEvents.length} of {events.length} events
        </span>
      </header>

      {/* Toolbar / Filters */}
      <div className={styles.timelineToolbar}>
        <div className={styles.timelineFilters}>
          <label htmlFor="timeline-sort-select" style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
            Sort:
          </label>
          <select
            id="timeline-sort-select"
            className={styles.filterSelect}
            value={sortOrder}
            onChange={e => setSortOrder(e.target.value as 'asc' | 'desc')}
          >
            <option value="asc">Earliest First (Chronological)</option>
            <option value="desc">Latest First (Reverse)</option>
          </select>

          <label htmlFor="timeline-outcome-select" style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
            Outcome:
          </label>
          <select
            id="timeline-outcome-select"
            className={styles.filterSelect}
            value={outcomeFilter}
            onChange={e => setOutcomeFilter(e.target.value as 'all' | 'failure' | 'success')}
          >
            <option value="all">All Outcomes</option>
            <option value="failure">Failures Only</option>
            <option value="success">Successes Only</option>
          </select>
        </div>

        {/* Clear Cross-Filters if active */}
        {(selectedHost || selectedRuleId) && (
          <div style={{ display: 'flex', gap: '6px' }}>
            {selectedHost && onSelectHost && (
              <button
                type="button"
                className={styles.clearFilterBtn}
                onClick={() => onSelectHost(null)}
                title="Remove host filter"
              >
                Host: {selectedHost} ✕
              </button>
            )}
            {selectedRuleId && onSelectRule && (
              <button
                type="button"
                className={styles.clearFilterBtn}
                onClick={() => onSelectRule(null)}
                title="Remove rule filter"
              >
                Rule: {selectedRuleId} ✕
              </button>
            )}
          </div>
        )}
      </div>

      {/* Event List */}
      {filteredEvents.length === 0 ? (
        <div style={{ padding: '24px', textAlign: 'center', color: '#94a3b8', fontSize: '0.85rem' }}>
          No authentication events match the current filter criteria.
        </div>
      ) : (
        <div className={styles.timelineList} role="feed" aria-label="Authentication event stream">
          {filteredEvents.map(event => {
            const isSelected = selectedEventId === event.id
            const matchedRules = eventToRulesMap.get(event.id) ?? []
            const validTime = safeParseTime(event.timestamp)
            const timeLabel = validTime !== null
              ? new Date(validTime).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
              : 'Unknown / Malformed Timestamp'

            return (
              <div
                key={event.id}
                className={`${styles.timelineItem} ${isSelected ? styles.timelineItemSelected : ''}`}
                onClick={() => onSelectEvent(isSelected ? null : event.id)}
                onKeyDown={e => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    onSelectEvent(isSelected ? null : event.id)
                  }
                }}
                tabIndex={0}
                role="article"
                aria-label={`Event at ${timeLabel}: ${event.outcome} login from ${event.sourceIp} to ${event.destination ?? 'unspecified'}`}
              >
                <div className={styles.timelineItemHeader}>
                  <span className={styles.timePill}>{timeLabel}</span>
                  <span
                    className={
                      event.outcome === 'success'
                        ? styles.outcomeBadgeSuccess
                        : styles.outcomeBadgeFailure
                    }
                  >
                    {event.outcome.toUpperCase()}
                  </span>
                </div>

                <div className={styles.timelineItemBody}>
                  <span>
                    User: <strong className={styles.monoTag}>{event.username}</strong>
                  </span>
                  <span>
                    IP: <span className={styles.monoTag}>{event.sourceIp}</span>
                    {event.location && (
                      <span style={{ marginLeft: '4px', fontSize: '0.72rem', color: '#38bdf8' }}>
                        ({event.location})
                      </span>
                    )}
                  </span>
                  <span>
                    Target:{' '}
                    {event.destination ? (
                      <span className={styles.hostTag}>{event.destination}</span>
                    ) : (
                      <span style={{ color: '#64748b' }}>Perimeter / None</span>
                    )}
                  </span>
                  <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                    Logon: {event.logonType}
                  </span>
                </div>

                {matchedRules.length > 0 && (
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '4px' }}>
                    {matchedRules.map(r => (
                      <span key={r.id} className={styles.ruleBadge} title={`Triggered rule ${r.name}`}>
                        ⚡ {r.name}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* Selected Event Inspection Drawer */}
      {selectedEvent && (
        <div className={styles.eventInspector} aria-label="Event detail inspector">
          <div className={styles.inspectorHeader}>
            <h4 className={styles.inspectorTitle}>
              Telemetry Event Inspector — <code>{selectedEvent.id}</code>
            </h4>
            <button
              type="button"
              className={styles.clearFilterBtn}
              onClick={() => onSelectEvent(null)}
              aria-label="Close event inspector"
            >
              Close
            </button>
          </div>

          <div className={styles.inspectorGrid}>
            <div className={styles.inspectorField}>
              <span className={styles.inspectorLabel}>Event ID</span>
              <span className={styles.inspectorValue}>{selectedEvent.id}</span>
            </div>
            <div className={styles.inspectorField}>
              <span className={styles.inspectorLabel}>Timestamp (UTC)</span>
              <span className={styles.inspectorValue}>{selectedEvent.timestamp}</span>
            </div>
            <div className={styles.inspectorField}>
              <span className={styles.inspectorLabel}>Account Username</span>
              <span className={styles.inspectorValue}>{selectedEvent.username}</span>
            </div>
            <div className={styles.inspectorField}>
              <span className={styles.inspectorLabel}>Source IPv4</span>
              <span className={styles.inspectorValue}>{selectedEvent.sourceIp}</span>
            </div>
            <div className={styles.inspectorField}>
              <span className={styles.inspectorLabel}>Enriched Location</span>
              <span className={styles.inspectorValue}>{selectedEvent.location || 'Unenriched / External'}</span>
            </div>
            <div className={styles.inspectorField}>
              <span className={styles.inspectorLabel}>Destination Host</span>
              <span className={styles.inspectorValue}>{selectedEvent.destination || 'Unspecified / External'}</span>
            </div>
            <div className={styles.inspectorField}>
              <span className={styles.inspectorLabel}>Logon Method</span>
              <span className={styles.inspectorValue}>{selectedEvent.logonType}</span>
            </div>
            <div className={styles.inspectorField}>
              <span className={styles.inspectorLabel}>Outcome</span>
              <span
                className={
                  selectedEvent.outcome === 'success'
                    ? styles.outcomeBadgeSuccess
                    : styles.outcomeBadgeFailure
                }
              >
                {selectedEvent.outcome.toUpperCase()}
              </span>
            </div>
            <div className={styles.inspectorField}>
              <span className={styles.inspectorLabel}>Source CSV Row</span>
              <span className={styles.inspectorValue}>{selectedEvent.rawRow}</span>
            </div>
            <div className={styles.inspectorField}>
              <span className={styles.inspectorLabel}>Duplicate Record</span>
              <span className={styles.inspectorValue}>{selectedEvent.isDuplicate ? 'Yes (De-duplicated)' : 'No (Original)'}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
