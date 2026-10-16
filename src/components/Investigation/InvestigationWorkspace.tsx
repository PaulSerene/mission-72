/**
 * InvestigationWorkspace — SignalForge Integrated SOC Investigation Studio
 *
 * Coordinates:
 * 1. Interactive User-to-Host SVG Topology Graph
 * 2. Chronological Suspicious Event Timeline with Inspector
 * 3. Exact Mathematical Heuristic Risk Breakdown
 * 4. Alert Explanations with Deterministic Evidence-Strength Classification
 * 5. Bidirectional Cross-Filtering (Incident -> Rule -> Host -> Event)
 */

import { useState, useMemo } from 'react'
import type { Incident, AuthEvent, AssetRecord, BaselineStatus } from '@/types'
import { buildUserHostGraphData } from '@/engine/investigation'
import { UserHostGraph } from './UserHostGraph'
import { Timeline } from './Timeline'
import { RiskBreakdown } from './RiskBreakdown'
import { AlertExplanations } from './AlertExplanations'
import styles from './Investigation.module.css'

interface InvestigationWorkspaceProps {
  incident: Incident
  allEvents: AuthEvent[]
  assets?: AssetRecord[]
  baselineStatus?: BaselineStatus
  onClose?: () => void
  incidentsList?: Incident[]
  onSelectIncident?: (incidentId: string) => void
}

export function InvestigationWorkspace({
  incident,
  allEvents,
  assets = [],
  baselineStatus,
  onClose,
  incidentsList,
  onSelectIncident,
}: InvestigationWorkspaceProps) {
  // Cross-filtering states
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null)
  const [selectedHost, setSelectedHost] = useState<string | null>(null)
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null)

  // Compute graph data
  const graphData = useMemo(() => {
    return buildUserHostGraphData(incident, allEvents, assets)
  }, [incident, allEvents, assets])

  // Reset all cross-filters
  function handleClearAllFilters() {
    setSelectedRuleId(null)
    setSelectedHost(null)
    setSelectedEventId(null)
    setSelectedNodeId(null)
    setSelectedEdgeId(null)
  }

  const hasActiveFilters = Boolean(selectedRuleId || selectedHost || selectedEventId)

  return (
    <div className={styles.container} aria-label="Incident Investigation Studio">
      {/* Incident Switcher Toolbar (if incidentsList provided) */}
      {incidentsList && incidentsList.length > 1 && onSelectIncident && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            flexWrap: 'wrap',
            padding: '10px 14px',
            background: 'var(--color-bg-surface, #0d1424)',
            border: '1px solid var(--color-border, rgba(99, 130, 190, 0.2))',
            borderRadius: 'var(--radius-md, 8px)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <label htmlFor="investigation-incident-select" style={{ fontSize: '0.82rem', color: '#94a3b8', fontWeight: 600 }}>
              Select Correlated Incident:
            </label>
            <select
              id="investigation-incident-select"
              className={styles.filterSelect}
              value={incident.id}
              onChange={e => {
                handleClearAllFilters()
                onSelectIncident(e.target.value)
              }}
              style={{ minWidth: '240px' }}
            >
              {incidentsList.map(inc => (
                <option key={inc.id} value={inc.id}>
                  {inc.id} — {inc.username} (Risk: {inc.riskScore}, {inc.severity.toUpperCase()})
                </option>
              ))}
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              Viewing telemetry for <strong style={{ color: '#f1f5f9' }}>{incident.username}</strong> ({incident.startTimestamp.slice(0, 10)})
            </div>
            {onClose && (
              <button
                type="button"
                className={styles.clearFilterBtn}
                onClick={onClose}
                aria-label="Close investigation studio"
              >
                Close Studio
              </button>
            )}
          </div>
        </div>
      )}

      {/* Active Cross-Filter Banner */}
      {hasActiveFilters && (
        <div className={styles.crossFilterBanner} role="status">
          <div className={styles.filterTagsGroup}>
            <span style={{ fontWeight: 600 }}>Active Investigation Filters:</span>
            {selectedRuleId && (
              <span className={styles.filterTag}>
                Rule: {selectedRuleId}
                <button
                  type="button"
                  onClick={() => setSelectedRuleId(null)}
                  style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: 0 }}
                  aria-label="Remove rule filter"
                >
                  ✕
                </button>
              </span>
            )}
            {selectedHost && (
              <span className={styles.filterTag}>
                Host: {selectedHost}
                <button
                  type="button"
                  onClick={() => {
                    setSelectedHost(null)
                    setSelectedNodeId(null)
                    setSelectedEdgeId(null)
                  }}
                  style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: 0 }}
                  aria-label="Remove host filter"
                >
                  ✕
                </button>
              </span>
            )}
            {selectedEventId && (
              <span className={styles.filterTag}>
                Event: {selectedEventId}
                <button
                  type="button"
                  onClick={() => setSelectedEventId(null)}
                  style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: 0 }}
                  aria-label="Remove event filter"
                >
                  ✕
                </button>
              </span>
            )}
          </div>

          <button
            type="button"
            className={styles.clearFilterBtn}
            onClick={handleClearAllFilters}
          >
            Reset All Filters
          </button>
        </div>
      )}

      {/* Row 1: Interactive User-Host Graph & Risk Breakdown */}
      <div className={styles.splitGrid}>
        {/* User-to-Host Graph */}
        <div className={styles.card} aria-labelledby="host-graph-heading">
          <header className={styles.cardHeader}>
            <h3 id="host-graph-heading" className={styles.cardTitle}>
              <svg className={styles.cardIcon} viewBox="0 0 24 24" fill="none" width="18" height="18" aria-hidden="true">
                <circle cx="6" cy="6" r="3" stroke="currentColor" strokeWidth="2" />
                <circle cx="18" cy="6" r="3" stroke="currentColor" strokeWidth="2" />
                <circle cx="12" cy="18" r="3" stroke="currentColor" strokeWidth="2" />
                <path d="M8.5 7.5L15.5 7.5M7.5 8.5L10.5 15.5M16.5 8.5L13.5 15.5" stroke="currentColor" strokeWidth="1.5" />
              </svg>
              User-to-Host Interaction Graph
            </h3>
            <span className={styles.cardBadge}>
              {graphData.hostNodes.length} host endpoint{graphData.hostNodes.length !== 1 ? 's' : ''}
            </span>
          </header>

          <UserHostGraph
            graphData={graphData}
            selectedNodeId={selectedNodeId}
            selectedEdgeId={selectedEdgeId}
            onSelectNode={(nodeId, node) => {
              setSelectedNodeId(nodeId)
              if (node?.type === 'host') {
                setSelectedHost(node.label)
              } else {
                setSelectedHost(null)
              }
            }}
            onSelectEdge={(edgeId, edge) => {
              setSelectedEdgeId(edgeId)
              setSelectedHost(edge ? edge.targetHost : null)
            }}
            onSelectHost={host => setSelectedHost(host)}
          />
        </div>

        {/* Risk Breakdown */}
        <RiskBreakdown
          incident={incident}
          selectedRuleId={selectedRuleId}
          onSelectRule={ruleId => setSelectedRuleId(ruleId)}
        />
      </div>

      {/* Row 2: Alert Explanations & Chronological Timeline */}
      <div className={styles.splitGrid}>
        {/* Alert Explanations */}
        <AlertExplanations
          ruleMatches={incident.ruleMatches}
          events={allEvents}
          selectedRuleId={selectedRuleId}
          onSelectRule={ruleId => setSelectedRuleId(ruleId)}
          baselineStatus={baselineStatus}
        />

        {/* Chronological Timeline */}
        <Timeline
          events={allEvents.filter(ev => {
            // Filter to events associated with this incident
            const incEventIds = new Set(incident.ruleMatches.flatMap(m => m.evidence.eventIds))
            if (incEventIds.has(ev.id)) return true
            return ev.username.toLowerCase() === incident.username.toLowerCase()
          })}
          ruleMatches={incident.ruleMatches}
          selectedEventId={selectedEventId}
          selectedHost={selectedHost}
          selectedRuleId={selectedRuleId}
          onSelectEvent={eventId => setSelectedEventId(eventId)}
          onSelectRule={ruleId => setSelectedRuleId(ruleId)}
          onSelectHost={host => {
            setSelectedHost(host)
            if (!host) {
              setSelectedNodeId(null)
              setSelectedEdgeId(null)
            }
          }}
        />
      </div>
    </div>
  )
}
