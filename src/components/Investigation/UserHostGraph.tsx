/**
 * UserHostGraph — SignalForge Interactive Topology Graph
 *
 * Visualizes user accounts and destination hosts accessed during an incident.
 * - Deterministic, lightweight SVG rendering
 * - Selectable nodes and edges with keyboard navigation
 * - Visual indication of event volume, failure rates, and privileged assets
 * - Accessible text-based table alternative
 * - Clean empty state handling for external/perimeter attacks
 */

import { useState } from 'react'
import type { UserHostGraphData, GraphNode, GraphEdge } from '@/types'
import styles from './Investigation.module.css'

interface UserHostGraphProps {
  graphData: UserHostGraphData
  selectedNodeId: string | null
  selectedEdgeId: string | null
  onSelectNode: (nodeId: string | null, node: GraphNode | null) => void
  onSelectEdge: (edgeId: string | null, edge: GraphEdge | null) => void
  onSelectHost?: (host: string | null) => void
}

export function UserHostGraph({
  graphData,
  selectedNodeId,
  selectedEdgeId,
  onSelectNode,
  onSelectEdge,
  onSelectHost,
}: UserHostGraphProps) {
  const [viewMode, setViewMode] = useState<'svg' | 'table'>('svg')

  const { userNode, hostNodes, edges, totalEvents, unspecifiedDestinationCount } = graphData

  // Empty state check
  if (hostNodes.length === 0) {
    return (
      <div className={styles.graphContainer}>
        <div className={styles.graphEmptyState}>
          <svg className={styles.graphEmptyIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d="M3 15a4 4 0 004 4h10a4 4 0 004-4M3 15a4 4 0 014-4h10a4 4 0 014 4M7 11V7a5 5 0 0110 0v4"
              stroke="currentColor"
              strokeWidth="1.75"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <strong>No Target Hosts Recorded</strong>
          <p style={{ margin: 0, fontSize: '0.82rem', maxWidth: '420px', lineHeight: 1.4 }}>
            All {totalEvents} authentication events in this incident occurred against perimeter or
            unspecified network services without explicit internal destination hosts.
          </p>
          {unspecifiedDestinationCount > 0 && (
            <span className={styles.cardBadge}>
              {unspecifiedDestinationCount} perimeter / external event{unspecifiedDestinationCount !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>
    )
  }

  // Layout calculations
  const width = 640
  const height = 380
  const centerX = width / 2
  const centerY = height / 2

  const hostCount = hostNodes.length
  const radiusX = hostCount <= 2 ? 180 : Math.min(230, Math.max(160, 200))
  const radiusY = hostCount <= 2 ? 110 : Math.min(140, Math.max(100, 120))

  const hostPositions = new Map<string, { x: number; y: number }>()

  hostNodes.forEach((host, idx) => {
    let angle: number
    if (hostCount === 1) {
      angle = 0
    } else {
      angle = (2 * Math.PI * idx) / hostCount - Math.PI / 2
    }
    const x = Math.round(centerX + radiusX * Math.cos(angle))
    const y = Math.round(centerY + radiusY * Math.sin(angle))
    hostPositions.set(host.id, { x, y })
  })

  function handleNodeClick(node: GraphNode) {
    if (selectedNodeId === node.id) {
      onSelectNode(null, null)
      if (onSelectHost) onSelectHost(null)
    } else {
      onSelectNode(node.id, node)
      if (node.type === 'host' && onSelectHost) {
        onSelectHost(node.label)
      } else if (node.type === 'user' && onSelectHost) {
        onSelectHost(null)
      }
    }
  }

  function handleEdgeClick(edge: GraphEdge) {
    if (selectedEdgeId === edge.id) {
      onSelectEdge(null, null)
      if (onSelectHost) onSelectHost(null)
    } else {
      onSelectEdge(edge.id, edge)
      if (onSelectHost) onSelectHost(edge.targetHost)
    }
  }

  return (
    <div className={styles.graphContainer}>
      {/* View Toggle */}
      <div className={styles.graphControls}>
        <button
          type="button"
          className={styles.graphToggleBtn}
          onClick={() => setViewMode(prev => (prev === 'svg' ? 'table' : 'svg'))}
          aria-label={viewMode === 'svg' ? 'Switch to accessible table view' : 'Switch to interactive graph view'}
        >
          {viewMode === 'svg' ? 'View as Table' : 'View as Graph'}
        </button>
      </div>

      {viewMode === 'table' ? (
        <div className={styles.tableAlternative}>
          <table className={styles.accessibleTable} aria-label="User-to-host interaction relationships">
            <thead>
              <tr>
                <th scope="col">Source Account</th>
                <th scope="col">Destination Host</th>
                <th scope="col">Host Role</th>
                <th scope="col">Privileged</th>
                <th scope="col">Events</th>
                <th scope="col">Success / Failure</th>
                <th scope="col">Logon Types</th>
              </tr>
            </thead>
            <tbody>
              {edges.map(edge => {
                const targetNode = hostNodes.find(h => h.id === edge.target)
                const isSelected = selectedEdgeId === edge.id || selectedNodeId === edge.target
                return (
                  <tr
                    key={edge.id}
                    onClick={() => handleEdgeClick(edge)}
                    style={{
                      cursor: 'pointer',
                      background: isSelected ? 'rgba(59, 130, 246, 0.15)' : undefined,
                    }}
                  >
                    <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{userNode.label}</td>
                    <td style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{edge.targetHost}</td>
                    <td>{targetNode?.role ?? 'endpoint'}</td>
                    <td>
                      {targetNode?.isPrivileged ? (
                        <span style={{ color: '#f59e0b', fontWeight: 600 }}>★ Privileged</span>
                      ) : (
                        'Standard'
                      )}
                    </td>
                    <td style={{ fontFamily: 'monospace' }}>{edge.eventCount}</td>
                    <td>
                      <span style={{ color: '#10b981' }}>{edge.successCount}S</span> /{' '}
                      <span style={{ color: '#ef4444' }}>{edge.failureCount}F</span>
                    </td>
                    <td style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                      {edge.logonTypes.join(', ') || '—'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <svg
          className={styles.graphSvg}
          viewBox={`0 0 ${width} ${height}`}
          role="graphics-document"
          aria-label={`User-to-host interaction graph for account ${userNode.label}`}
        >
          <defs>
            <linearGradient id="userGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#3b82f6" />
              <stop offset="100%" stopColor="#1d4ed8" />
            </linearGradient>
            <linearGradient id="hostGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#1e293b" />
              <stop offset="100%" stopColor="#0f172a" />
            </linearGradient>
            <filter id="glowEffect" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            <marker
              id="arrowhead"
              markerWidth="7"
              markerHeight="7"
              refX="6"
              refY="3.5"
              orient="auto"
            >
              <polygon points="0 0, 7 3.5, 0 7" fill="#64748b" />
            </marker>
          </defs>

          {/* Edges */}
          <g className="edges-layer" aria-label="Graph connections">
            {edges.map(edge => {
              const targetPos = hostPositions.get(edge.target)
              if (!targetPos) return null

              const isEdgeSelected = selectedEdgeId === edge.id
              const isLinkedToSelectedNode =
                selectedNodeId === edge.source || selectedNodeId === edge.target
              const isHighlighted = isEdgeSelected || isLinkedToSelectedNode

              const strokeWidth = Math.min(5, Math.max(2, 1.5 + Math.log2(edge.eventCount + 1)))
              const midX = (centerX + targetPos.x) / 2
              const midY = (centerY + targetPos.y) / 2

              const edgeColor = isHighlighted
                ? '#38bdf8'
                : edge.failureCount > 0
                ? '#f97316'
                : 'rgba(99, 130, 190, 0.4)'

              return (
                <g key={edge.id} onClick={() => handleEdgeClick(edge)}>
                  <line
                    x1={centerX}
                    y1={centerY}
                    x2={targetPos.x}
                    y2={targetPos.y}
                    stroke={edgeColor}
                    strokeWidth={isHighlighted ? strokeWidth + 1.5 : strokeWidth}
                    strokeDasharray={edge.failureCount > 0 && edge.successCount === 0 ? '4 3' : undefined}
                    className={`${styles.graphEdge} ${isHighlighted ? styles.graphEdgeSelected : ''}`}
                  />
                  {/* Midpoint Event Count Badge */}
                  <rect
                    x={midX - 12}
                    y={midY - 9}
                    width={24}
                    height={16}
                    rx={4}
                    fill="#0d1424"
                    stroke={edgeColor}
                    strokeWidth="1"
                    style={{ pointerEvents: 'none' }}
                  />
                  <text
                    x={midX}
                    y={midY + 3}
                    textAnchor="middle"
                    fill="#f1f5f9"
                    fontSize="9"
                    fontFamily="monospace"
                    fontWeight="600"
                    style={{ pointerEvents: 'none' }}
                  >
                    {edge.eventCount}
                  </text>
                </g>
              )
            })}
          </g>

          {/* User Node (Center) */}
          <g
            className={`${styles.nodeUser} ${selectedNodeId === userNode.id ? styles.nodeSelected : ''}`}
            onClick={() => handleNodeClick(userNode)}
            onKeyDown={e => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                handleNodeClick(userNode)
              }
            }}
            tabIndex={0}
            role="graphics-symbol"
            aria-label={`User account: ${userNode.label}, ${userNode.eventCount} total events`}
          >
            <circle
              cx={centerX}
              cy={centerY}
              r={28}
              fill="url(#userGrad)"
              stroke="#60a5fa"
              strokeWidth={selectedNodeId === userNode.id ? '3' : '2'}
            />
            {/* User Icon */}
            <circle cx={centerX} cy={centerY - 6} r={7} fill="#ffffff" />
            <path
              d={`M ${centerX - 13} ${centerY + 16} Q ${centerX} ${centerY + 4} ${centerX + 13} ${centerY + 16}`}
              stroke="#ffffff"
              strokeWidth="3.5"
              strokeLinecap="round"
              fill="none"
            />
            {/* Account Label */}
            <text
              x={centerX}
              y={centerY + 42}
              textAnchor="middle"
              fill="#f1f5f9"
              fontSize="11"
              fontWeight="600"
              fontFamily="monospace"
            >
              {userNode.label}
            </text>
            <text
              x={centerX}
              y={centerY + 54}
              textAnchor="middle"
              fill="#94a3b8"
              fontSize="9"
            >
              (Primary Account)
            </text>
          </g>

          {/* Host Nodes */}
          {hostNodes.map(host => {
            const pos = hostPositions.get(host.id)
            if (!pos) return null

            const isSelected = selectedNodeId === host.id
            const isPrivileged = host.isPrivileged

            return (
              <g
                key={host.id}
                className={`${styles.nodeHost} ${isSelected ? styles.nodeSelected : ''}`}
                onClick={() => handleNodeClick(host)}
                onKeyDown={e => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    handleNodeClick(host)
                  }
                }}
                tabIndex={0}
                role="graphics-symbol"
                aria-label={`Host ${host.label}: ${host.eventCount} events, role: ${host.role}`}
              >
                {/* Node Box */}
                <rect
                  x={pos.x - 36}
                  y={pos.y - 20}
                  width={72}
                  height={40}
                  rx={8}
                  fill="url(#hostGrad)"
                  stroke={isSelected ? '#60a5fa' : isPrivileged ? '#f59e0b' : 'rgba(99, 130, 190, 0.4)'}
                  strokeWidth={isSelected ? '2.5' : '1.5'}
                />

                {/* Privileged Star Badge */}
                {isPrivileged && (
                  <text
                    x={pos.x + 26}
                    y={pos.y - 10}
                    fill="#f59e0b"
                    fontSize="10"
                    fontWeight="bold"
                  >
                    ★<title>Privileged Host</title>
                  </text>
                )}

                {/* Server Icon */}
                <rect
                  x={pos.x - 28}
                  y={pos.y - 12}
                  width={14}
                  height={24}
                  rx={2}
                  fill="none"
                  stroke={isPrivileged ? '#f59e0b' : '#38bdf8'}
                  strokeWidth="1.2"
                />
                <line
                  x1={pos.x - 25}
                  y1={pos.y - 5}
                  x2={pos.x - 17}
                  y2={pos.y - 5}
                  stroke={isPrivileged ? '#f59e0b' : '#38bdf8'}
                  strokeWidth="1"
                />
                <line
                  x1={pos.x - 25}
                  y1={pos.y + 3}
                  x2={pos.x - 17}
                  y2={pos.y + 3}
                  stroke={isPrivileged ? '#f59e0b' : '#38bdf8'}
                  strokeWidth="1"
                />

                {/* Hostname Short */}
                <text
                  x={pos.x - 8}
                  y={pos.y - 2}
                  textAnchor="start"
                  fill="#f1f5f9"
                  fontSize="9.5"
                  fontWeight="600"
                  fontFamily="monospace"
                >
                  {host.label.length > 8 ? `${host.label.slice(0, 7)}…` : host.label}
                </text>

                {/* Host Role or Event Count */}
                <text
                  x={pos.x - 8}
                  y={pos.y + 9}
                  textAnchor="start"
                  fill="#94a3b8"
                  fontSize="8"
                >
                  {host.role ?? 'endpoint'}
                </text>

                {/* Full Hostname Tooltip on Bottom */}
                <text
                  x={pos.x}
                  y={pos.y + 30}
                  textAnchor="middle"
                  fill="#cbd5e1"
                  fontSize="8.5"
                  fontFamily="monospace"
                >
                  {host.label}
                </text>
              </g>
            )
          })}
        </svg>
      )}
    </div>
  )
}
