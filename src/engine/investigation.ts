/**
 * Investigation Engine — Mission 03: Visualization & Risk Analysis
 *
 * Provides pure, deterministic functions for:
 * 1. Safe chronological event sorting (handling valid, missing, or malformed timestamps).
 * 2. Deterministic evidence-strength evaluation for detection rule matches.
 * 3. User-to-host topology graph data generation for correlated incidents.
 * 4. Cross-filtering and event correlation helpers.
 */

import type {
  AuthEvent,
  Incident,
  RuleMatch,
  AssetRecord,
  EvidenceStrengthEvaluation,
  EvidenceStrengthLevel,
  UserHostGraphData,
  GraphNode,
  GraphEdge,
  BaselineStatus,
} from '@/types'

/**
 * Safely parse an ISO timestamp string into epoch milliseconds.
 * Returns null if the timestamp is null, undefined, empty, or an invalid date.
 */
export function safeParseTime(ts: string | null | undefined): number | null {
  if (!ts || typeof ts !== 'string') return null
  const time = new Date(ts).getTime()
  return isNaN(time) ? null : time
}

/**
 * Deterministically sorts authentication events chronologically.
 * - Valid timestamps are ordered by epoch time.
 * - Missing or malformed timestamps are handled safely and positioned at the end (or beginning if desc).
 * - Stable secondary sort uses rawRow or id to ensure absolute determinism.
 */
export function sortEventsChronologically(
  events: AuthEvent[],
  order: 'asc' | 'desc' = 'asc',
): AuthEvent[] {
  return [...events].sort((a, b) => {
    const timeA = safeParseTime(a.timestamp)
    const timeB = safeParseTime(b.timestamp)

    if (timeA === null && timeB === null) {
      return (a.rawRow ?? 0) - (b.rawRow ?? 0) || a.id.localeCompare(b.id)
    }
    if (timeA === null) return 1 // push invalid to the end
    if (timeB === null) return -1

    if (timeA !== timeB) {
      return order === 'asc' ? timeA - timeB : timeB - timeA
    }

    return (a.rawRow ?? 0) - (b.rawRow ?? 0) || a.id.localeCompare(b.id)
  })
}

/**
 * Deterministically evaluates the strength of evidence supporting a detection rule match.
 *
 * Evaluation Methodology:
 * - Evidence strength is NOT a calibrated probability of compromise.
 * - It evaluates corroboration volume, completeness of resolved event references,
 *   baseline status, and contextual de-escalation factors.
 * - Categorized strictly as 'Strong' | 'Moderate' | 'Weak'.
 */
export function evaluateEvidenceStrength(
  match: RuleMatch,
  resolvedEvents: AuthEvent[],
  baselineStatus?: BaselineStatus,
): EvidenceStrengthEvaluation {
  const criteria: string[] = []
  const resolvedIds = new Set(resolvedEvents.map(e => e.id))
  const matchEventIds = match.evidence.eventIds ?? []
  const totalEventCount = matchEventIds.length

  // 1. Traceability Check
  let resolvedEventCount = 0
  for (const id of matchEventIds) {
    if (resolvedIds.has(id)) resolvedEventCount++
  }
  const allEventsResolved = totalEventCount > 0 && resolvedEventCount === totalEventCount

  if (allEventsResolved) {
    criteria.push(
      `Full telemetry traceability: 100% of referenced events (${totalEventCount}/${totalEventCount}) verified in session logs.`,
    )
  } else if (resolvedEventCount > 0) {
    criteria.push(
      `Partial telemetry traceability: ${resolvedEventCount}/${totalEventCount} referenced events found in log stream.`,
    )
  } else {
    criteria.push(
      `Unresolved telemetry: none of the ${totalEventCount} referenced event IDs were present in the active event index.`,
    )
  }

  // 2. Context Adjustment Check
  const hasContextSuppression = Boolean(match.contextSuppression)
  if (hasContextSuppression) {
    const mult = match.contextSuppression?.scoreMultiplier ?? 1.0
    criteria.push(
      `Contextual exception active: evidence de-escalated to ${Math.round(mult * 100)}% weight (${match.contextSuppression?.reason}).`,
    )
  }

  // 3. Rule-Specific Heuristic Strength Evaluation
  let baseScore = 50 // default moderate starting point

  switch (match.ruleId) {
    case 'burst_success': {
      // High-risk indicator: multiple failures preceding a success
      const successCount = resolvedEvents.filter(e => e.outcome === 'success').length
      const failureCount = resolvedEvents.filter(e => e.outcome === 'failure').length
      if (successCount >= 1 && failureCount >= 4) {
        baseScore = 85
        criteria.push(
          `Multi-event progression: ${failureCount} sequential failures immediately followed by successful authentication.`,
        )
      } else if (successCount >= 1) {
        baseScore = 70
        criteria.push(
          `Authentication transition: verified credential failure followed by successful logon within correlation window.`,
        )
      } else {
        baseScore = 55
        criteria.push(`Burst pattern observed in ${totalEventCount} authentication attempts.`)
      }
      break
    }
    case 'brute_force': {
      if (totalEventCount >= 10) {
        baseScore = 85
        criteria.push(
          `High failure volume: ${totalEventCount} authentication failures demonstrate sustained credential trial.`,
        )
      } else if (totalEventCount >= 5) {
        baseScore = 70
        criteria.push(
          `Threshold failure volume: ${totalEventCount} repeated failed attempts within detection window.`,
        )
      } else {
        baseScore = 45
        criteria.push(`Sub-threshold or low failure volume (${totalEventCount} events).`)
      }
      break
    }
    case 'password_spray': {
      const distinctUsers = new Set(resolvedEvents.map(e => e.username)).size
      if (distinctUsers >= 5) {
        baseScore = 85
        criteria.push(
          `Distributed attack breadth: ${distinctUsers} distinct accounts targeted from identical origin.`,
        )
      } else if (distinctUsers >= 3) {
        baseScore = 70
        criteria.push(
          `Horizontal traversal: ${distinctUsers} accounts targeted within short temporal window.`,
        )
      } else {
        baseScore = 50
        criteria.push(`Target account spread across ${totalEventCount} events.`)
      }
      break
    }
    case 'new_hosts': {
      const distinctHosts = new Set(resolvedEvents.map(e => e.destination).filter(Boolean)).size
      if (distinctHosts >= 5) {
        baseScore = 85
        criteria.push(
          `Extensive host enumeration: ${distinctHosts} previously unobserved destination endpoints accessed.`,
        )
      } else if (distinctHosts >= 3) {
        baseScore = 65
        criteria.push(
          `Lateral movement pattern: ${distinctHosts} new destination endpoints accessed.`,
        )
      } else {
        baseScore = 50
        criteria.push(`Unfamiliar destination host access (${totalEventCount} events).`)
      }
      break
    }
    case 'new_ip_location': {
      if (baselineStatus === 'sufficient') {
        baseScore = 60
        criteria.push(
          `Established baseline deviation: login from unfamiliar IP/geographic location with sufficient training history.`,
        )
      } else {
        baseScore = 40
        criteria.push(
          `Limited baseline confidence: user lacks extensive training history to firmly establish geographic norms.`,
        )
      }
      break
    }
    case 'unusual_hours': {
      if (baselineStatus === 'sufficient') {
        baseScore = 60
        criteria.push(
          `Off-shift access: authentication outside 100% of historical training hour distribution.`,
        )
      } else {
        baseScore = 35
        criteria.push(
          `Default off-hours window: user baseline was insufficient, defaulting to standard 22:00-06:00 UTC policy.`,
        )
      }
      break
    }
    case 'impossible_travel': {
      const speed = typeof match.evidence.data?.speedKmH === 'number' ? match.evidence.data.speedKmH : 0
      const dist = typeof match.evidence.data?.distanceKm === 'number' ? match.evidence.data.distanceKm : 0
      if (speed >= 2000) {
        baseScore = 85
        criteria.push(
          `Extreme geographic incompatibility: required velocity of ${speed} km/h (${dist} km) vastly exceeds supersonic aviation.`,
        )
      } else if (speed > 1000) {
        baseScore = 75
        criteria.push(
          `Physical travel impossibility: required velocity of ${speed} km/h (${dist} km) exceeds commercial aircraft capabilities.`,
        )
      } else {
        baseScore = 60
        criteria.push(
          `Geographic anomaly: required travel speed of ${speed} km/h over ${dist} km between consecutive logins.`,
        )
      }
      break
    }
    default: {
      baseScore = 50
      criteria.push(`Standard rule pattern with ${totalEventCount} contributing events.`)
    }
  }

  // Adjust score based on traceability and context suppression
  if (!allEventsResolved) {
    baseScore -= 20
  }
  if (hasContextSuppression) {
    baseScore -= 25
  }

  const finalScore = Math.max(10, Math.min(100, Math.round(baseScore)))

  let level: EvidenceStrengthLevel = 'Moderate'
  if (finalScore >= 75) {
    level = 'Strong'
  } else if (finalScore < 45) {
    level = 'Weak'
  }

  return {
    level,
    score: finalScore,
    criteria,
    resolvedEventCount,
    totalEventCount,
    allEventsResolved,
  }
}

/**
 * Builds the User-to-Host interaction graph topology model for an incident.
 */
export function buildUserHostGraphData(
  incident: Incident,
  allEvents: AuthEvent[],
  assets: AssetRecord[] = [],
): UserHostGraphData {
  // Build asset lookup map (hostname lowercase -> AssetRecord)
  const assetMap = new Map<string, AssetRecord>()
  for (const a of assets) {
    assetMap.set(a.host.toLowerCase(), a)
  }

  // Collect all event IDs referenced by the incident's rule matches
  const incidentEventIdSet = new Set<string>()
  for (const rm of incident.ruleMatches) {
    for (const id of rm.evidence.eventIds) {
      incidentEventIdSet.add(id)
    }
  }

  // Find all events belonging to this incident (either by ID or matching user within incident window)
  const incidentEvents = allEvents.filter(ev => {
    if (incidentEventIdSet.has(ev.id)) return true
    if (ev.username.toLowerCase() === incident.username.toLowerCase()) {
      const t = safeParseTime(ev.timestamp)
      const start = safeParseTime(incident.startTimestamp)
      const end = safeParseTime(incident.endTimestamp)
      if (t !== null && start !== null && end !== null) {
        return t >= start && t <= end
      }
    }
    return false
  })

  // Map of rule matches by event ID
  const eventRuleMap = new Map<string, Set<string>>()
  for (const rm of incident.ruleMatches) {
    for (const id of rm.evidence.eventIds) {
      const set = eventRuleMap.get(id) ?? new Set<string>()
      set.add(rm.ruleId)
      eventRuleMap.set(id, set)
    }
  }

  // Group events by destination host
  const hostGroupMap = new Map<
    string,
    {
      events: AuthEvent[]
      successCount: number
      failureCount: number
      logonTypes: Set<string>
      ruleIds: Set<string>
    }
  >()

  let unspecifiedDestinationCount = 0

  for (const ev of incidentEvents) {
    const rawDest = ev.destination ? ev.destination.trim() : null
    if (!rawDest) {
      unspecifiedDestinationCount++
      continue
    }

    const hostKey = rawDest.toLowerCase()
    let group = hostGroupMap.get(hostKey)
    if (!group) {
      group = {
        events: [],
        successCount: 0,
        failureCount: 0,
        logonTypes: new Set<string>(),
        ruleIds: new Set<string>(),
      }
      hostGroupMap.set(hostKey, group)
    }

    group.events.push(ev)
    if (ev.outcome === 'success') group.successCount++
    else group.failureCount++

    if (ev.logonType) group.logonTypes.add(ev.logonType)

    const rulesForEvent = eventRuleMap.get(ev.id)
    if (rulesForEvent) {
      for (const r of rulesForEvent) group.ruleIds.add(r)
    }
  }

  // User Node
  const userNode: GraphNode = {
    id: `user-${incident.username}`,
    label: incident.username,
    type: 'user',
    eventCount: incidentEvents.length,
    successCount: incidentEvents.filter(e => e.outcome === 'success').length,
    failureCount: incidentEvents.filter(e => e.outcome !== 'success').length,
    relatedRuleIds: Array.from(new Set(incident.ruleMatches.map(m => m.ruleId))),
  }

  // Host Nodes & Edges
  const hostNodes: GraphNode[] = []
  const edges: GraphEdge[] = []

  for (const [hostKey, group] of hostGroupMap) {
    const asset = assetMap.get(hostKey)
    const hostNodeId = `host-${hostKey}`

    const hostNode: GraphNode = {
      id: hostNodeId,
      label: hostKey,
      type: 'host',
      role: asset?.role ?? 'endpoint',
      isPrivileged: asset?.privileged ?? false,
      eventCount: group.events.length,
      successCount: group.successCount,
      failureCount: group.failureCount,
      relatedRuleIds: Array.from(group.ruleIds),
    }
    hostNodes.push(hostNode)

    const edge: GraphEdge = {
      id: `edge-${userNode.id}-${hostNodeId}`,
      source: userNode.id,
      target: hostNodeId,
      targetHost: hostKey,
      eventCount: group.events.length,
      successCount: group.successCount,
      failureCount: group.failureCount,
      logonTypes: Array.from(group.logonTypes),
      eventIds: group.events.map(e => e.id),
      relatedRuleIds: Array.from(group.ruleIds),
    }
    edges.push(edge)
  }

  // Sort host nodes deterministically by event count descending, then label
  hostNodes.sort((a, b) => b.eventCount - a.eventCount || a.label.localeCompare(b.label))

  return {
    userNode,
    hostNodes,
    edges,
    totalEvents: incidentEvents.length,
    unspecifiedDestinationCount,
  }
}
