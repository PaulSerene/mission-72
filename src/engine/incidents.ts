/**
 * Incident Correlation & Risk Scoring — Mission 72
 *
 * Correlates individual RuleMatches into actionable Incidents.
 * Multiple detections for the same user within a temporal window are
 * aggregated into a single incident with an explainable heuristic risk score.
 *
 * Risk scores are bounded [0, 100] and represent heuristic severity, NOT
 * probability of compromise.
 *
 * Overlap handling:
 *   - Overlapping brute_force and burst_success on the same event set are
 *     adjusted to prevent double-counting.
 *   - Repeated firings of the same rule within an incident yield diminishing score increments.
 */

import type {
  Incident,
  RuleMatch,
  Severity,
  RuleScoreContribution,
  IncidentRiskBreakdown,
} from '@/types'
import { RULE_SCORES } from './rules'

// ─── Configuration ───────────────────────────────────────────────────────────

/** Maximum time gap (in ms) between consecutive rule matches to be grouped into one incident (default 2 hours). */
const DEFAULT_CORRELATION_WINDOW_MS = 2 * 60 * 60 * 1000

// ─── Helpers ─────────────────────────────────────────────────────────────────

function parseTime(ts: string): number {
  return new Date(ts).getTime()
}

/** Check if two arrays of event IDs share any common IDs. */
function shareEventIds(ids1: string[], ids2: string[]): boolean {
  const set1 = new Set(ids1)
  return ids2.some(id => set1.has(id))
}

/**
 * Faithfully decompose an explainable, bounded heuristic risk score [0, 100]
 * into its individual rule contributions, diminishing repetitions, overlap deductions,
 * contextual reductions, and multi-rule synergy bonus.
 */
export function decomposeIncidentRiskScore(matches: RuleMatch[]): IncidentRiskBreakdown {
  if (matches.length === 0) {
    return {
      finalScore: 0,
      rawCalculatedScore: 0,
      contributions: [],
      synergyBonus: 0,
      distinctRuleCount: 0,
      cappedAt100: false,
    }
  }

  const ruleCounts = new Map<string, number>()
  const contributions: RuleScoreContribution[] = []

  // Check if both brute_force and burst_success are present
  const hasBurstSuccess = matches.some(m => m.ruleId === 'burst_success')

  // Check if they share any event IDs
  const bfMatches = matches.filter(m => m.ruleId === 'brute_force')
  const bsMatches = matches.filter(m => m.ruleId === 'burst_success')
  const overlapEvents = bfMatches.some(bf =>
    bsMatches.some(bs => shareEventIds(bf.evidence.eventIds, bs.evidence.eventIds)),
  )

  let scoreSum = 0

  matches.forEach((match, index) => {
    const baseScore = RULE_SCORES[match.ruleId] ?? 20
    const count = (ruleCounts.get(match.ruleId) ?? 0) + 1
    ruleCounts.set(match.ruleId, count)

    // Context-aware multiplier from partial suppression
    const ctxMultiplier = match.contextSuppression?.scoreMultiplier ?? 1.0
    const contextReason = match.contextSuppression?.reason

    // Overlap suppression: If both brute_force and burst_success fire on the same sequence,
    // burst_success carries full weight (55) and brute_force is discounted to avoid double-counting.
    if (match.ruleId === 'brute_force' && hasBurstSuccess && overlapEvents) {
      const rawContribution = count === 1 ? 15 : 5
      const repetitionMultiplier = rawContribution / baseScore
      const finalContribution = Math.round(rawContribution * ctxMultiplier)
      scoreSum += finalContribution

      contributions.push({
        ruleId: match.ruleId,
        ruleName: match.ruleName,
        matchIndex: index,
        repetitionCount: count,
        baseScore,
        repetitionMultiplier,
        rawContribution,
        contextMultiplier: ctxMultiplier,
        contextReason,
        overlapDiscounted: true,
        overlapDiscountReason:
          'Secondary brute-force detection discounted to prevent double-counting alongside overlapping burst-success credential compromise sequence',
        finalContribution,
      })
      return
    }

    // Diminishing returns for repeated firings of the same rule
    let repetitionMultiplier: number
    if (count === 1) {
      repetitionMultiplier = 1.0
    } else if (count === 2) {
      repetitionMultiplier = 0.4
    } else {
      repetitionMultiplier = 0.2
    }

    const rawContribution = Math.round(baseScore * repetitionMultiplier)
    const finalContribution = Math.round(rawContribution * ctxMultiplier)
    scoreSum += finalContribution

    contributions.push({
      ruleId: match.ruleId,
      ruleName: match.ruleName,
      matchIndex: index,
      repetitionCount: count,
      baseScore,
      repetitionMultiplier,
      rawContribution,
      contextMultiplier: ctxMultiplier,
      contextReason,
      overlapDiscounted: false,
      finalContribution,
    })
  })

  // Multi-rule synergy: observing 3 or more distinct rules indicates coordinated or advanced activity
  const distinctRules = new Set(matches.map(m => m.ruleId))
  const synergyBonus = distinctRules.size >= 3 ? 15 : 0
  const rawCalculatedScore = scoreSum + synergyBonus
  const finalScore = Math.min(100, Math.max(0, Math.round(rawCalculatedScore)))
  const cappedAt100 = rawCalculatedScore > 100

  return {
    finalScore,
    rawCalculatedScore,
    contributions,
    synergyBonus,
    distinctRuleCount: distinctRules.size,
    cappedAt100,
  }
}

/**
 * Compute an explainable, bounded heuristic risk score [0, 100].
 * Delegates faithfully to decomposeIncidentRiskScore.
 */
export function calculateIncidentRiskScore(matches: RuleMatch[]): number {
  return decomposeIncidentRiskScore(matches).finalScore
}

/**
 * Determine severity based on heuristic risk score.
 */
export function scoreToSeverity(score: number): Severity {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 35) return 'medium'
  return 'low'
}

/**
 * Generate a concise, analyst-friendly explanation of the correlated incident.
 * Notes context suppressions so analysts understand why risk was reduced.
 */
export function generateExplanation(username: string, matches: RuleMatch[]): string {
  const distinctRules = [...new Set(matches.map(m => m.ruleName))]
  const ruleCount = matches.length

  const suppressedMatches = matches.filter(m => m.contextSuppression)
  const suppressionNote = suppressedMatches.length > 0
    ? ` [Context: ${suppressedMatches.map(m => m.contextSuppression!.reason).join('; ')}]`
    : ''

  if (matches.length === 1) {
    return matches[0].evidence.description + suppressionNote
  }

  const parts = matches.map(m => m.evidence.description)
  return `Correlated incident for user "${username}": ${distinctRules.join(', ')} (${ruleCount} detections). Observations: ${parts.join('; ')}.${suppressionNote}`
}

/**
 * Recommend actionable triage steps based on the combination of rules that fired.
 */
export function generateRecommendedTriage(matches: RuleMatch[]): string {
  const ruleIds = new Set(matches.map(m => m.ruleId))

  if (ruleIds.has('burst_success') || (ruleIds.has('brute_force') && ruleIds.has('new_hosts'))) {
    return 'Critical compromise indicator: immediately revoke active sessions, reset user credentials, verify MFA registration, and check accessed hosts for persistence or lateral movement.'
  }

  if (ruleIds.has('password_spray')) {
    return 'Password spraying detected: block offending source IP on perimeter firewall/WAF, audit successful logins from that subnet, and enforce credential resets on targeted accounts.'
  }

  if (ruleIds.has('brute_force')) {
    return 'Repeated authentication failures: check if source IP is internal or known VPN, enforce temporary account lockout or MFA prompt, and check for leaked credential dumps.'
  }

  if (ruleIds.has('new_hosts')) {
    return 'Potential lateral movement: inspect endpoint security logs on newly accessed hosts, review recent commands executed under this user, and verify authorized operational need.'
  }

  if (ruleIds.has('new_ip_location') || ruleIds.has('unusual_hours')) {
    return 'Anomalous access pattern: verify user travel status and current shift through out-of-band communication, and monitor subsequent session actions.'
  }

  return 'Review event logs and confirm user activity with account owner.'
}

// ─── Main Correlation Function ────────────────────────────────────────────────

/**
 * Correlate a list of RuleMatches into an array of Incidents.
 *
 * @param matches                 Array of all rule matches produced by detection rules.
 * @param correlationWindowMs     Max gap between detections for the same user to be joined (default 2h).
 */
export function correlateIncidents(
  matches: RuleMatch[],
  correlationWindowMs: number = DEFAULT_CORRELATION_WINDOW_MS,
): Incident[] {
  if (matches.length === 0) return []

  // Group matches by user
  const byUser = new Map<string, RuleMatch[]>()
  for (const m of matches) {
    const list = byUser.get(m.username) ?? []
    list.push(m)
    byUser.set(m.username, list)
  }

  const incidents: Incident[] = []
  let incidentSeq = 1

  for (const [username, userMatches] of byUser) {
    // Sort matches chronologically
    const sorted = [...userMatches].sort((a, b) => a.timestamp.localeCompare(b.timestamp))

    // Chunk into time-correlated clusters
    const clusters: RuleMatch[][] = []
    let currentCluster: RuleMatch[] = [sorted[0]]

    for (let i = 1; i < sorted.length; i++) {
      const prevTime = parseTime(sorted[i - 1].timestamp)
      const currTime = parseTime(sorted[i].timestamp)

      if (currTime - prevTime <= correlationWindowMs) {
        currentCluster.push(sorted[i])
      } else {
        clusters.push(currentCluster)
        currentCluster = [sorted[i]]
      }
    }
    if (currentCluster.length > 0) {
      clusters.push(currentCluster)
    }

    // Build Incident for each cluster
    for (const cluster of clusters) {
      const startTimestamp = cluster[0].timestamp
      const endTimestamp = cluster[cluster.length - 1].timestamp
      const riskScore = calculateIncidentRiskScore(cluster)
      const severity = scoreToSeverity(riskScore)
      const explanation = generateExplanation(username, cluster)
      const recommendedTriage = generateRecommendedTriage(cluster)

      const id = `inc-${String(incidentSeq++).padStart(4, '0')}-${username}`

      incidents.push({
        id,
        username,
        startTimestamp,
        endTimestamp,
        ruleMatches: cluster,
        riskScore,
        severity,
        explanation,
        recommendedTriage,
      })
    }
  }

  // Sort incidents by startTimestamp ascending
  return incidents.sort((a, b) => a.startTimestamp.localeCompare(b.startTimestamp))
}
