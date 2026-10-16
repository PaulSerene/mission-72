/**
 * RiskBreakdown — SignalForge Heuristic Risk Decomposition
 *
 * Displays faithful, mathematically exact decomposition of an incident's risk score:
 * - Base rule weights
 * - Repetition diminishing multipliers (1.0, 0.4, 0.2)
 * - Overlap deductions (brute force + burst success on shared events)
 * - Contextual exception multipliers (VPN, maintenance window, role policy)
 * - Multi-rule synergy bonus (+15 for >= 3 distinct rules)
 * - Max cap [0, 100] boundary
 */

import { useMemo } from 'react'
import type { Incident } from '@/types'
import { decomposeIncidentRiskScore } from '@/engine/incidents'
import { SeverityBadge } from '@/components/SeverityBadge'
import styles from './Investigation.module.css'

interface RiskBreakdownProps {
  incident: Incident
  selectedRuleId?: string | null
  onSelectRule?: (ruleId: string | null) => void
}

export function RiskBreakdown({
  incident,
  selectedRuleId,
  onSelectRule,
}: RiskBreakdownProps) {
  const breakdown = useMemo(() => {
    return decomposeIncidentRiskScore(incident.ruleMatches)
  }, [incident.ruleMatches])

  const {
    finalScore,
    rawCalculatedScore,
    contributions,
    synergyBonus,
    distinctRuleCount,
    cappedAt100,
  } = breakdown

  const getMeterColor = (score: number) => {
    if (score >= 80) return 'var(--color-critical, #ef4444)'
    if (score >= 60) return 'var(--color-high, #f97316)'
    if (score >= 35) return 'var(--color-medium, #eab308)'
    return 'var(--color-low, #10b981)'
  }

  const meterColor = getMeterColor(finalScore)

  return (
    <div className={styles.card} aria-labelledby="risk-breakdown-title">
      <header className={styles.cardHeader}>
        <h3 id="risk-breakdown-title" className={styles.cardTitle}>
          <svg className={styles.cardIcon} viewBox="0 0 24 24" fill="none" width="18" height="18" aria-hidden="true">
            <path
              d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinejoin="round"
            />
          </svg>
          Heuristic Risk Breakdown &amp; Scoring Engine
        </h3>
        <SeverityBadge severity={incident.severity} />
      </header>

      {/* Score Gauge Section */}
      <section className={styles.riskMeterSection}>
        <div className={styles.riskHeaderRow}>
          <div>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Composite Risk Score
            </span>
            <div className={styles.riskScoreNumber} style={{ color: meterColor }}>
              {finalScore} <span style={{ fontSize: '1rem', color: '#64748b' }}>/ 100</span>
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
              Raw Sum: <strong style={{ color: '#f1f5f9' }}>{rawCalculatedScore}</strong>
            </span>
            {cappedAt100 && (
              <div style={{ fontSize: '0.72rem', color: '#f97316', fontWeight: 600 }}>
                Capped at 100 Maximum
              </div>
            )}
          </div>
        </div>

        <div className={styles.riskBarTrack} aria-hidden="true">
          <div
            className={styles.riskBarFill}
            style={{
              width: `${Math.min(finalScore, 100)}%`,
              backgroundColor: meterColor,
            }}
          />
        </div>
      </section>

      {/* Synergy Bonus Notice */}
      {synergyBonus > 0 && (
        <div className={styles.synergyCard}>
          <div>
            <strong style={{ color: '#60a5fa' }}>+15 Multi-Rule Synergy Bonus Applied</strong>
            <p style={{ margin: '2px 0 0 0', fontSize: '0.75rem', color: '#94a3b8' }}>
              Incident exhibits {distinctRuleCount} distinct detection rule classes simultaneously,
              indicating coordinated threat activity or multi-vector behavior.
            </p>
          </div>
          <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '1.1rem', color: '#60a5fa' }}>
            +15
          </span>
        </div>
      )}

      {/* Contributions Table */}
      <div className={styles.breakdownTableWrapper}>
        <table className={styles.breakdownTable} aria-label="Detection rule risk contributions">
          <thead>
            <tr>
              <th scope="col">Detection Rule</th>
              <th scope="col">Base Weight</th>
              <th scope="col">Repetition</th>
              <th scope="col">Context / Overlap Adjustment</th>
              <th scope="col" style={{ textAlign: 'right' }}>Contribution</th>
            </tr>
          </thead>
          <tbody>
            {contributions.map((c, idx) => {
              const isSelected = selectedRuleId === c.ruleId
              return (
                <tr
                  key={idx}
                  onClick={() => onSelectRule && onSelectRule(isSelected ? null : c.ruleId)}
                  style={{
                    cursor: onSelectRule ? 'pointer' : 'default',
                    background: isSelected ? 'rgba(59, 130, 246, 0.12)' : undefined,
                  }}
                  title={onSelectRule ? 'Click to cross-filter evidence timeline and graph' : undefined}
                >
                  <td>
                    <strong style={{ color: '#f1f5f9' }}>{c.ruleName}</strong>
                    <div style={{ fontFamily: 'monospace', fontSize: '0.72rem', color: '#60a5fa' }}>
                      [{c.ruleId}]
                    </div>
                  </td>
                  <td style={{ fontFamily: 'monospace' }}>{c.baseScore}</td>
                  <td>
                    <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
                      Occurrence #{c.repetitionCount} (×{c.repetitionMultiplier.toFixed(1)})
                    </span>
                  </td>
                  <td>
                    {c.overlapDiscounted && (
                      <div className={styles.discountPill} title={c.overlapDiscountReason}>
                        Overlap Discount (−{c.baseScore - c.rawContribution})
                      </div>
                    )}
                    {c.contextMultiplier < 1.0 && (
                      <div
                        className={styles.discountPill}
                        style={{ marginTop: c.overlapDiscounted ? '4px' : '0' }}
                        title={c.contextReason}
                      >
                        Context Adjusted (×{c.contextMultiplier.toFixed(2)})
                      </div>
                    )}
                    {!c.overlapDiscounted && c.contextMultiplier >= 1.0 && (
                      <span style={{ color: '#64748b', fontSize: '0.75rem' }}>Full Weight</span>
                    )}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <span className={styles.ruleScoreVal}>+{c.finalContribution}</span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <div style={{ fontSize: '0.73rem', color: '#64748b', fontStyle: 'italic', lineHeight: 1.4 }}>
        Note: Risk scores are bounded [0–100] heuristic indicators derived strictly from rule
        combinations and contextual adjustments. They represent relative deviation, not calibrated
        probabilities of compromise.
      </div>
    </div>
  )
}
