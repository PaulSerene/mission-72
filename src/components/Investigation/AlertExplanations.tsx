/**
 * AlertExplanations — SignalForge Evidence-Strength and Detection Explanations
 *
 * Explains triggering detection rules with:
 * - Deterministic evidence-strength label ('Strong' | 'Moderate' | 'Weak')
 * - Human-readable narrative description and observations
 * - Traceable supporting event references
 * - Contextual exception transparency
 * - Cross-filtering triggers
 */

import type { RuleMatch, AuthEvent, BaselineStatus } from '@/types'
import { evaluateEvidenceStrength } from '@/engine/investigation'
import styles from './Investigation.module.css'

interface AlertExplanationsProps {
  ruleMatches: RuleMatch[]
  events: AuthEvent[]
  selectedRuleId: string | null
  onSelectRule: (ruleId: string | null) => void
  baselineStatus?: BaselineStatus
}

export function AlertExplanations({
  ruleMatches,
  events,
  selectedRuleId,
  onSelectRule,
  baselineStatus,
}: AlertExplanationsProps) {
  return (
    <div className={styles.card} aria-labelledby="alert-explanations-title">
      <header className={styles.cardHeader}>
        <h3 id="alert-explanations-title" className={styles.cardTitle}>
          <svg className={styles.cardIcon} viewBox="0 0 24 24" fill="none" width="18" height="18" aria-hidden="true">
            <path
              d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          Alert Explanations &amp; Evidence Strength
        </h3>
        <span className={styles.cardBadge}>
          {ruleMatches.length} Triggered Rule{ruleMatches.length !== 1 ? 's' : ''}
        </span>
      </header>

      <div className={styles.rulesList}>
        {ruleMatches.map((match, idx) => {
          const isSelected = selectedRuleId === match.ruleId
          const evalResult = evaluateEvidenceStrength(match, events, baselineStatus)

          const getBadgeClass = (level: string) => {
            if (level === 'Strong') return styles.evidenceBadgeStrong
            if (level === 'Moderate') return styles.evidenceBadgeModerate
            return styles.evidenceBadgeWeak
          }

          return (
            <div
              key={idx}
              className={`${styles.ruleItem} ${isSelected ? styles.ruleItemActive : ''}`}
            >
              <div className={styles.ruleHeader}>
                <div className={styles.ruleHeaderLeft}>
                  <strong className={styles.ruleTitle}>{match.ruleName}</strong>
                  <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: '#60a5fa' }}>
                    [{match.ruleId}]
                  </span>
                  {match.mitreTactic && (
                    <span
                      style={{
                        fontSize: '0.7rem',
                        padding: '1px 6px',
                        borderRadius: '4px',
                        background: 'rgba(99, 130, 190, 0.15)',
                        color: '#94a3b8',
                        border: '1px solid rgba(99, 130, 190, 0.25)',
                      }}
                    >
                      {match.mitreTactic}
                    </span>
                  )}
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span
                    className={getBadgeClass(evalResult.level)}
                    title={`Deterministic evidence strength score: ${evalResult.score}/100`}
                  >
                    ● Evidence: {evalResult.level}
                  </span>
                </div>
              </div>

              <p className={styles.ruleDescription}>{match.evidence.description}</p>

              {/* Deterministic Evaluation Criteria */}
              <div className={styles.evidenceCriteriaList}>
                <div style={{ fontWeight: 600, color: '#cbd5e1', fontSize: '0.72rem' }}>
                  Deterministic Evidence Evaluation:
                </div>
                {evalResult.criteria.map((c, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '6px' }}>
                    <span style={{ color: '#38bdf8' }}>›</span>
                    <span>{c}</span>
                  </div>
                ))}
              </div>

              {/* Traceability & Actions */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', flexWrap: 'wrap', marginTop: '4px' }}>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                  Traceability:{' '}
                  <strong style={{ color: evalResult.allEventsResolved ? '#10b981' : '#f97316' }}>
                    {evalResult.resolvedEventCount} / {evalResult.totalEventCount} events verified
                  </strong>
                </span>

                <button
                  type="button"
                  className={styles.filterRuleBtn}
                  onClick={() => onSelectRule(isSelected ? null : match.ruleId)}
                >
                  {isSelected ? 'Clear Filter' : `Filter Timeline to Rule (${evalResult.resolvedEventCount})`}
                </button>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
