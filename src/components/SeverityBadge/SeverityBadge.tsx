import type { Severity } from '@/types'
import styles from './SeverityBadge.module.css'

interface SeverityBadgeProps {
  severity: Severity
  className?: string
}

const LABELS: Record<Severity, string> = {
  critical: 'CRITICAL',
  high:     'HIGH',
  medium:   'MEDIUM',
  low:      'LOW',
  info:     'INFO',
}

/**
 * A compact badge that displays a severity level with colour coding.
 */
export function SeverityBadge({ severity, className = '' }: SeverityBadgeProps) {
  return (
    <span
      className={`${styles.badge} ${styles[severity]} ${className}`}
      aria-label={`Severity: ${severity}`}
    >
      {LABELS[severity]}
    </span>
  )
}
