/**
 * StatCard — a dashboard metric card.
 *
 * Displays a labelled number with an optional accent colour, icon, and subtext.
 */

import styles from './StatCard.module.css'

interface StatCardProps {
  id: string
  label: string
  value: number | string
  /** Accent colour variant */
  variant?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'accent'
  /** Optional icon (SVG element) */
  icon?: React.ReactNode
  /** Optional subtext / indicator */
  subtext?: string
  className?: string
}

export function StatCard({
  id,
  label,
  value,
  variant = 'default',
  icon,
  subtext,
  className = '',
}: StatCardProps) {
  return (
    <article
      id={id}
      className={`${styles.card} ${styles[variant]} ${className}`}
      aria-labelledby={`${id}-label`}
    >
      <div className={styles.topRow}>
        <span id={`${id}-label`} className={styles.label}>
          {label}
        </span>
        {icon && (
          <span className={styles.iconWrapper} aria-hidden="true">
            {icon}
          </span>
        )}
      </div>

      <div className={styles.valueRow}>
        <div className={styles.value} aria-live="polite">
          {value}
        </div>
      </div>

      {subtext && <div className={styles.subtext}>{subtext}</div>}
    </article>
  )
}
