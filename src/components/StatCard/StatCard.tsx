/**
 * StatCard — a dashboard metric card.
 *
 * Displays a labelled number with an optional accent colour and trend indicator.
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
  className?: string
}

export function StatCard({
  id,
  label,
  value,
  variant = 'default',
  icon,
  className = '',
}: StatCardProps) {
  return (
    <article
      id={id}
      className={`${styles.card} ${styles[variant]} ${className}`}
      aria-labelledby={`${id}-label`}
    >
      <div className={styles.header}>
        <span id={`${id}-label`} className={styles.label}>
          {label}
        </span>
        {icon && (
          <span className={styles.icon} aria-hidden="true">
            {icon}
          </span>
        )}
      </div>
      <div className={styles.value} aria-live="polite">
        {value}
      </div>
    </article>
  )
}
