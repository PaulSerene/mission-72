/**
 * IngestionSummary — Mission 72
 *
 * Displays data-quality diagnostics from the ingestion pipeline.
 */

import type { IngestionReport } from '@/types'
import styles from './IngestionSummary.module.css'

interface IngestionSummaryProps {
  report: IngestionReport
  insufficientBaselineUsers: string[]
}

export function IngestionSummary({
  report,
  insufficientBaselineUsers = [],
}: IngestionSummaryProps) {
  const users = insufficientBaselineUsers ?? []
  const hasWarnings =
    report.invalidRows.length > 0 ||
    report.duplicateCount > 0 ||
    report.missingFields.length > 0 ||
    users.length > 0

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h3 className={styles.title}>Data Quality Report</h3>
        {hasWarnings ? (
          <span className={styles.warnBadge} aria-label={`${report.invalidRows.length + report.duplicateCount} data quality issues`}>
            ⚠ {report.invalidRows.length + report.duplicateCount} issue{(report.invalidRows.length + report.duplicateCount) !== 1 ? 's' : ''}
          </span>
        ) : (
          <span className={styles.okBadge}>✓ Clean</span>
        )}
      </div>

      <div className={styles.statsRow}>
        <Stat label="Total Rows" value={report.totalRows} />
        <Stat label="Valid Events" value={report.validEvents} accent />
        <Stat label="Rejected Rows" value={report.invalidRows.length} warn={report.invalidRows.length > 0} />
        <Stat label="Duplicates" value={report.duplicateCount} warn={report.duplicateCount > 0} />
        <Stat label="Timezone" value={report.timezone} mono />
      </div>

      {report.invalidRows.length > 0 && (
        <details className={styles.details}>
          <summary className={styles.summary}>
            {report.invalidRows.length} rejected row{report.invalidRows.length !== 1 ? 's' : ''} (click to expand)
          </summary>
          <ul className={styles.errorList}>
            {report.invalidRows.slice(0, 20).map((row) => (
              <li key={row.rowIndex} className={styles.errorItem}>
                <span className={styles.rowNum}>Row {row.rowIndex + 1}:</span>
                <span className={styles.errorReason}>{row.reason}</span>
              </li>
            ))}
            {report.invalidRows.length > 20 && (
              <li className={styles.moreItems}>…and {report.invalidRows.length - 20} more</li>
            )}
          </ul>
        </details>
      )}

      {report.missingFields.length > 0 && (
        <div className={styles.missingFields}>
          {report.missingFields.map(mf => (
            <div key={mf.field} className={styles.missingField}>
              <span className={styles.fieldName}>{mf.field}</span>
              <span className={styles.fieldCount}>absent in {mf.affectedRowCount} rows</span>
              {mf.requiredByRules.length > 0 && (
                <span className={styles.ruleImpact}>
                  Affects: {mf.requiredByRules.join(', ')}
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      {users.length > 0 && (
        <div className={styles.baselineWarning}>
          <span className={styles.baselineWarnIcon}>⚠</span>
          <span>
            <strong>{users.length}</strong> account{users.length !== 1 ? 's' : ''} had insufficient training data:{' '}
            <span className={styles.userList}>
              {users.slice(0, 8).join(', ')}
              {users.length > 8 ? ` +${users.length - 8} more` : ''}
            </span>.
            Detections for these accounts may have lower confidence.
          </span>
        </div>
      )}
    </div>
  )
}

function Stat({
  label,
  value,
  accent = false,
  warn = false,
  mono = false,
}: {
  label: string
  value: number | string
  accent?: boolean
  warn?: boolean
  mono?: boolean
}) {
  return (
    <div className={styles.stat}>
      <span className={styles.statLabel}>{label}</span>
      <span className={`${styles.statValue} ${accent ? styles.accent : ''} ${warn ? styles.warn : ''} ${mono ? styles.mono : ''}`}>
        {value}
      </span>
    </div>
  )
}
