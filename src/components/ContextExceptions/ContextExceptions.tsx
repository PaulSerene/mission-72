/**
 * ContextExceptions — Mission 72 (Mission 02)
 *
 * Displays security audit log of alert signals that were vetted against
 * declared maintenance windows and approved corporate VPN CIDR ranges,
 * and suppressed or reduced to eliminate false positives.
 */

import type { SuppressedAlert } from '@/types'
import styles from './ContextExceptions.module.css'

interface ContextExceptionsProps {
  suppressedAlerts: SuppressedAlert[]
}

export function ContextExceptions({ suppressedAlerts }: ContextExceptionsProps) {
  if (!suppressedAlerts || suppressedAlerts.length === 0) {
    return (
      <div className={styles.container}>
        <div className={styles.header}>
          <div>
            <h3 className={styles.title}>
              Context-Aware Policy Exceptions & Suppressed Signals
              <span className={styles.countBadge}>0</span>
            </h3>
            <p className={styles.subtitle}>
              No alerts were suppressed by maintenance windows or VPN policies in the current analysis.
            </p>
          </div>
        </div>
        <div className={styles.emptyState}>
          All evaluated authentication signals either triggered active alerts or fell within normal baseline activity.
        </div>
      </div>
    )
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div>
          <h3 className={styles.title}>
            Context-Aware Policy Exceptions & Suppressed Signals
            <span className={styles.countBadge}>{suppressedAlerts.length} Suppressed</span>
          </h3>
          <p className={styles.subtitle}>
            Audit log of benign operational signals suppressed to eliminate false positives while preserving evidence.
          </p>
        </div>
      </div>

      <div className={styles.tableWrapper}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Policy Domain</th>
              <th>Account</th>
              <th>Timestamp (UTC)</th>
              <th>Suppressed Rule</th>
              <th>Operational Exception Reason</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {suppressedAlerts.map(alert => (
              <tr key={alert.id}>
                <td>
                  {alert.policyType === 'approved_vpn' && (
                    <span className={styles.policyVpn}>Approved Corporate VPN</span>
                  )}
                  {alert.policyType === 'maintenance_window' && (
                    <span className={styles.policyMaint}>Maintenance Window</span>
                  )}
                  {alert.policyType === 'role_policy' && (
                    <span className={styles.policyRole}>Role Policy</span>
                  )}
                </td>
                <td className={styles.userCell}>{alert.username}</td>
                <td className={styles.timeCell}>
                  {alert.timestamp.slice(0, 19).replace('T', ' ')}Z
                </td>
                <td className={styles.ruleCell}>
                  {alert.ruleName}
                  <span className={styles.ruleId}>[{alert.ruleId}]</span>
                </td>
                <td className={styles.reasonCell}>{alert.reason}</td>
                <td>
                  <span className={styles.evidenceTag}>
                    {alert.evidence.eventIds.length} event{alert.evidence.eventIds.length !== 1 ? 's' : ''}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
