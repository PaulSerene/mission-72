/**
 * Visualizations — Mission 72
 *
 * Real-data visualizations derived dynamically from current pipeline results:
 * 1. Incidents by Severity (segmented breakdown)
 * 2. Incident Counts Over Time (temporal distribution histogram)
 * 3. Top Affected Accounts (ranked horizontal bars)
 * 4. Most Frequently Triggered Rules (rule match breakdown)
 * 5. 24-Hour Login Activity (success vs failure distribution by UTC hour)
 */

import { useMemo } from 'react'
import type { Incident, AuthEvent, RuleMatch } from '@/types'
import styles from './Visualizations.module.css'

interface VisualizationsProps {
  incidents: Incident[]
  events: AuthEvent[]
  ruleMatches: RuleMatch[]
}

const SEVERITY_CONFIG = [
  { key: 'critical', label: 'Critical', color: 'var(--color-critical)' },
  { key: 'high',     label: 'High',     color: 'var(--color-high)' },
  { key: 'medium',   label: 'Medium',   color: 'var(--color-medium)' },
  { key: 'low',      label: 'Low',      color: 'var(--color-low)' },
] as const

export function Visualizations({ incidents, events, ruleMatches }: VisualizationsProps) {
  // 1. Severity Distribution
  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const inc of incidents) {
      if (inc.severity in counts) {
        counts[inc.severity as keyof typeof counts]++
      }
    }
    return counts
  }, [incidents])

  // 2. Top Affected Accounts
  const topAccounts = useMemo(() => {
    const map = new Map<string, { count: number; maxRisk: number; severity: string }>()
    for (const inc of incidents) {
      const existing = map.get(inc.username) ?? { count: 0, maxRisk: 0, severity: inc.severity }
      existing.count++
      if (inc.riskScore > existing.maxRisk) {
        existing.maxRisk = inc.riskScore
        existing.severity = inc.severity
      }
      map.set(inc.username, existing)
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1].count - a[1].count || b[1].maxRisk - a[1].maxRisk)
      .slice(0, 5)
  }, [incidents])

  // 3. Most Frequently Triggered Rules
  const topRules = useMemo(() => {
    const map = new Map<string, { name: string; count: number }>()
    for (const rm of ruleMatches) {
      const existing = map.get(rm.ruleId) ?? { name: rm.ruleName, count: 0 }
      existing.count++
      map.set(rm.ruleId, existing)
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 6)
  }, [ruleMatches])

  // 4. 24-Hour Login Activity (from AuthEvents)
  const hourlyActivity = useMemo(() => {
    const hours = Array.from({ length: 24 }, (_, i) => ({
      hour: i,
      success: 0,
      failure: 0,
    }))
    for (const ev of events) {
      try {
        const d = new Date(ev.timestamp)
        const h = d.getUTCHours()
        if (h >= 0 && h < 24) {
          if (ev.outcome === 'success') hours[h].success++
          else hours[h].failure++
        }
      } catch {
        // ignore malformed timestamp
      }
    }
    return hours
  }, [events])

  const maxHourlyTotal = useMemo(() => {
    let max = 1
    for (const h of hourlyActivity) {
      const tot = h.success + h.failure
      if (tot > max) max = tot
    }
    return max
  }, [hourlyActivity])

  // 5. Incident Counts Over Time (Buckets)
  const timelineBuckets = useMemo(() => {
    if (incidents.length === 0) return []
    const timestamps = incidents.map(i => new Date(i.startTimestamp).getTime())
    const minTime = Math.min(...timestamps)
    const maxTime = Math.max(...timestamps)
    const diff = Math.max(maxTime - minTime, 3600_000) // minimum 1 hr range
    const bucketCount = 6
    const step = diff / bucketCount

    const buckets = Array.from({ length: bucketCount }, (_, i) => {
      const bStart = minTime + i * step
      const bEnd = bStart + step
      const count = incidents.filter(inc => {
        const t = new Date(inc.startTimestamp).getTime()
        return t >= bStart && (i === bucketCount - 1 ? t <= bEnd : t < bEnd)
      }).length
      const d = new Date(bStart)
      const label = `${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}`
      return { label, count }
    })
    return buckets
  }, [incidents])

  const maxTimelineCount = useMemo(() => {
    return Math.max(1, ...timelineBuckets.map(b => b.count))
  }, [timelineBuckets])

  if (incidents.length === 0 && events.length === 0) {
    return (
      <div className={styles.emptyState}>
        <p>No activity data available to visualize. Load a log file or demo data to view analytics.</p>
      </div>
    )
  }

  const totalIncidents = incidents.length

  return (
    <div className={styles.container}>
      {/* ── Grid of Visualizations ──────────────────────────── */}
      <div className={styles.vizGrid}>
        {/* Card 1: Severity Distribution */}
        <section className={styles.card} aria-labelledby="viz-severity-title">
          <h3 id="viz-severity-title" className={styles.cardTitle}>
            Incidents by Severity
          </h3>
          <div className={styles.severityBarWrapper}>
            <div className={styles.severityBarTrack}>
              {SEVERITY_CONFIG.map(sc => {
                const count = severityCounts[sc.key]
                const pct = totalIncidents > 0 ? (count / totalIncidents) * 100 : 0
                if (pct === 0) return null
                return (
                  <div
                    key={sc.key}
                    className={styles.severityBarSegment}
                    style={{
                      width: `${pct}%`,
                      backgroundColor: sc.color,
                    }}
                    title={`${sc.label}: ${count} (${Math.round(pct)}%)`}
                    aria-label={`${sc.label}: ${count}`}
                  />
                )
              })}
            </div>
            <div className={styles.severityLegend}>
              {SEVERITY_CONFIG.map(sc => {
                const count = severityCounts[sc.key]
                const pct = totalIncidents > 0 ? Math.round((count / totalIncidents) * 100) : 0
                return (
                  <div key={sc.key} className={styles.legendItem}>
                    <span className={styles.legendDot} style={{ backgroundColor: sc.color }} />
                    <span className={styles.legendLabel}>{sc.label}</span>
                    <strong className={styles.legendVal}>{count}</strong>
                    <span className={styles.legendPct}>({pct}%)</span>
                  </div>
                )
              })}
            </div>
          </div>
        </section>

        {/* Card 2: Top Affected Accounts */}
        <section className={styles.card} aria-labelledby="viz-accounts-title">
          <h3 id="viz-accounts-title" className={styles.cardTitle}>
            Top Affected Accounts
          </h3>
          {topAccounts.length === 0 ? (
            <p className={styles.emptyCardText}>No affected accounts recorded.</p>
          ) : (
            <div className={styles.horizontalBarList}>
              {topAccounts.map(([user, data]) => {
                const maxCount = topAccounts[0][1].count
                const barWidth = (data.count / maxCount) * 100
                return (
                  <div key={user} className={styles.hbarItem}>
                    <div className={styles.hbarLabels}>
                      <span className={styles.hbarUser}>{user}</span>
                      <span className={styles.hbarMeta}>
                        {data.count} incident{data.count !== 1 ? 's' : ''} · Max Risk {data.maxRisk}
                      </span>
                    </div>
                    <div className={styles.hbarTrack}>
                      <div
                        className={styles.hbarFill}
                        style={{
                          width: `${barWidth}%`,
                          backgroundColor:
                            data.maxRisk >= 85
                              ? 'var(--color-critical)'
                              : data.maxRisk >= 65
                              ? 'var(--color-high)'
                              : 'var(--color-accent)',
                        }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </section>

        {/* Card 3: Frequently Triggered Rules */}
        <section className={styles.card} aria-labelledby="viz-rules-title">
          <h3 id="viz-rules-title" className={styles.cardTitle}>
            Most Triggered Rules
          </h3>
          {topRules.length === 0 ? (
            <p className={styles.emptyCardText}>No rule matches recorded.</p>
          ) : (
            <div className={styles.horizontalBarList}>
              {topRules.map(([ruleId, data]) => {
                const maxCount = topRules[0][1].count
                const barWidth = (data.count / maxCount) * 100
                return (
                  <div key={ruleId} className={styles.hbarItem}>
                    <div className={styles.hbarLabels}>
                      <span className={styles.hbarUser} title={data.name}>
                        {data.name}
                      </span>
                      <span className={styles.hbarMeta}>{data.count} hits</span>
                    </div>
                    <div className={styles.hbarTrack}>
                      <div
                        className={styles.hbarFill}
                        style={{
                          width: `${barWidth}%`,
                          backgroundColor: 'var(--color-accent)',
                        }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </section>

        {/* Card 4: Incident Timeline */}
        <section className={styles.card} aria-labelledby="viz-timeline-title">
          <h3 id="viz-timeline-title" className={styles.cardTitle}>
            Incident Timeline Distribution
          </h3>
          {timelineBuckets.length === 0 ? (
            <p className={styles.emptyCardText}>No incident timeline data.</p>
          ) : (
            <div className={styles.timelineWrapper}>
              <div className={styles.timelineBars}>
                {timelineBuckets.map((b, idx) => {
                  const hPct = (b.count / maxTimelineCount) * 100
                  return (
                    <div key={idx} className={styles.timelineCol} title={`${b.label} UTC: ${b.count} incidents`}>
                      <span className={styles.barCount}>{b.count > 0 ? b.count : ''}</span>
                      <div className={styles.vbarTrack}>
                        <div
                          className={styles.vbarFill}
                          style={{
                            height: `${Math.max(hPct, b.count > 0 ? 8 : 0)}%`,
                            backgroundColor: 'var(--color-critical)',
                          }}
                        />
                      </div>
                      <span className={styles.barLabel}>{b.label}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </section>
      </div>

      {/* Card 5: 24-Hour Authentication Activity (Success vs Failure) */}
      {events.length > 0 && (
        <section className={styles.cardWide} aria-labelledby="viz-activity-title">
          <div className={styles.wideHeader}>
            <h3 id="viz-activity-title" className={styles.cardTitle}>
              Authentication Activity by UTC Hour (24h Pattern)
            </h3>
            <div className={styles.activityLegend}>
              <span className={styles.actSuccessDot} /> Successful Logins
              <span className={styles.actFailureDot} /> Failed Logins
            </div>
          </div>
          <div className={styles.hourlyChart}>
            {hourlyActivity.map(h => {
              const total = h.success + h.failure
              const totalPct = maxHourlyTotal > 0 ? (total / maxHourlyTotal) * 100 : 0
              const failPctOfBar = total > 0 ? (h.failure / total) * 100 : 0
              const succPctOfBar = 100 - failPctOfBar

              return (
                <div
                  key={h.hour}
                  className={styles.hourlyCol}
                  title={`${String(h.hour).padStart(2, '0')}:00 UTC — Success: ${h.success}, Failure: ${h.failure}`}
                >
                  <div className={styles.hourlyTrack}>
                    {total > 0 && (
                      <div
                        className={styles.hourlyStack}
                        style={{ height: `${Math.max(totalPct, 6)}%` }}
                      >
                        <div
                          className={styles.hourlyFailFill}
                          style={{ height: `${failPctOfBar}%` }}
                        />
                        <div
                          className={styles.hourlySuccFill}
                          style={{ height: `${succPctOfBar}%` }}
                        />
                      </div>
                    )}
                  </div>
                  <span className={styles.hourlyLabel}>
                    {h.hour % 3 === 0 ? `${h.hour}h` : ''}
                  </span>
                </div>
              )
            })}
          </div>
        </section>
      )}
    </div>
  )
}
