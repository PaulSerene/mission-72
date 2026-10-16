/**
 * Export utilities — Mission 72
 *
 * Safe, client-side only exports:
 * - CSV of incident list
 * - HTML investigation report
 *
 * No external requests. All user-supplied text is HTML-escaped in the report.
 */

import type { Incident, AnalysisConfig, RuleMatch } from '@/types'
import type { IngestionReport } from '@/types'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.style.display = 'none'
  document.body.appendChild(a)
  a.click()
  setTimeout(() => {
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }, 300)
}

function csvEscape(value: string | number): string {
  const str = String(value)
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

// ─── CSV Export ───────────────────────────────────────────────────────────────

export function generateIncidentsCsv(
  incidents: Incident[],
  acknowledgedIds: Set<string>,
): string {
  const headers = [
    'Incident ID',
    'Username',
    'Severity',
    'Risk Score',
    'Start Time (UTC)',
    'End Time (UTC)',
    'Rules Triggered',
    'Evidence Event Count',
    'Explanation',
    'Recommended Triage',
    'Acknowledged',
  ]

  const rows = incidents.map(inc => [
    csvEscape(inc.id),
    csvEscape(inc.username),
    csvEscape(inc.severity),
    csvEscape(inc.riskScore),
    csvEscape(inc.startTimestamp),
    csvEscape(inc.endTimestamp),
    csvEscape([...new Set(inc.ruleMatches.map(m => m.ruleName))].join('; ')),
    csvEscape(inc.ruleMatches.reduce((sum, m) => sum + m.evidence.eventIds.length, 0)),
    csvEscape(inc.explanation),
    csvEscape(inc.recommendedTriage),
    csvEscape(acknowledgedIds.has(inc.id) ? 'Yes' : 'No'),
  ])

  return [
    headers.map(csvEscape).join(','),
    ...rows.map(row => row.join(',')),
  ].join('\n')
}

export function exportIncidentsCsv(
  incidents: Incident[],
  acknowledgedIds: Set<string>,
  filename = 'mission72-incidents.csv',
): void {
  const csv = generateIncidentsCsv(incidents, acknowledgedIds)
  downloadBlob(new Blob([csv], { type: 'text/csv;charset=utf-8;' }), filename)
}

// ─── HTML Report Export ───────────────────────────────────────────────────────

interface ReportOptions {
  incidents: Incident[]
  acknowledgedIds: Set<string>
  ingestionReport: IngestionReport | null
  config: AnalysisConfig | null
  dataSourceLabel: string | null
  lastAnalysisAt: string | null
  insufficientBaselineUsers: string[]
  filename?: string
}

function renderRuleMatch(m: RuleMatch): string {
  const eventCount = m.evidence.eventIds.length
  return `
    <div class="rule-match">
      <span class="rule-name">${escapeHtml(m.ruleName)}</span>
      <span class="rule-id">[${escapeHtml(m.ruleId)}]</span>
      ${m.mitreTactic ? `<span class="mitre">${escapeHtml(m.mitreTactic)}</span>` : ''}
      <span class="evidence-count">${eventCount} event${eventCount !== 1 ? 's' : ''}</span>
      <div class="evidence-desc">${escapeHtml(m.evidence.description)}</div>
    </div>
  `
}

function renderIncident(inc: Incident, index: number, acknowledgedIds: Set<string>): string {
  const isAcknowledged = acknowledgedIds.has(inc.id)
  const distinctRules = [...new Set(inc.ruleMatches.map(m => m.ruleName))]
  const totalEvents = inc.ruleMatches.reduce((s, m) => s + m.evidence.eventIds.length, 0)
  const startDate = new Date(inc.startTimestamp)
  const endDate = new Date(inc.endTimestamp)

  return `
    <div class="incident severity-${escapeHtml(inc.severity)}${isAcknowledged ? ' acknowledged' : ''}">
      <div class="incident-header">
        <span class="incident-num">#${index + 1}</span>
        <span class="severity-badge severity-${escapeHtml(inc.severity)}">${escapeHtml(inc.severity.toUpperCase())}</span>
        <span class="incident-user">${escapeHtml(inc.username)}</span>
        <span class="risk-score">Risk: <strong>${inc.riskScore}/100</strong></span>
        ${isAcknowledged ? '<span class="ack-badge">ACKNOWLEDGED</span>' : ''}
      </div>

      <div class="incident-id"><code>${escapeHtml(inc.id)}</code></div>

      <div class="incident-meta">
        <span>Start: ${startDate.toUTCString()}</span>
        <span>End: ${endDate.toUTCString()}</span>
        <span>Rules: ${escapeHtml(distinctRules.join(', '))}</span>
        <span>Total events: ${totalEvents}</span>
      </div>

      <div class="explanation">
        <h4>Explanation</h4>
        <p>${escapeHtml(inc.explanation)}</p>
      </div>

      <div class="triage">
        <h4>Recommended Triage</h4>
        <p>${escapeHtml(inc.recommendedTriage)}</p>
      </div>

      <div class="rules-section">
        <h4>Fired Rules (${inc.ruleMatches.length})</h4>
        ${inc.ruleMatches.map(renderRuleMatch).join('')}
      </div>

      <div class="disclaimer">
        ⚠ Anomaly signal only — not proof of compromise. Verify with additional evidence before action.
      </div>
    </div>
  `
}

export function generateHtmlReport(options: Omit<ReportOptions, 'filename'>): string {
  const {
    incidents,
    acknowledgedIds,
    ingestionReport,
    config,
    dataSourceLabel,
    lastAnalysisAt,
    insufficientBaselineUsers,
  } = options

  const generatedAt = new Date().toUTCString()
  const criticalCount = incidents.filter(i => i.severity === 'critical').length
  const highCount = incidents.filter(i => i.severity === 'high').length
  const mediumCount = incidents.filter(i => i.severity === 'medium').length
  const lowCount = incidents.filter(i => i.severity === 'low').length
  const ackCount = incidents.filter(i => acknowledgedIds.has(i.id)).length

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mission 72 — Investigation Report</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', system-ui, sans-serif; font-size: 14px; line-height: 1.6;
           background: #040d1a; color: #e2eaf6; padding: 2rem; }
    h1 { font-size: 1.5rem; color: #00d4ff; margin-bottom: 0.5rem; }
    h2 { font-size: 1.1rem; color: #7a9fc0; margin: 2rem 0 1rem; border-bottom: 1px solid #1a3154; padding-bottom: 0.5rem; }
    h3 { font-size: 1rem; color: #e2eaf6; }
    h4 { font-size: 0.875rem; color: #7a9fc0; margin: 0.75rem 0 0.25rem; }
    p { font-size: 0.875rem; color: #b0c8e0; margin: 0.25rem 0; }
    code { font-family: 'JetBrains Mono', monospace; font-size: 0.8em; background: #0b1c38; padding: 0.1em 0.3em; border-radius: 3px; }
    .meta { color: #7a9fc0; font-size: 0.8rem; margin-bottom: 0.25rem; }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin: 1rem 0; }
    .stat-card { background: #0b1c38; border: 1px solid #1a3154; border-radius: 8px; padding: 1rem; text-align: center; }
    .stat-value { font-size: 1.75rem; font-weight: 700; }
    .stat-label { font-size: 0.75rem; color: #7a9fc0; text-transform: uppercase; letter-spacing: 0.05em; }
    .critical { color: #ff3b6b; } .high { color: #ff7043; } .medium { color: #ffd740; } .low { color: #69f0ae; } .accent { color: #00d4ff; }
    .incident { background: #0b1c38; border: 1px solid #1a3154; border-radius: 8px; padding: 1.25rem; margin: 1rem 0; }
    .incident.severity-critical { border-color: rgba(255,59,107,0.4); }
    .incident.severity-high { border-color: rgba(255,112,67,0.4); }
    .incident.severity-medium { border-color: rgba(255,215,64,0.3); }
    .incident.acknowledged { opacity: 0.6; }
    .incident-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; flex-wrap: wrap; }
    .incident-num { color: #7a9fc0; font-family: monospace; }
    .severity-badge { font-size: 0.7rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 4px; letter-spacing: 0.1em; }
    .severity-badge.severity-critical { background: rgba(255,59,107,0.15); color: #ff3b6b; border: 1px solid #ff3b6b; }
    .severity-badge.severity-high { background: rgba(255,112,67,0.15); color: #ff7043; border: 1px solid #ff7043; }
    .severity-badge.severity-medium { background: rgba(255,215,64,0.12); color: #ffd740; border: 1px solid #ffd740; }
    .severity-badge.severity-low { background: rgba(105,240,174,0.12); color: #69f0ae; border: 1px solid #69f0ae; }
    .incident-user { font-weight: 600; }
    .risk-score { font-size: 0.875rem; color: #7a9fc0; }
    .ack-badge { font-size: 0.7rem; background: rgba(0,212,255,0.1); color: #00d4ff; border: 1px solid #00d4ff; padding: 0.1rem 0.4rem; border-radius: 4px; }
    .incident-id { font-size: 0.75rem; color: #3d5a7a; margin-bottom: 0.5rem; }
    .incident-meta { font-size: 0.75rem; color: #7a9fc0; margin-bottom: 0.75rem; display: flex; gap: 1rem; flex-wrap: wrap; }
    .explanation, .triage { background: rgba(255,255,255,0.03); border-radius: 4px; padding: 0.75rem; margin: 0.5rem 0; }
    .rule-match { background: rgba(0,0,0,0.2); border-radius: 4px; padding: 0.5rem 0.75rem; margin: 0.25rem 0; }
    .rule-name { font-weight: 600; color: #e2eaf6; margin-right: 0.5rem; }
    .rule-id { font-family: monospace; font-size: 0.75rem; color: #7a9fc0; margin-right: 0.5rem; }
    .mitre { font-size: 0.7rem; color: #ffd740; background: rgba(255,215,64,0.1); padding: 0.1rem 0.4rem; border-radius: 3px; margin-right: 0.5rem; }
    .evidence-count { font-size: 0.75rem; color: #7a9fc0; }
    .evidence-desc { font-size: 0.8rem; color: #b0c8e0; margin-top: 0.25rem; }
    .rules-section { margin-top: 0.75rem; }
    .disclaimer { font-size: 0.75rem; color: #ffd740; margin-top: 0.75rem; padding: 0.5rem; background: rgba(255,215,64,0.05); border-radius: 4px; }
    .config-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem 2rem; margin: 0.5rem 0; font-size: 0.875rem; }
    .config-key { color: #7a9fc0; }
    .warning-banner { background: rgba(255,215,64,0.1); border: 1px solid rgba(255,215,64,0.3); border-radius: 6px; padding: 0.75rem; margin: 1rem 0; font-size: 0.8rem; color: #ffd740; }
    @media print { body { background: white; color: black; } }
  </style>
</head>
<body>
  <h1>🔒 Mission 72 — Investigation Report</h1>
  <p class="meta">Generated: ${escapeHtml(generatedAt)}</p>
  <p class="meta">Data Source: ${escapeHtml(dataSourceLabel ?? 'Unknown')}</p>
  ${lastAnalysisAt ? `<p class="meta">Last Analysis: ${escapeHtml(new Date(lastAnalysisAt).toUTCString())}</p>` : ''}

  <div class="warning-banner">
    ⚠ <strong>This report contains heuristic anomaly signals only.</strong>
    Detections are based on behavioral baselines and configurable thresholds.
    No detection automatically proves malicious activity. All findings require
    manual verification with additional evidence before any remediation action.
  </div>

  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="stat-card"><div class="stat-value accent">${incidents.length}</div><div class="stat-label">Total Incidents</div></div>
    <div class="stat-card"><div class="stat-value critical">${criticalCount}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card"><div class="stat-value high">${highCount}</div><div class="stat-label">High</div></div>
    <div class="stat-card"><div class="stat-value medium">${mediumCount}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card"><div class="stat-value low">${lowCount}</div><div class="stat-label">Low</div></div>
    <div class="stat-card"><div class="stat-value accent">${ackCount}</div><div class="stat-label">Acknowledged</div></div>
  </div>

  ${ingestionReport ? `
  <h2>Data Quality</h2>
  <div class="config-grid">
    <span class="config-key">Total CSV Rows:</span><span>${ingestionReport.totalRows}</span>
    <span class="config-key">Valid Events:</span><span>${ingestionReport.validEvents}</span>
    <span class="config-key">Invalid / Rejected:</span><span>${ingestionReport.invalidRows.length}</span>
    <span class="config-key">Duplicate Records:</span><span>${ingestionReport.duplicateCount}</span>
    <span class="config-key">Source Timezone:</span><span>${escapeHtml(ingestionReport.timezone)}</span>
  </div>
  ${ingestionReport.invalidRows.length > 0 ? `
  <p style="font-size:0.8rem;color:#ffd740;margin-top:0.5rem;">
    ${ingestionReport.invalidRows.length} row(s) were rejected during ingestion.
    Common causes: missing required fields, malformed timestamps, or invalid IP addresses.
  </p>` : ''}
  ` : ''}

  ${insufficientBaselineUsers.length > 0 ? `
  <h2>Baseline Coverage Warnings</h2>
  <p style="font-size:0.875rem;color:#ffd740;">
    The following ${insufficientBaselineUsers.length} account(s) had insufficient training data.
    Alerts for these accounts may have lower confidence:
  </p>
  <p style="font-family:monospace;font-size:0.8rem;color:#7a9fc0;">${escapeHtml(insufficientBaselineUsers.join(', '))}</p>
  ` : ''}

  ${config ? `
  <h2>Analysis Configuration</h2>
  <div class="config-grid">
    <span class="config-key">Timezone:</span><span>${escapeHtml(config.timezone)}</span>
    <span class="config-key">Training Period:</span><span>${escapeHtml(config.trainingPeriod.start)} — ${escapeHtml(config.trainingPeriod.end)}</span>
    <span class="config-key">Analysis Period:</span><span>${escapeHtml(config.analysisPeriod.start)} — ${escapeHtml(config.analysisPeriod.end)}</span>
    <span class="config-key">Brute Force Threshold:</span><span>${config.rules.bruteForce.failureCount} failures / ${config.rules.bruteForce.windowSeconds}s</span>
    <span class="config-key">Burst Success Threshold:</span><span>${config.rules.burstSuccess.failureCount} failures / ${config.rules.burstSuccess.windowSeconds}s</span>
    <span class="config-key">Password Spray Threshold:</span><span>${config.rules.passwordSpray.userCount} users / ${config.rules.passwordSpray.windowSeconds}s</span>
    <span class="config-key">Off-Hours Window:</span><span>${config.rules.unusualHours.offHoursStart}:00–${config.rules.unusualHours.offHoursEnd}:00 UTC</span>
    <span class="config-key">New Host Threshold:</span><span>${config.rules.newHosts.newHostCount} hosts / ${config.rules.newHosts.windowHours}h</span>
  </div>
  ` : ''}

  <h2>Incidents (${incidents.length})</h2>
  ${incidents.length === 0
    ? '<p>No incidents detected in the analysis period.</p>'
    : incidents.map((inc, i) => renderIncident(inc, i, acknowledgedIds)).join('\n')
  }

  <h2>Limitations and Disclaimer</h2>
  <ul style="margin: 0.5rem 0 0 1rem; font-size:0.875rem; color:#b0c8e0;">
    <li>All detections are heuristic anomaly signals based on behavioral baselines, not ground truth.</li>
    <li>A missing or limited baseline reduces detection confidence and may increase false positives.</li>
    <li>IPv6 source addresses are not supported in IP-location enrichment.</li>
    <li>Approved VPN suppression and maintenance window suppression depend on the accuracy of the supplied configuration.</li>
    <li>Risk scores are additive heuristics bounded to [0, 100] and are not probabilities of compromise.</li>
    <li>This report was generated offline and has not been reviewed by a human analyst.</li>
  </ul>
</body>
</html>`
}

export function exportHtmlReport(options: ReportOptions): void {
  const html = generateHtmlReport(options)
  downloadBlob(
    new Blob([html], { type: 'text/html;charset=utf-8;' }),
    options.filename ?? 'mission72-investigation-report.html',
  )
}
