import { describe, it, expect } from 'vitest'
import { generateIncidentsCsv, generateHtmlReport } from './export'
import type { Incident, IngestionReport } from '@/types'

describe('Export Utilities', () => {
  const mockIncidents: Incident[] = [
    {
      id: 'inc-001',
      username: 'alice',
      severity: 'critical',
      riskScore: 95,
      startTimestamp: '2026-03-15T10:00:00Z',
      endTimestamp: '2026-03-15T10:05:00Z',
      ruleMatches: [
        {
          ruleId: 'brute_force',
          ruleName: 'Brute Force Attack',
          severity: 'critical',
          username: 'alice',
          timestamp: '2026-03-15T10:05:00Z',
          mitreTactic: 'Credential Access',
          evidence: {
            description: '10 consecutive failed logins from 198.51.100.42',
            eventIds: ['ev-1', 'ev-2'],
          },
        },
      ],
      explanation: 'Repeated authentication failures within 5 minutes',
      recommendedTriage: 'Lock account and check perimeter logs',
    },
    {
      id: 'inc-002',
      username: 'attacker,"with",commas',
      severity: 'high',
      riskScore: 75,
      startTimestamp: '2026-03-15T11:00:00Z',
      endTimestamp: '2026-03-15T11:02:00Z',
      ruleMatches: [
        {
          ruleId: 'burst_success',
          ruleName: 'Burst Failures with Success',
          severity: 'high',
          username: 'attacker,"with",commas',
          timestamp: '2026-03-15T11:02:00Z',
          evidence: {
            description: 'Burst failure pattern',
            eventIds: ['ev-3'],
          },
        },
      ],
      explanation: 'Quote test "special quotes" and commas, here',
      recommendedTriage: 'Verify IP reputation',
    },
  ]

  describe('generateIncidentsCsv', () => {
    it('generates valid CSV with correct headers and escapes fields', () => {
      const ackIds = new Set(['inc-001'])
      const csv = generateIncidentsCsv(mockIncidents, ackIds)
      const lines = csv.split('\n')

      // Check header
      expect(lines[0]).toContain('Incident ID')
      expect(lines[0]).toContain('Username')
      expect(lines[0]).toContain('Severity')
      expect(lines[0]).toContain('Risk Score')
      expect(lines[0]).toContain('Acknowledged')

      // Check first incident
      expect(lines[1]).toContain('inc-001')
      expect(lines[1]).toContain('alice')
      expect(lines[1]).toContain('critical')
      expect(lines[1]).toContain('95')
      expect(lines[1]).toContain('Yes') // acknowledged

      // Check second incident escaping commas and quotes
      expect(lines[2]).toContain('"attacker,""with"",commas"')
      expect(lines[2]).toContain('No') // not acknowledged
    })
  })

  describe('generateHtmlReport & Security Escaping', () => {
    it('escapes malicious HTML/XSS inputs in user, explanation, and triage', () => {
      const maliciousIncidents: Incident[] = [
        {
          id: 'inc-xss',
          username: '<script>alert("xss")</script>',
          severity: 'critical',
          riskScore: 88,
          startTimestamp: '2026-03-15T12:00:00Z',
          endTimestamp: '2026-03-15T12:01:00Z',
          ruleMatches: [
            {
              ruleId: '<img src=x onerror=alert(1)>',
              ruleName: '<b>Bold Rule</b>',
              severity: 'critical',
              username: '<script>alert("xss")</script>',
              timestamp: '2026-03-15T12:01:00Z',
              mitreTactic: '<i>Injected Tactic</i>',
              evidence: {
                description: '<svg onload=alert(2)>',
                eventIds: ['ev-xss'],
              },
            },
          ],
          explanation: '<iframe src="evil.com"></iframe>',
          recommendedTriage: 'javascript:void(0)',
        },
      ]

      const html = generateHtmlReport({
        incidents: maliciousIncidents,
        acknowledgedIds: new Set(),
        ingestionReport: null,
        config: null,
        dataSourceLabel: 'Test <script>',
        lastAnalysisAt: '2026-03-15T12:00:00Z',
        insufficientBaselineUsers: ['bad<user>'],
      })

      // Verify that raw script and iframe tags are NOT present unescaped
      expect(html).not.toContain('<script>alert("xss")</script>')
      expect(html).not.toContain('<iframe src="evil.com"></iframe>')
      expect(html).not.toContain('<img src=x onerror=alert(1)>')
      expect(html).not.toContain('<svg onload=alert(2)>')

      // Verify that safe escaped entities ARE present
      expect(html).toContain('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;')
      expect(html).toContain('&lt;iframe src=&quot;evil.com&quot;&gt;&lt;/iframe&gt;')
      expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
      expect(html).toContain('&lt;svg onload=alert(2)&gt;')
      expect(html).toContain('bad&lt;user&gt;')
    })

    it('includes data quality metrics, baseline coverage warnings, and limitations', () => {
      const mockIngestionReport: IngestionReport = {
        totalRows: 500,
        validEvents: 480,
        invalidRows: [
          { rowIndex: 12, reason: 'Invalid IP address', raw: {} },
        ],
        duplicateCount: 5,
        missingFields: [],
        timezone: 'UTC',
      }

      const html = generateHtmlReport({
        incidents: mockIncidents,
        acknowledgedIds: new Set(['inc-001']),
        ingestionReport: mockIngestionReport,
        config: null,
        dataSourceLabel: 'Synthetic Demo',
        lastAnalysisAt: '2026-03-15T10:00:00Z',
        insufficientBaselineUsers: ['user_limited_1', 'user_limited_2'],
      })

      // Header and summary
      expect(html).toContain('Mission 72 — Investigation Report')
      expect(html).toContain('Total Incidents')
      expect(html).toContain('Synthetic Demo')

      // Data quality
      expect(html).toContain('Total CSV Rows:')
      expect(html).toContain('500')
      expect(html).toContain('Valid Events:')
      expect(html).toContain('480')
      expect(html).toContain('Invalid / Rejected:')
      expect(html).toContain('Duplicate Records:')

      // Baseline coverage
      expect(html).toContain('Baseline Coverage Warnings')
      expect(html).toContain('user_limited_1')

      // Limitations
      expect(html).toContain('Limitations and Disclaimer')
      expect(html).toContain('All detections are heuristic anomaly signals')
    })
  })
})
