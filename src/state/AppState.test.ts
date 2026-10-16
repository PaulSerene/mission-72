import { describe, it, expect } from 'vitest'
import {
  type AppState,
  type FilterState,
  type IncidentSortKey,
} from './AppState'
import type { Incident } from '@/types'

describe('AppState Reducer & Filter Logic', () => {
  const initialFilters: FilterState = {
    severity: [],
    ruleIds: [],
    username: '',
    minRiskScore: 0,
    searchText: '',
    showAcknowledged: true,
    sortBy: 'risk_desc',
  }

  const baseState: AppState = {
    status: 'idle',
    errorMessage: null,
    rawAuthCsv: undefined,
    rawAssetCsv: undefined,
    rawIpLocationCsv: undefined,
    pipelineResult: null,
    events: [],
    incidents: [],
    ruleMatches: [],
    suppressedAlerts: [],
    ingestionReport: null,
    insufficientBaselineUsers: [],
    acknowledgedIds: new Set(),
    selectedIncidentId: null,
    filters: initialFilters,
    config: null,
    lastAnalysisAt: null,
    dataSourceLabel: null,
  }

  // Create mock incidents
  const mockIncidents: Incident[] = [
    {
      id: 'inc-001',
      username: 'alice',
      severity: 'critical',
      riskScore: 90,
      startTimestamp: '2026-03-15T10:00:00Z',
      endTimestamp: '2026-03-15T10:05:00Z',
      ruleMatches: [
        {
          ruleId: 'brute_force',
          ruleName: 'Brute Force Authentication',
          severity: 'high',
          username: 'alice',
          timestamp: '2026-03-15T10:05:00Z',
          evidence: {
            description: '10 failed logins',
            eventIds: ['ev-1', 'ev-2'],
          },
        },
      ],
      explanation: 'Repeated authentication failures detected',
      recommendedTriage: 'Reset credentials and check IP blocklist',
    },
    {
      id: 'inc-002',
      username: 'bob',
      severity: 'high',
      riskScore: 70,
      startTimestamp: '2026-03-15T11:00:00Z',
      endTimestamp: '2026-03-15T11:10:00Z',
      ruleMatches: [
        {
          ruleId: 'password_spray',
          ruleName: 'Password Spraying Campaign',
          severity: 'high',
          username: 'bob',
          timestamp: '2026-03-15T11:10:00Z',
          evidence: {
            description: 'Spraying across 5 users',
            eventIds: ['ev-3'],
          },
        },
      ],
      explanation: 'Password spraying activity targeting user accounts',
      recommendedTriage: 'Inspect perimeter gateway logs',
    },
    {
      id: 'inc-003',
      username: 'charlie',
      severity: 'medium',
      riskScore: 45,
      startTimestamp: '2026-03-15T09:00:00Z',
      endTimestamp: '2026-03-15T09:02:00Z',
      ruleMatches: [
        {
          ruleId: 'unusual_hours',
          ruleName: 'Off-Hours Login Activity',
          severity: 'medium',
          username: 'charlie',
          timestamp: '2026-03-15T09:02:00Z',
          evidence: {
            description: 'Login at 3am UTC',
            eventIds: ['ev-4'],
          },
        },
      ],
      explanation: 'Account accessed outside established hours',
      recommendedTriage: 'Verify user travel or authorized shift work',
    },
  ]

  it('manages incident acknowledgement state correctly', () => {
    // Add acknowledgement
    const ackSet1 = new Set(baseState.acknowledgedIds)
    ackSet1.add('inc-001')
    expect(ackSet1.has('inc-001')).toBe(true)

    // Remove acknowledgement
    ackSet1.delete('inc-001')
    expect(ackSet1.has('inc-001')).toBe(false)
  })

  describe('Filtering incidents', () => {
    function applyFilters(incidents: Incident[], filters: FilterState, ackIds: Set<string>): Incident[] {
      return incidents.filter(incident => {
        if (filters.severity.length > 0 && !filters.severity.includes(incident.severity)) {
          return false
        }
        if (filters.ruleIds.length > 0) {
          const ruleIds = incident.ruleMatches.map(m => m.ruleId)
          if (!filters.ruleIds.some(r => ruleIds.includes(r))) return false
        }
        if (filters.username && !incident.username.toLowerCase().includes(filters.username.toLowerCase())) {
          return false
        }
        if (incident.riskScore < filters.minRiskScore) return false
        if (!filters.showAcknowledged && ackIds.has(incident.id)) return false
        if (filters.searchText) {
          const needle = filters.searchText.toLowerCase()
          const haystack = [
            incident.username,
            incident.explanation,
            incident.recommendedTriage,
            ...incident.ruleMatches.map(m => m.ruleName),
            ...incident.ruleMatches.map(m => m.evidence.description),
          ].join(' ').toLowerCase()
          if (!haystack.includes(needle)) return false
        }
        return true
      })
    }

    it('returns all incidents when no filters are set', () => {
      const res = applyFilters(mockIncidents, initialFilters, new Set())
      expect(res).toHaveLength(3)
    })

    it('filters by severity correctly', () => {
      const res = applyFilters(
        mockIncidents,
        { ...initialFilters, severity: ['critical'] },
        new Set()
      )
      expect(res).toHaveLength(1)
      expect(res[0].id).toBe('inc-001')
    })

    it('filters by multiple severities', () => {
      const res = applyFilters(
        mockIncidents,
        { ...initialFilters, severity: ['critical', 'high'] },
        new Set()
      )
      expect(res).toHaveLength(2)
      expect(res.map(i => i.id)).toEqual(['inc-001', 'inc-002'])
    })

    it('filters by rule ID', () => {
      const res = applyFilters(
        mockIncidents,
        { ...initialFilters, ruleIds: ['password_spray'] },
        new Set()
      )
      expect(res).toHaveLength(1)
      expect(res[0].id).toBe('inc-002')
    })

    it('filters by username (case-insensitive partial match)', () => {
      const res = applyFilters(
        mockIncidents,
        { ...initialFilters, username: 'ALIC' }, // matches alice case-insensitively
        new Set()
      )
      expect(res).toHaveLength(1)
      expect(res[0].id).toBe('inc-001')
    })

    it('filters by minimum risk score', () => {
      const res = applyFilters(
        mockIncidents,
        { ...initialFilters, minRiskScore: 70 },
        new Set()
      )
      expect(res).toHaveLength(2)
      expect(res.map(i => i.id)).toEqual(['inc-001', 'inc-002'])
    })

    it('filters out acknowledged incidents when showAcknowledged is false', () => {
      const ackIds = new Set(['inc-001'])
      const res = applyFilters(
        mockIncidents,
        { ...initialFilters, showAcknowledged: false },
        ackIds
      )
      expect(res).toHaveLength(2)
      expect(res.find(i => i.id === 'inc-001')).toBeUndefined()
    })

    it('filters by free search text in explanation and recommended triage', () => {
      const res1 = applyFilters(
        mockIncidents,
        { ...initialFilters, searchText: 'blocklist' },
        new Set()
      )
      expect(res1).toHaveLength(1)
      expect(res1[0].id).toBe('inc-001')

      const res2 = applyFilters(
        mockIncidents,
        { ...initialFilters, searchText: 'spraying' },
        new Set()
      )
      expect(res2).toHaveLength(1)
      expect(res2[0].id).toBe('inc-002')
    })
  })

  describe('Sorting incidents', () => {
    function sortIncidents(incidents: Incident[], sortKey: IncidentSortKey): Incident[] {
      return [...incidents].sort((a, b) => {
        const timeA = new Date(a.startTimestamp).getTime()
        const timeB = new Date(b.startTimestamp).getTime()
        switch (sortKey) {
          case 'risk_desc':
            return b.riskScore - a.riskScore || timeB - timeA
          case 'risk_asc':
            return a.riskScore - b.riskScore || timeA - timeB
          case 'time_desc':
            return timeB - timeA || b.riskScore - a.riskScore
          case 'time_asc':
            return timeA - timeB || b.riskScore - a.riskScore
          default:
            return 0
        }
      })
    }

    it('sorts by risk descending (highest risk first)', () => {
      const res = sortIncidents(mockIncidents, 'risk_desc')
      expect(res.map(i => i.riskScore)).toEqual([90, 70, 45])
    })

    it('sorts by risk ascending (lowest risk first)', () => {
      const res = sortIncidents(mockIncidents, 'risk_asc')
      expect(res.map(i => i.riskScore)).toEqual([45, 70, 90])
    })

    it('sorts by time descending (newest first)', () => {
      const res = sortIncidents(mockIncidents, 'time_desc')
      expect(res.map(i => i.id)).toEqual(['inc-002', 'inc-001', 'inc-003'])
    })

    it('sorts by time ascending (oldest first)', () => {
      const res = sortIncidents(mockIncidents, 'time_asc')
      expect(res.map(i => i.id)).toEqual(['inc-003', 'inc-001', 'inc-002'])
    })
  })
})
