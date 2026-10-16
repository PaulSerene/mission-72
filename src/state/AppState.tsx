/**
 * Application State — Mission 72
 *
 * Central state management for the detection pipeline workflow.
 * Uses React Context + useReducer to manage:
 *   - File loading / pipeline status
 *   - Pipeline results (events, incidents, rule matches, ingestion reports)
 *   - Filter state
 *   - Acknowledged incidents
 *   - Configuration (analysis config, training period, timezone)
 */

import {
  createContext,
  useContext,
  useReducer,
  useCallback,
  type ReactNode,
} from 'react'
import type {
  Incident,
  RuleMatch,
  AnalysisConfig,
  AuthEvent,
} from '@/types'
import type { PipelineResult } from '@/engine/pipeline'
import type { IngestionReport } from '@/types'

// ─── Types ───────────────────────────────────────────────────────────────────

export type AppStatus =
  | 'idle'          // No data loaded yet
  | 'parsing'       // Parsing CSV files
  | 'analyzing'     // Running detection pipeline
  | 'done'          // Analysis complete
  | 'error'         // Fatal error

export type IncidentSortKey = 'risk_desc' | 'risk_asc' | 'time_desc' | 'time_asc'

export interface FilterState {
  severity: string[]      // e.g. ['critical', 'high']
  ruleIds: string[]       // e.g. ['brute_force']
  username: string        // partial match
  minRiskScore: number    // 0–100
  searchText: string      // full-text match
  showAcknowledged: boolean
  sortBy: IncidentSortKey
}

export interface AppState {
  status: AppStatus
  errorMessage: string | null

  // Cached raw CSV sources for rerun/reanalysis
  rawAuthCsv?: string
  rawAssetCsv?: string
  rawIpLocationCsv?: string

  // Pipeline results
  pipelineResult: PipelineResult | null
  events: AuthEvent[]
  incidents: Incident[]
  ruleMatches: RuleMatch[]
  ingestionReport: IngestionReport | null
  insufficientBaselineUsers: string[]

  // Acknowledged incidents (by ID)
  acknowledgedIds: Set<string>

  // Selected incident for detail panel
  selectedIncidentId: string | null

  // Filter state
  filters: FilterState

  // Analysis configuration
  config: AnalysisConfig | null

  // Metadata
  lastAnalysisAt: string | null
  dataSourceLabel: string | null    // e.g. "Synthetic Demo Data" or uploaded filename
}

export type AppAction =
  | { type: 'START_PARSING'; label: string }
  | {
      type: 'PARSE_COMPLETE';
      result: PipelineResult;
      config: AnalysisConfig;
      rawAuthCsv?: string;
      rawAssetCsv?: string;
      rawIpLocationCsv?: string;
    }
  | { type: 'START_ANALYZING' }
  | { type: 'ANALYSIS_COMPLETE'; result: PipelineResult }
  | { type: 'SET_ERROR'; message: string }
  | { type: 'RESET' }
  | { type: 'ACKNOWLEDGE_INCIDENT'; incidentId: string }
  | { type: 'UNACKNOWLEDGE_INCIDENT'; incidentId: string }
  | { type: 'SELECT_INCIDENT'; incidentId: string | null }
  | { type: 'SET_FILTER'; filter: Partial<FilterState> }
  | { type: 'RESET_FILTERS' }
  | { type: 'UPDATE_CONFIG'; config: Partial<AnalysisConfig> }

// ─── Initial State ────────────────────────────────────────────────────────────

const DEFAULT_FILTERS: FilterState = {
  severity: [],
  ruleIds: [],
  username: '',
  minRiskScore: 0,
  searchText: '',
  showAcknowledged: true,
  sortBy: 'risk_desc',
}

const INITIAL_STATE: AppState = {
  status: 'idle',
  errorMessage: null,
  rawAuthCsv: undefined,
  rawAssetCsv: undefined,
  rawIpLocationCsv: undefined,
  pipelineResult: null,
  events: [],
  incidents: [],
  ruleMatches: [],
  ingestionReport: null,
  insufficientBaselineUsers: [],
  acknowledgedIds: new Set(),
  selectedIncidentId: null,
  filters: DEFAULT_FILTERS,
  config: null,
  lastAnalysisAt: null,
  dataSourceLabel: null,
}

// ─── Reducer ──────────────────────────────────────────────────────────────────

function appReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case 'START_PARSING':
      return {
        ...state,
        status: 'parsing',
        errorMessage: null,
        dataSourceLabel: action.label,
        pipelineResult: null,
        events: [],
        incidents: [],
        ruleMatches: [],
        ingestionReport: null,
        selectedIncidentId: null,
      }

    case 'PARSE_COMPLETE':
      return {
        ...state,
        status: 'done',
        pipelineResult: action.result,
        events: action.result.events,
        incidents: action.result.incidents,
        ruleMatches: action.result.ruleMatches,
        ingestionReport: action.result.ingestionReport,
        insufficientBaselineUsers: action.result.insufficientBaselineUsers,
        config: action.config,
        rawAuthCsv: action.rawAuthCsv,
        rawAssetCsv: action.rawAssetCsv,
        rawIpLocationCsv: action.rawIpLocationCsv,
        lastAnalysisAt: new Date().toISOString(),
        errorMessage: null,
      }

    case 'START_ANALYZING':
      return { ...state, status: 'analyzing', errorMessage: null }

    case 'ANALYSIS_COMPLETE':
      return {
        ...state,
        status: 'done',
        pipelineResult: action.result,
        events: action.result.events,
        incidents: action.result.incidents,
        ruleMatches: action.result.ruleMatches,
        ingestionReport: action.result.ingestionReport,
        insufficientBaselineUsers: action.result.insufficientBaselineUsers,
        lastAnalysisAt: new Date().toISOString(),
        errorMessage: null,
      }

    case 'SET_ERROR':
      return { ...state, status: 'error', errorMessage: action.message }

    case 'RESET':
      return { ...INITIAL_STATE, acknowledgedIds: new Set() }

    case 'ACKNOWLEDGE_INCIDENT': {
      const next = new Set(state.acknowledgedIds)
      next.add(action.incidentId)
      return { ...state, acknowledgedIds: next }
    }

    case 'UNACKNOWLEDGE_INCIDENT': {
      const next = new Set(state.acknowledgedIds)
      next.delete(action.incidentId)
      return { ...state, acknowledgedIds: next }
    }

    case 'SELECT_INCIDENT':
      return { ...state, selectedIncidentId: action.incidentId }

    case 'SET_FILTER':
      return { ...state, filters: { ...state.filters, ...action.filter } }

    case 'RESET_FILTERS':
      return { ...state, filters: DEFAULT_FILTERS }

    case 'UPDATE_CONFIG':
      return {
        ...state,
        config: state.config ? { ...state.config, ...action.config } : null,
      }

    default:
      return state
  }
}

// ─── Context ──────────────────────────────────────────────────────────────────

interface AppContextValue {
  state: AppState
  dispatch: React.Dispatch<AppAction>
}

const AppContext = createContext<AppContextValue | null>(null)

export function AppProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(appReducer, INITIAL_STATE)
  return (
    <AppContext.Provider value={{ state, dispatch }}>
      {children}
    </AppContext.Provider>
  )
}

export function useAppState(): AppContextValue {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('useAppState must be used within AppProvider')
  return ctx
}

// ─── Derived Selectors ────────────────────────────────────────────────────────

/** Apply current filters and sorting to the full incident list. */
export function useFilteredIncidents(): Incident[] {
  const { state } = useAppState()
  const { incidents, filters, acknowledgedIds } = state

  const filtered = incidents.filter(incident => {
    // Severity filter
    if (filters.severity.length > 0 && !filters.severity.includes(incident.severity)) {
      return false
    }

    // Rule filter
    if (filters.ruleIds.length > 0) {
      const incidentRuleIds = incident.ruleMatches.map(m => m.ruleId)
      if (!filters.ruleIds.some(r => incidentRuleIds.includes(r))) return false
    }

    // Username filter
    if (filters.username && !incident.username.toLowerCase().includes(filters.username.toLowerCase())) {
      return false
    }

    // Min risk score filter
    if (incident.riskScore < filters.minRiskScore) return false

    // Acknowledged filter
    if (!filters.showAcknowledged && acknowledgedIds.has(incident.id)) return false

    // Text search
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

  // Apply sorting
  return [...filtered].sort((a, b) => {
    const timeA = new Date(a.startTimestamp).getTime()
    const timeB = new Date(b.startTimestamp).getTime()
    switch (filters.sortBy) {
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

/** Actions as convenient callbacks. */
export function useAppActions() {
  const { dispatch } = useAppState()

  const acknowledgeIncident = useCallback((id: string) => {
    dispatch({ type: 'ACKNOWLEDGE_INCIDENT', incidentId: id })
  }, [dispatch])

  const unacknowledgeIncident = useCallback((id: string) => {
    dispatch({ type: 'UNACKNOWLEDGE_INCIDENT', incidentId: id })
  }, [dispatch])

  const selectIncident = useCallback((id: string | null) => {
    dispatch({ type: 'SELECT_INCIDENT', incidentId: id })
  }, [dispatch])

  const resetFilters = useCallback(() => {
    dispatch({ type: 'RESET_FILTERS' })
  }, [dispatch])

  const reset = useCallback(() => {
    dispatch({ type: 'RESET' })
  }, [dispatch])

  return { acknowledgeIncident, unacknowledgeIncident, selectIncident, resetFilters, reset }
}
