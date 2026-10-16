/**
 * IncidentFilterBar — Mission 72
 *
 * Filter and sorting controls for the incident feed:
 * - Search text
 * - Severity toggles
 * - Rule filter
 * - Username search
 * - Min risk score
 * - Show/hide acknowledged
 * - Sort options (risk asc/desc, time asc/desc)
 */

import { useAppState, type IncidentSortKey } from '@/state/AppState'
import styles from './IncidentFilterBar.module.css'

const SEVERITY_OPTIONS = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
]

const SORT_OPTIONS: { value: IncidentSortKey; label: string }[] = [
  { value: 'risk_desc', label: 'Risk: High → Low' },
  { value: 'risk_asc', label: 'Risk: Low → High' },
  { value: 'time_desc', label: 'Time: Newest First' },
  { value: 'time_asc', label: 'Time: Oldest First' },
]

export function IncidentFilterBar({
  totalCount,
  filteredCount,
}: {
  totalCount: number
  filteredCount: number
}) {
  const { state, dispatch } = useAppState()
  const { filters, ruleMatches } = state

  // Extract unique rule IDs and names present in data
  const availableRules = Array.from(
    new Map(ruleMatches.map(m => [m.ruleId, m.ruleName])).entries()
  )

  function toggleSeverity(sev: string) {
    const next = filters.severity.includes(sev)
      ? filters.severity.filter(s => s !== sev)
      : [...filters.severity, sev]
    dispatch({ type: 'SET_FILTER', filter: { severity: next } })
  }

  function handleRuleChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const val = e.target.value
    dispatch({ type: 'SET_FILTER', filter: { ruleIds: val ? [val] : [] } })
  }

  function handleSortChange(e: React.ChangeEvent<HTMLSelectElement>) {
    dispatch({
      type: 'SET_FILTER',
      filter: { sortBy: e.target.value as IncidentSortKey },
    })
  }

  const hasActiveFilters =
    filters.severity.length > 0 ||
    filters.ruleIds.length > 0 ||
    filters.username !== '' ||
    filters.minRiskScore > 0 ||
    filters.searchText !== '' ||
    !filters.showAcknowledged

  return (
    <div className={styles.filterBar} role="search" aria-label="Incident filters">
      {/* Top row: search & primary controls */}
      <div className={styles.topRow}>
        <div className={styles.searchBox}>
          <svg className={styles.searchIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle cx="11" cy="11" r="8" stroke="currentColor" strokeWidth="1.5" />
            <path d="M21 21l-4.35-4.35" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
          <input
            id="incident-search-input"
            type="search"
            className={styles.searchInput}
            placeholder="Search user, rule, explanation, triage…"
            value={filters.searchText}
            onChange={e => dispatch({ type: 'SET_FILTER', filter: { searchText: e.target.value } })}
            aria-label="Search incidents"
          />
          {filters.searchText && (
            <button
              type="button"
              className={styles.clearSearchBtn}
              onClick={() => dispatch({ type: 'SET_FILTER', filter: { searchText: '' } })}
              aria-label="Clear search"
            >
              ×
            </button>
          )}
        </div>

        {/* Sort Select */}
        <div className={styles.sortGroup}>
          <label htmlFor="incident-sort-select" className={styles.sortLabel}>
            Sort:
          </label>
          <select
            id="incident-sort-select"
            className={styles.selectInput}
            value={filters.sortBy}
            onChange={handleSortChange}
            aria-label="Sort incidents"
          >
            {SORT_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Second row: filter chips & controls */}
      <div className={styles.bottomRow}>
        {/* Severity toggles */}
        <div className={styles.severityGroup} role="group" aria-label="Filter by severity">
          <span className={styles.filterGroupLabel}>Severity:</span>
          {SEVERITY_OPTIONS.map(opt => {
            const isActive = filters.severity.includes(opt.value)
            return (
              <button
                key={opt.value}
                type="button"
                className={`${styles.severityChip} ${styles[opt.value]} ${isActive ? styles.activeChip : ''}`}
                onClick={() => toggleSeverity(opt.value)}
                aria-pressed={isActive}
              >
                {opt.label}
              </button>
            )
          })}
        </div>

        {/* Rule selector */}
        {availableRules.length > 0 && (
          <div className={styles.filterGroup}>
            <label htmlFor="incident-rule-select" className={styles.filterGroupLabel}>
              Rule:
            </label>
            <select
              id="incident-rule-select"
              className={styles.selectInput}
              value={filters.ruleIds[0] ?? ''}
              onChange={handleRuleChange}
              aria-label="Filter by rule"
            >
              <option value="">All Rules ({availableRules.length})</option>
              {availableRules.map(([id, name]) => (
                <option key={id} value={id}>
                  {name}
                </option>
              ))}
            </select>
          </div>
        )}

        {/* Min Risk Score slider / input */}
        <div className={styles.filterGroup}>
          <label htmlFor="incident-min-risk" className={styles.filterGroupLabel}>
            Min Risk: <strong>{filters.minRiskScore}</strong>
          </label>
          <input
            id="incident-min-risk"
            type="range"
            min="0"
            max="100"
            step="5"
            className={styles.rangeInput}
            value={filters.minRiskScore}
            onChange={e =>
              dispatch({
                type: 'SET_FILTER',
                filter: { minRiskScore: Number(e.target.value) },
              })
            }
            aria-label="Minimum risk score"
          />
        </div>

        {/* Show Acknowledged Checkbox */}
        <label className={styles.checkboxLabel}>
          <input
            id="show-acknowledged-check"
            type="checkbox"
            checked={filters.showAcknowledged}
            onChange={e =>
              dispatch({
                type: 'SET_FILTER',
                filter: { showAcknowledged: e.target.checked },
              })
            }
          />
          <span>Show Acknowledged</span>
        </label>

        {/* Reset button & count badge */}
        <div className={styles.countAndReset}>
          <span className={styles.countBadge}>
            Showing {filteredCount} of {totalCount}
          </span>
          {hasActiveFilters && (
            <button
              id="btn-reset-filters"
              type="button"
              className={styles.resetBtn}
              onClick={() => dispatch({ type: 'RESET_FILTERS' })}
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
