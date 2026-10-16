/**
 * ExportBar — Mission 72
 *
 * Export and operational actions bar:
 * - Export Incidents CSV
 * - Export HTML Investigation Report
 * - Reload / Regenerate Synthetic Demo Data
 * - Reset Analysis state
 */

import { useAppState, useAppActions } from '@/state/AppState'
import { usePipeline } from '@/hooks/usePipeline'
import { exportIncidentsCsv, exportHtmlReport } from '@/utils/export'
import styles from './ExportBar.module.css'

export function ExportBar() {
  const { state } = useAppState()
  const { reset } = useAppActions()
  const { loadDemoData } = usePipeline()

  const {
    incidents,
    acknowledgedIds,
    ingestionReport,
    config,
    dataSourceLabel,
    lastAnalysisAt,
    insufficientBaselineUsers,
    status,
  } = state

  const hasData = incidents.length > 0 || state.events.length > 0
  const isBusy = status === 'parsing' || status === 'analyzing'

  function handleExportCsv() {
    exportIncidentsCsv(incidents, acknowledgedIds)
  }

  function handleExportHtml() {
    exportHtmlReport({
      incidents,
      acknowledgedIds,
      ingestionReport,
      config,
      dataSourceLabel,
      lastAnalysisAt,
      insufficientBaselineUsers,
    })
  }

  async function handleReloadDemo() {
    await loadDemoData()
  }

  return (
    <div className={styles.bar} role="region" aria-label="Investigation export and actions">
      <div className={styles.metaInfo}>
        <span className={styles.label}>Data Source:</span>
        <span className={styles.value}>{dataSourceLabel ?? 'None loaded'}</span>
        {lastAnalysisAt && (
          <>
            <span className={styles.divider}>•</span>
            <span className={styles.label}>Analyzed:</span>
            <time className={styles.value} dateTime={lastAnalysisAt}>
              {new Date(lastAnalysisAt).toUTCString().slice(17, 25)} UTC
            </time>
          </>
        )}
      </div>

      <div className={styles.actionButtons}>
        {/* Export CSV */}
        <button
          id="btn-export-csv"
          type="button"
          className={styles.exportBtn}
          onClick={handleExportCsv}
          disabled={!hasData || isBusy}
          title="Export detected incidents as CSV"
        >
          <svg className={styles.btnIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M12 3v12m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          Export CSV
        </button>

        {/* Export HTML Report */}
        <button
          id="btn-export-html"
          type="button"
          className={styles.exportBtn}
          onClick={handleExportHtml}
          disabled={!hasData || isBusy}
          title="Download complete SOC investigation report as self-contained HTML"
        >
          <svg className={styles.btnIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          Export HTML Report
        </button>

        {/* Reload Demo Data */}
        <button
          id="btn-reload-demo"
          type="button"
          className={styles.secondaryBtn}
          onClick={handleReloadDemo}
          disabled={isBusy}
          title="Reload fresh synthetic demo dataset"
        >
          ↻ Reload Demo
        </button>

        {/* Reset Analysis */}
        {hasData && (
          <button
            id="btn-reset-analysis"
            type="button"
            className={styles.resetBtn}
            onClick={reset}
            disabled={isBusy}
            title="Cleanly reset current analysis and clear all loaded data"
          >
            Clear / Reset
          </button>
        )}
      </div>
    </div>
  )
}
