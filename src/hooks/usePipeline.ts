/**
 * usePipeline — Mission 72
 *
 * Hook that runs the detection pipeline inside a Web Worker (via setTimeout fallback)
 * on the main thread. Reads file content, calls runDetectionPipeline, and dispatches
 * state transitions to the AppContext.
 *
 * Safe file handling: CSV is parsed in-memory via PapaParse; nothing is
 * executed or sent to external services.
 */

import { useCallback } from 'react'
import { useAppState } from '@/state/AppState'
import { runDetectionPipeline, createDefaultConfig } from '@/engine/pipeline'
import { generateSyntheticDataset } from '@/data/generate'
import type { AnalysisConfig } from '@/types'

// ─── Fixture file URLs ────────────────────────────────────────────────────────
// These are resolved from the /public directory at runtime.
const FIXTURE_PATHS = {
  authLogs: '/fixtures/auth_logs.csv',
  assets: '/fixtures/assets.csv',
  ipLocations: '/fixtures/ip_locations.csv',
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function readFileAsText(file: File): Promise<string> {
  if (typeof file.text === 'function') {
    return file.text()
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(reader.result as string)
    reader.onerror = () => reject(new Error(`Failed to read file: ${file.name}`))
    reader.readAsText(file, 'utf-8')
  })
}

async function fetchText(url: string): Promise<string | null> {
  try {
    const resp = await fetch(url)
    if (!resp.ok) return null
    return await resp.text()
  } catch {
    return null
  }
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export interface LoadFilesOptions {
  authFile: File
  assetFile?: File
  ipLocationFile?: File
  config?: Partial<AnalysisConfig>
  label?: string
}

export function usePipeline() {
  const { dispatch } = useAppState()

  /**
   * Load and analyze an uploaded authentication log CSV.
   */
  const loadFiles = useCallback(async (options: LoadFilesOptions) => {
    const { authFile, assetFile, ipLocationFile, config, label } = options
    const sourceLabel = label ?? authFile.name

    dispatch({ type: 'START_PARSING', label: sourceLabel })

    // Yield to browser to allow status re-render
    await new Promise(r => setTimeout(r, 0))

    try {
      const authData = await readFileAsText(authFile)
      const assetData = assetFile ? await readFileAsText(assetFile) : undefined
      const ipLocationData = ipLocationFile ? await readFileAsText(ipLocationFile) : undefined

      const effectiveConfig = createDefaultConfig(config)

      dispatch({ type: 'START_ANALYZING' })
      await new Promise(r => setTimeout(r, 0))

      const result = runDetectionPipeline({
        authData,
        assetData,
        ipLocationData,
        config,
      })

      if (result.events.length === 0) {
        const invalidCount = result.ingestionReport?.invalidRows.length ?? 0
        const firstReason = result.ingestionReport?.invalidRows[0]?.reason
        const detail = firstReason ? `: ${firstReason}` : ''
        throw new Error(
          `No valid authentication events found in "${sourceLabel}". ${
            invalidCount > 0
              ? `${invalidCount} invalid row(s) detected${detail}.`
              : 'The file contains no data rows.'
          } Please check CSV headers, columns, and timestamp formats.`
        )
      }

      dispatch({
        type: 'PARSE_COMPLETE',
        result,
        config: effectiveConfig,
        rawAuthCsv: authData,
        rawAssetCsv: assetData,
        rawIpLocationCsv: ipLocationData,
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      dispatch({ type: 'SET_ERROR', message: `Failed to process file: ${message}` })
    }
  }, [dispatch])

  /**
   * Load the synthetic demo dataset (generated in-memory).
   */
  const loadDemoData = useCallback(async (config?: Partial<AnalysisConfig>) => {
    dispatch({ type: 'START_PARSING', label: 'Synthetic Demo Dataset' })
    await new Promise(r => setTimeout(r, 0))

    try {
      // First try to load pre-generated fixtures from /public
      const [authCsvFetched, assetsCsvFetched, ipLocationsCsvFetched] = await Promise.all([
        fetchText(FIXTURE_PATHS.authLogs),
        fetchText(FIXTURE_PATHS.assets),
        fetchText(FIXTURE_PATHS.ipLocations),
      ])

      let authData: string
      let assetData: string | undefined
      let ipLocationData: string | undefined

      if (authCsvFetched) {
        authData = authCsvFetched
        assetData = assetsCsvFetched ?? undefined
        ipLocationData = ipLocationsCsvFetched ?? undefined
      } else {
        // Fall back to in-memory generation
        const dataset = generateSyntheticDataset(42)
        authData = dataset.authCsv
        assetData = dataset.assetsCsv
        ipLocationData = dataset.ipLocationsCsv
      }

      const effectiveConfig = createDefaultConfig(config)

      dispatch({ type: 'START_ANALYZING' })
      await new Promise(r => setTimeout(r, 0))

      const result = runDetectionPipeline({
        authData,
        assetData,
        ipLocationData,
        config,
      })

      dispatch({
        type: 'PARSE_COMPLETE',
        result,
        config: effectiveConfig,
        rawAuthCsv: authData,
        rawAssetCsv: assetData,
        rawIpLocationCsv: ipLocationData,
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      dispatch({ type: 'SET_ERROR', message: `Failed to load demo data: ${message}` })
    }
  }, [dispatch])

  /**
   * Re-run analysis against the same raw data with updated config.
   * Requires existing pipeline result to have the raw data available.
   */
  const reanalyze = useCallback(async (
    rawAuthCsv: string,
    rawAssets: string | undefined,
    rawIpLocations: string | undefined,
    config: Partial<AnalysisConfig>,
  ) => {
    dispatch({ type: 'START_ANALYZING' })
    await new Promise(r => setTimeout(r, 0))

    try {
      const effectiveConfig = createDefaultConfig(config)
      const result = runDetectionPipeline({
        authData: rawAuthCsv,
        assetData: rawAssets,
        ipLocationData: rawIpLocations,
        config,
      })
      dispatch({ type: 'ANALYSIS_COMPLETE', result })
      void effectiveConfig // keep reference
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      dispatch({ type: 'SET_ERROR', message: `Re-analysis failed: ${message}` })
    }
  }, [dispatch])

  return { loadFiles, loadDemoData, reanalyze }
}
