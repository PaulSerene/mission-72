/**
 * LoadDataPanel — Mission 72
 *
 * File upload and demo data loading interface.
 */

import { useState, useRef, type ChangeEvent } from 'react'
import { usePipeline } from '@/hooks/usePipeline'
import { useAppState } from '@/state/AppState'
import styles from './LoadDataPanel.module.css'

export function LoadDataPanel() {
  const { state } = useAppState()
  const { loadFiles, loadDemoData } = usePipeline()
  const [dragOver, setDragOver] = useState(false)
  const [authFile, setAuthFile] = useState<File | null>(null)
  const [assetFile, setAssetFile] = useState<File | null>(null)
  const [ipFile, setIpFile] = useState<File | null>(null)
  const [timezone, setTimezone] = useState('UTC')
  const [tzOverridden, setTzOverridden] = useState(false)
  const authRef = useRef<HTMLInputElement>(null)
  const assetRef = useRef<HTMLInputElement>(null)
  const ipRef = useRef<HTMLInputElement>(null)

  const isLoading = state.status === 'parsing' || state.status === 'analyzing'

  function handleAuthFile(files: FileList | null) {
    if (files && files[0]) {
      const file = files[0]
      setAuthFile(file)
      if (!tzOverridden) {
        if (
          file.name.includes('_A.') ||
          file.name.includes('_B.') ||
          file.name.includes('mission0') ||
          file.name.includes('TC')
        ) {
          setTimezone('Asia/Kolkata')
        }
      }
    }
  }

  function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setDragOver(false)
    handleAuthFile(e.dataTransfer.files)
  }

  async function handleRun() {
    if (!authFile) return
    await loadFiles({
      authFile,
      assetFile: assetFile ?? undefined,
      ipLocationFile: ipFile ?? undefined,
      config: tzOverridden ? { timezone } : undefined,
      label: authFile.name,
    })
  }

  async function handleDemoData() {
    await loadDemoData({ timezone })
  }

  return (
    <div className={styles.panel}>
      <div className={styles.panelHeader}>
        <h2 className={styles.panelTitle}>Load Data</h2>
        <span className={styles.panelBadge}>Step 1</span>
      </div>

      {/* Demo Data Button */}
      <button
        id="btn-load-demo"
        className={styles.demoBtn}
        onClick={handleDemoData}
        disabled={isLoading}
        type="button"
        aria-label="Load synthetic demo dataset"
      >
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" className={styles.demoBtnIcon}>
          <path d="M3 7h18M3 12h18M3 17h18" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
        Load Synthetic Demo Dataset
        <span className={styles.demoBtnTag}>10 scenarios · 280 events</span>
      </button>

      <div className={styles.divider}><span>or upload your own files</span></div>

      {/* Auth Log Upload */}
      <div
        className={`${styles.dropzone} ${dragOver ? styles.dropzoneOver : ''} ${authFile ? styles.dropzoneHasFile : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => authRef.current?.click()}
        role="button"
        tabIndex={0}
        aria-label="Drop authentication log CSV or click to select"
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            authRef.current?.click()
          }
        }}
      >
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" className={styles.dropzoneIcon}>
          <path d="M4 16l4-4 3 3 5-6 4 5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
          <rect x="2" y="3" width="20" height="18" rx="2" stroke="currentColor" strokeWidth="1.5"/>
        </svg>
        {authFile ? (
          <div className={styles.authFileInfo}>
            <span className={styles.fileName}>{authFile.name}</span>
            <button
              type="button"
              className={styles.clearBtn}
              onClick={(e) => {
                e.stopPropagation()
                setAuthFile(null)
                if (authRef.current) authRef.current.value = ''
              }}
              aria-label="Remove authentication log CSV"
            >×</button>
          </div>
        ) : (
          <>
            <span className={styles.dropzoneLabel}>Authentication Log CSV</span>
            <span className={styles.dropzoneHint}>Drop here or click to browse <strong>required</strong></span>
          </>
        )}
        <input
          ref={authRef}
          type="file"
          accept=".csv,text/csv"
          onChange={(e: ChangeEvent<HTMLInputElement>) => handleAuthFile(e.target.files)}
          onClick={(e) => {
            e.stopPropagation()
            e.currentTarget.value = ''
          }}
          className={styles.hiddenInput}
          id="input-auth-csv"
          aria-label="Authentication log CSV file"
        />
      </div>

      {/* Optional Files */}
      <div className={styles.optionalFiles}>
        <OptionalFileInput
          label="Asset Inventory CSV"
          hint="optional"
          file={assetFile}
          onChange={setAssetFile}
          inputRef={assetRef}
          id="input-assets-csv"
        />
        <OptionalFileInput
          label="IP-Location CSV"
          hint="optional — enables location enrichment"
          file={ipFile}
          onChange={setIpFile}
          inputRef={ipRef}
          id="input-ip-csv"
        />
      </div>

      {/* Timezone */}
      <div className={styles.timezoneRow}>
        <label htmlFor="select-timezone" className={styles.tzLabel}>Source Log Timezone</label>
        <select
          id="select-timezone"
          className={styles.tzSelect}
          value={timezone}
          onChange={e => {
            setTimezone(e.target.value)
            setTzOverridden(true)
          }}
          disabled={isLoading}
        >
          <option value="UTC">UTC</option>
          <option value="America/New_York">America/New_York (ET)</option>
          <option value="America/Chicago">America/Chicago (CT)</option>
          <option value="America/Denver">America/Denver (MT)</option>
          <option value="America/Los_Angeles">America/Los_Angeles (PT)</option>
          <option value="Europe/London">Europe/London (BST/GMT)</option>
          <option value="Europe/Berlin">Europe/Berlin (CET/CEST)</option>
          <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
          <option value="Asia/Kolkata">Asia/Kolkata (IST)</option>
          <option value="Australia/Sydney">Australia/Sydney (AEDT)</option>
        </select>
      </div>

      {/* Run Button */}
      {authFile && (
        <button
          id="btn-run-analysis"
          className={styles.runBtn}
          onClick={handleRun}
          disabled={isLoading}
          type="button"
        >
          {isLoading ? 'Analyzing…' : '▶ Run Analysis'}
        </button>
      )}

      {/* Loading State */}
      {isLoading && (
        <div className={styles.loadingRow} role="status" aria-live="polite">
          <div className={styles.spinner} aria-hidden="true" />
          <span>{state.status === 'parsing' ? 'Parsing CSV…' : 'Running detection pipeline…'}</span>
        </div>
      )}

      <p className={styles.disclaimer}>
        Files are processed entirely in your browser. No data is uploaded or sent to external servers.
      </p>
    </div>
  )
}

interface OptionalFileInputProps {
  label: string
  hint: string
  file: File | null
  onChange: (f: File | null) => void
  inputRef: React.RefObject<HTMLInputElement | null>
  id: string
}

function OptionalFileInput({ label, hint, file, onChange, inputRef, id }: OptionalFileInputProps) {
  return (
    <div className={styles.optionalFile}>
      <label htmlFor={id} className={styles.optionalLabel}>
        {label} <span className={styles.optionalHint}>{hint}</span>
      </label>
      <div className={styles.optionalRow}>
        <span className={styles.optionalFileName}>{file?.name ?? 'No file selected'}</span>
        <button
          type="button"
          className={styles.browseBtn}
          onClick={() => inputRef.current?.click()}
        >
          Browse
        </button>
        {file && (
          <button
            type="button"
            className={styles.clearBtn}
            onClick={() => {
              onChange(null)
              if (inputRef.current) inputRef.current.value = ''
            }}
            aria-label={`Remove ${label}`}
          >×</button>
        )}
      </div>
      <input
        ref={inputRef}
        type="file"
        accept=".csv,text/csv"
        id={id}
        className={styles.hiddenInput}
        onChange={(e: ChangeEvent<HTMLInputElement>) => onChange(e.target.files?.[0] ?? null)}
        onClick={(e) => {
          e.stopPropagation()
          e.currentTarget.value = ''
        }}
        aria-label={`${label} CSV file (optional)`}
      />
    </div>
  )
}
