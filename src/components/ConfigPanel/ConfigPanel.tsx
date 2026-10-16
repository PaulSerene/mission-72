/**
 * ConfigPanel — Mission 72
 *
 * Configuration and re-analysis management:
 * - View & tweak analysis options (timezone, training period, rule thresholds)
 * - Rerun analysis against already-loaded data with updated configuration
 * - Clear baseline transparency & heuristic limitations disclaimers
 */

import { useState } from 'react'
import { useAppState } from '@/state/AppState'
import { usePipeline } from '@/hooks/usePipeline'
import type { AnalysisConfig } from '@/types'
import styles from './ConfigPanel.module.css'

export function ConfigPanel() {
  const { state } = useAppState()
  const { reanalyze } = usePipeline()
  const { config, rawAuthCsv, rawAssetCsv, rawIpLocationCsv, status } = state
  const isAnalyzing = status === 'analyzing'

  const configKey = config
    ? `${config.trainingPeriod.start}-${config.timezone}`
    : 'default-config'

  return (
    <ConfigPanelForm
      key={configKey}
      config={config}
      rawAuthCsv={rawAuthCsv}
      rawAssetCsv={rawAssetCsv}
      rawIpLocationCsv={rawIpLocationCsv}
      isAnalyzing={isAnalyzing}
      onReanalyze={reanalyze}
    />
  )
}

interface ConfigPanelFormProps {
  config: AnalysisConfig | null
  rawAuthCsv?: string
  rawAssetCsv?: string
  rawIpLocationCsv?: string
  isAnalyzing: boolean
  onReanalyze: (
    rawAuthCsv: string,
    rawAssetCsv: string | undefined,
    rawIpLocationCsv: string | undefined,
    config: Partial<AnalysisConfig>
  ) => Promise<void>
}

function ConfigPanelForm({
  config,
  rawAuthCsv,
  rawAssetCsv,
  rawIpLocationCsv,
  isAnalyzing,
  onReanalyze,
}: ConfigPanelFormProps) {
  const [timezone, setTimezone] = useState(config?.timezone ?? 'UTC')
  const [trainingStart, setTrainingStart] = useState(config?.trainingPeriod?.start ?? '')
  const [trainingEnd, setTrainingEnd] = useState(config?.trainingPeriod?.end ?? '')
  const [analysisStart, setAnalysisStart] = useState(config?.analysisPeriod?.start ?? '')
  const [analysisEnd, setAnalysisEnd] = useState(config?.analysisPeriod?.end ?? '')

  // Rule thresholds
  const [bfCount, setBfCount] = useState(config?.rules?.bruteForce?.failureCount ?? 5)
  const [bfWindow, setBfWindow] = useState(config?.rules?.bruteForce?.windowSeconds ?? 300)

  const [burstCount, setBurstCount] = useState(config?.rules?.burstSuccess?.failureCount ?? 3)
  const [burstWindow, setBurstWindow] = useState(config?.rules?.burstSuccess?.windowSeconds ?? 600)

  const [sprayUsers, setSprayUsers] = useState(config?.rules?.passwordSpray?.userCount ?? 5)
  const [sprayWindow, setSprayWindow] = useState(config?.rules?.passwordSpray?.windowSeconds ?? 900)

  const [offStart, setOffStart] = useState(config?.rules?.unusualHours?.offHoursStart ?? 20)
  const [offEnd, setOffEnd] = useState(config?.rules?.unusualHours?.offHoursEnd ?? 6)

  const [newHostCount, setNewHostCount] = useState(config?.rules?.newHosts?.newHostCount ?? 3)
  const [newHostWindow, setNewHostWindow] = useState(config?.rules?.newHosts?.windowHours ?? 24)

  const canRerun = Boolean(rawAuthCsv) && !isAnalyzing

  async function handleRerun() {
    if (!rawAuthCsv) return

    const updatedConfig: Partial<AnalysisConfig> = {
      timezone,
      ...(trainingStart && trainingEnd
        ? { trainingPeriod: { start: trainingStart, end: trainingEnd } }
        : {}),
      ...(analysisStart && analysisEnd
        ? { analysisPeriod: { start: analysisStart, end: analysisEnd } }
        : {}),
      rules: {
        bruteForce: {
          failureCount: Number(bfCount),
          windowSeconds: Number(bfWindow),
        },
        burstSuccess: {
          failureCount: Number(burstCount),
          windowSeconds: Number(burstWindow),
        },
        passwordSpray: {
          userCount: Number(sprayUsers),
          windowSeconds: Number(sprayWindow),
        },
        unusualHours: {
          offHoursStart: Number(offStart),
          offHoursEnd: Number(offEnd),
        },
        newHosts: {
          newHostCount: Number(newHostCount),
          windowHours: Number(newHostWindow),
        },
      },
    }

    await onReanalyze(rawAuthCsv, rawAssetCsv, rawIpLocationCsv, updatedConfig)
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div>
          <h3 className={styles.title}>Detection Engine Configuration & Baseline Controls</h3>
          <p className={styles.subtitle}>
            Adjust detection sensitivity thresholds, timezones, and evaluation periods, then re-evaluate loaded logs.
          </p>
        </div>
        {canRerun && (
          <button
            id="btn-rerun-analysis"
            type="button"
            className={styles.rerunBtn}
            onClick={handleRerun}
            disabled={isAnalyzing}
          >
            {isAnalyzing ? 'Re-evaluating…' : '↻ Apply & Rerun Pipeline'}
          </button>
        )}
      </div>

      <div className={styles.formGrid}>
        {/* Timing and timezone */}
        <div className={styles.formSection}>
          <h4 className={styles.sectionTitle}>Time & Timezone Settings</h4>
          <div className={styles.fieldRow}>
            <label htmlFor="config-timezone" className={styles.fieldLabel}>Log Timezone</label>
            <select
              id="config-timezone"
              className={styles.selectInput}
              value={timezone}
              onChange={e => setTimezone(e.target.value)}
            >
              <option value="UTC">UTC (Coordinated Universal Time)</option>
              <option value="America/New_York">America/New_York (ET)</option>
              <option value="America/Chicago">America/Chicago (CT)</option>
              <option value="America/Denver">America/Denver (MT)</option>
              <option value="America/Los_Angeles">America/Los_Angeles (PT)</option>
              <option value="Europe/London">Europe/London (GMT/BST)</option>
              <option value="Europe/Berlin">Europe/Berlin (CET/CEST)</option>
              <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
              <option value="Asia/Kolkata">Asia/Kolkata (IST)</option>
            </select>
          </div>

          <div className={styles.fieldRow}>
            <label htmlFor="config-training-start" className={styles.fieldLabel}>Training Period Start</label>
            <input
              id="config-training-start"
              type="text"
              className={styles.textInput}
              placeholder="e.g. 2026-03-01T00:00:00Z"
              value={trainingStart}
              onChange={e => setTrainingStart(e.target.value)}
            />
          </div>

          <div className={styles.fieldRow}>
            <label htmlFor="config-training-end" className={styles.fieldLabel}>Training Period End</label>
            <input
              id="config-training-end"
              type="text"
              className={styles.textInput}
              placeholder="e.g. 2026-03-14T23:59:59Z"
              value={trainingEnd}
              onChange={e => setTrainingEnd(e.target.value)}
            />
          </div>

          <div className={styles.fieldRow}>
            <label htmlFor="config-analysis-start" className={styles.fieldLabel}>Analysis Period Start</label>
            <input
              id="config-analysis-start"
              type="text"
              className={styles.textInput}
              placeholder="e.g. 2026-03-15T00:00:00Z"
              value={analysisStart}
              onChange={e => setAnalysisStart(e.target.value)}
            />
          </div>

          <div className={styles.fieldRow}>
            <label htmlFor="config-analysis-end" className={styles.fieldLabel}>Analysis Period End</label>
            <input
              id="config-analysis-end"
              type="text"
              className={styles.textInput}
              placeholder="e.g. 2026-03-15T23:59:59Z"
              value={analysisEnd}
              onChange={e => setAnalysisEnd(e.target.value)}
            />
          </div>
        </div>

        {/* Rule Thresholds */}
        <div className={styles.formSection}>
          <h4 className={styles.sectionTitle}>Rule Thresholds</h4>
          <div className={styles.dualField}>
            <div className={styles.fieldItem}>
              <label htmlFor="config-bf-count" className={styles.fieldLabel}>Brute Force Failures</label>
              <input
                id="config-bf-count"
                type="number"
                min="1"
                max="50"
                className={styles.numberInput}
                value={bfCount}
                onChange={e => setBfCount(Number(e.target.value))}
              />
            </div>
            <div className={styles.fieldItem}>
              <label htmlFor="config-bf-window" className={styles.fieldLabel}>Window (sec)</label>
              <input
                id="config-bf-window"
                type="number"
                min="10"
                max="3600"
                step="30"
                className={styles.numberInput}
                value={bfWindow}
                onChange={e => setBfWindow(Number(e.target.value))}
              />
            </div>
          </div>

          <div className={styles.dualField}>
            <div className={styles.fieldItem}>
              <label htmlFor="config-burst-count" className={styles.fieldLabel}>Burst Success Failures</label>
              <input
                id="config-burst-count"
                type="number"
                min="1"
                max="50"
                className={styles.numberInput}
                value={burstCount}
                onChange={e => setBurstCount(Number(e.target.value))}
              />
            </div>
            <div className={styles.fieldItem}>
              <label htmlFor="config-burst-window" className={styles.fieldLabel}>Window (sec)</label>
              <input
                id="config-burst-window"
                type="number"
                min="10"
                max="3600"
                step="30"
                className={styles.numberInput}
                value={burstWindow}
                onChange={e => setBurstWindow(Number(e.target.value))}
              />
            </div>
          </div>

          <div className={styles.dualField}>
            <div className={styles.fieldItem}>
              <label htmlFor="config-spray-users" className={styles.fieldLabel}>Spray Users Count</label>
              <input
                id="config-spray-users"
                type="number"
                min="2"
                max="50"
                className={styles.numberInput}
                value={sprayUsers}
                onChange={e => setSprayUsers(Number(e.target.value))}
              />
            </div>
            <div className={styles.fieldItem}>
              <label htmlFor="config-spray-window" className={styles.fieldLabel}>Window (sec)</label>
              <input
                id="config-spray-window"
                type="number"
                min="60"
                max="7200"
                step="60"
                className={styles.numberInput}
                value={sprayWindow}
                onChange={e => setSprayWindow(Number(e.target.value))}
              />
            </div>
          </div>

          <div className={styles.dualField}>
            <div className={styles.fieldItem}>
              <label htmlFor="config-off-start" className={styles.fieldLabel}>Off-Hours Start (UTC h)</label>
              <input
                id="config-off-start"
                type="number"
                min="0"
                max="23"
                className={styles.numberInput}
                value={offStart}
                onChange={e => setOffStart(Number(e.target.value))}
              />
            </div>
            <div className={styles.fieldItem}>
              <label htmlFor="config-off-end" className={styles.fieldLabel}>Off-Hours End (UTC h)</label>
              <input
                id="config-off-end"
                type="number"
                min="0"
                max="23"
                className={styles.numberInput}
                value={offEnd}
                onChange={e => setOffEnd(Number(e.target.value))}
              />
            </div>
          </div>

          <div className={styles.dualField}>
            <div className={styles.fieldItem}>
              <label htmlFor="config-new-hosts" className={styles.fieldLabel}>New Hosts Count</label>
              <input
                id="config-new-hosts"
                type="number"
                min="1"
                max="20"
                className={styles.numberInput}
                value={newHostCount}
                onChange={e => setNewHostCount(Number(e.target.value))}
              />
            </div>
            <div className={styles.fieldItem}>
              <label htmlFor="config-new-window" className={styles.fieldLabel}>Window (hours)</label>
              <input
                id="config-new-window"
                type="number"
                min="1"
                max="72"
                className={styles.numberInput}
                value={newHostWindow}
                onChange={e => setNewHostWindow(Number(e.target.value))}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Transparency & Heuristic Disclaimers */}
      <div className={styles.disclaimers}>
        <div className={styles.disclaimerItem}>
          <span className={styles.disclaimerIcon}>ℹ</span>
          <span>
            <strong>Baseline Coverage:</strong> Users require at least 5 training events to form a reliable baseline.
            Accounts with fewer events generate lower-confidence alerts. A missing baseline does not imply malicious intent.
          </span>
        </div>
        <div className={styles.disclaimerItem}>
          <span className={styles.disclaimerIcon}>ℹ</span>
          <span>
            <strong>Heuristic Nature:</strong> Off-hours logins and new source IPs are statistical deviations, not proofs of compromise.
            Authorized on-call work, shifting employee schedules, or new dynamic DHCP leases can cause legitimate deviations.
          </span>
        </div>
        <div className={styles.disclaimerItem}>
          <span className={styles.disclaimerIcon}>ℹ</span>
          <span>
            <strong>Synthetic Data Notice:</strong> The built-in dataset is a synthetic simulation fixture containing 10 pre-scripted scenarios.
            It is designed for functionality and regression demonstration, not statistical evidence of production accuracy.
          </span>
        </div>
      </div>
    </div>
  )
}
