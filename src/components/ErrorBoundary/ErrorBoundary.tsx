/**
 * ErrorBoundary — Mission 72
 *
 * Catches unhandled runtime exceptions in the component tree and renders
 * a dedicated SOC-themed error screen with stack trace details and a reset option,
 * preventing blank screens.
 */

import React, { Component, type ReactNode } from 'react'
import styles from './ErrorBoundary.module.css'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: React.ErrorInfo | null
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null, errorInfo: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    this.setState({ error, errorInfo })
    console.error('[Mission 72 Runtime Error]', error, errorInfo)
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null })
    window.location.reload()
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className={styles.errorContainer} role="alert">
          <div className={styles.errorCard}>
            <div className={styles.iconWrapper}>
              <svg className={styles.alertIcon} viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <h1 className={styles.title}>Application Exception Detected</h1>
            <p className={styles.desc}>
              An unexpected error occurred during execution. The diagnostic details below can assist investigation.
            </p>

            {this.state.error && (
              <div className={styles.errorBox}>
                <div className={styles.errorMessage}>
                  {this.state.error.name}: {this.state.error.message}
                </div>
                {this.state.error.stack && (
                  <pre className={styles.stackTrace}>{this.state.error.stack}</pre>
                )}
              </div>
            )}

            <div className={styles.actions}>
              <button
                type="button"
                className={styles.resetBtn}
                onClick={this.handleReset}
              >
                Reload Application
              </button>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
