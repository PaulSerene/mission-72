import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { AppProvider } from '@/state/AppState'
import DashboardPage from '@/pages/DashboardPage'
import styles from '@/components/LoadDataPanel/LoadDataPanel.module.css'

describe('File Picker Activation & Dashboard Usability Regressions', () => {
  let container: HTMLDivElement | null = null
  let root: Root | null = null
  let inputClickSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)

    // Spy on HTMLInputElement.prototype.click to detect when native file picker is invoked
    inputClickSpy = vi.spyOn(HTMLInputElement.prototype, 'click').mockImplementation(function (
      this: HTMLInputElement
    ) {
      // Mock implementation prevents opening an actual OS dialog in jsdom/browser
    })
  })

  afterEach(() => {
    inputClickSpy.mockRestore()
    if (root && container) {
      act(() => {
        root!.unmount()
      })
      container.remove()
      container = null
      root = null
    }
  })

  it('clicking Upload CSV dropzone invokes file picker activation on the auth input only', async () => {
    await act(async () => {
      root!.render(
        <AppProvider>
          <DashboardPage />
        </AppProvider>
      )
    })

    const dropzone = container!.querySelector(`.${styles.dropzone}`) as HTMLElement
    expect(dropzone).not.toBeNull()

    inputClickSpy.mockClear()

    // Click the dropzone
    act(() => {
      dropzone.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    })

    expect(inputClickSpy).toHaveBeenCalledTimes(1)
    const clickedElement = (inputClickSpy.mock.contexts[0] ?? inputClickSpy.mock.instances[0]) as HTMLInputElement
    expect(clickedElement.id).toBe('input-auth-csv')
    expect(clickedElement.type).toBe('file')
  })

  it('clicking Browse for optional files (assets, ip) invokes file picker on the respective input', async () => {
    await act(async () => {
      root!.render(
        <AppProvider>
          <DashboardPage />
        </AppProvider>
      )
    })

    const browseButtons = container!.querySelectorAll(`.${styles.browseBtn}`)
    expect(browseButtons.length).toBe(2) // assets and ip

    inputClickSpy.mockClear()

    // Click first Browse button (Asset Inventory)
    act(() => {
      browseButtons[0].dispatchEvent(new MouseEvent('click', { bubbles: true }))
    })

    expect(inputClickSpy).toHaveBeenCalledTimes(1)
    const firstClicked = (inputClickSpy.mock.contexts[0] ?? inputClickSpy.mock.instances[0]) as HTMLInputElement
    expect(firstClicked.id).toBe('input-assets-csv')

    // Click second Browse button (IP Locations)
    inputClickSpy.mockClear()
    act(() => {
      browseButtons[1].dispatchEvent(new MouseEvent('click', { bubbles: true }))
    })

    expect(inputClickSpy).toHaveBeenCalledTimes(1)
    const secondClicked = (inputClickSpy.mock.contexts[0] ?? inputClickSpy.mock.instances[0]) as HTMLInputElement
    expect(secondClicked.id).toBe('input-ip-csv')
  })

  it('clicking Load Synthetic Demo Dataset NEVER invokes the file picker and loads demo data', async () => {
    await act(async () => {
      root!.render(
        <AppProvider>
          <DashboardPage />
        </AppProvider>
      )
    })

    const demoBtn = container!.querySelector('#btn-onboarding-demo') as HTMLButtonElement
    expect(demoBtn).not.toBeNull()

    inputClickSpy.mockClear()

    await act(async () => {
      demoBtn.click()
      // Wait for pipeline execution
      await new Promise(r => setTimeout(r, 100))
    })

    // File picker MUST NOT have been triggered
    expect(inputClickSpy).not.toHaveBeenCalled()

    // Dashboard should transition out of onboarding and display incidents
    const incidentsTab = container!.querySelector('#tab-incidents')
    expect(incidentsTab).not.toBeNull()
  })

  it('clicking navigation tabs, reset, and reanalyze does NOT invoke the file picker', async () => {
    await act(async () => {
      root!.render(
        <AppProvider>
          <DashboardPage />
        </AppProvider>
      )
    })

    // Load demo data first
    const demoBtn = container!.querySelector('#btn-onboarding-demo') as HTMLButtonElement
    await act(async () => {
      demoBtn.click()
      await new Promise(r => setTimeout(r, 100))
    })

    inputClickSpy.mockClear()

    // 1. Navigation Tab: Visualizations
    const vizTab = container!.querySelector('#tab-visualizations') as HTMLButtonElement
    expect(vizTab).not.toBeNull()
    act(() => {
      vizTab.click()
    })
    expect(inputClickSpy).not.toHaveBeenCalled()

    // 2. Navigation Tab: Data Quality & Config
    const qualityTab = container!.querySelector('#tab-quality') as HTMLButtonElement
    expect(qualityTab).not.toBeNull()
    act(() => {
      qualityTab.click()
    })
    expect(inputClickSpy).not.toHaveBeenCalled()

    // 3. Reanalyze button inside ConfigPanel
    const rerunBtn = container!.querySelector('#btn-rerun-analysis') as HTMLButtonElement
    expect(rerunBtn).not.toBeNull()
    await act(async () => {
      rerunBtn.click()
      await new Promise(r => setTimeout(r, 50))
    })
    expect(inputClickSpy).not.toHaveBeenCalled()

    // 4. Reset/Clear button in ExportBar
    const resetBtn = container!.querySelector('#btn-reset-analysis') as HTMLButtonElement
    expect(resetBtn).not.toBeNull()
    act(() => {
      resetBtn.click()
    })
    expect(inputClickSpy).not.toHaveBeenCalled()

    // Dashboard returns to onboarding state
    expect(container!.querySelector('#btn-onboarding-demo')).not.toBeNull()
  })

  it('clicking empty dashboard space or main container does NOT invoke the file picker', async () => {
    await act(async () => {
      root!.render(
        <AppProvider>
          <DashboardPage />
        </AppProvider>
      )
    })

    inputClickSpy.mockClear()

    const main = container!.querySelector('#main-content') as HTMLElement
    expect(main).not.toBeNull()

    act(() => {
      main.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    })

    expect(inputClickSpy).not.toHaveBeenCalled()
  })

  it('file input elements have hiddenInput class with pointer-events: none and offscreen dimensions', async () => {
    await act(async () => {
      root!.render(
        <AppProvider>
          <DashboardPage />
        </AppProvider>
      )
    })

    const fileInputs = container!.querySelectorAll('input[type="file"]')
    expect(fileInputs.length).toBeGreaterThanOrEqual(3) // auth, assets, ip

    for (const input of Array.from(fileInputs)) {
      expect(input.className).toContain(styles.hiddenInput)
    }
  })

  it('selecting a CSV file through intended file input updates state without recursive click loops', async () => {
    await act(async () => {
      root!.render(
        <AppProvider>
          <DashboardPage />
        </AppProvider>
      )
    })

    const authInput = container!.querySelector('#input-auth-csv') as HTMLInputElement
    expect(authInput).not.toBeNull()

    inputClickSpy.mockClear()

    // Simulate selecting a file
    const mockFile = new File(
      ['timestamp,user,ip,status\n2026-03-01T12:00:00Z,analyst,192.168.1.100,success'],
      'auth_test.csv',
      { type: 'text/csv' }
    )

    Object.defineProperty(authInput, 'files', {
      value: [mockFile],
      writable: true,
    })

    act(() => {
      authInput.dispatchEvent(new Event('change', { bubbles: true }))
    })

    // Dropzone should now show the file name and the Run button
    expect(container!.textContent).toContain('auth_test.csv')
    const runBtn = container!.querySelector('#btn-run-analysis') as HTMLButtonElement
    expect(runBtn).not.toBeNull()

    // Clicking Run executes analysis without invoking file picker
    await act(async () => {
      runBtn.click()
      await new Promise(r => setTimeout(r, 50))
    })

    expect(inputClickSpy).not.toHaveBeenCalled()
  })
})
