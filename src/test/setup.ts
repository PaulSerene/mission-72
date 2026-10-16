/**
 * Vitest global test setup for SignalForge.
 *
 * This file runs before every test suite. Add global mocks,
 * custom matchers, or environment bootstrapping here.
 */

// Configure React 19 testing environment for act(...)
// @ts-expect-error global declaration for React testing
globalThis.IS_REACT_ACT_ENVIRONMENT = true

// Mock window.matchMedia for jsdom environments that don't support it.
// Components that use useTheme (e.g., TopNav) call window.matchMedia to
// detect the system color-scheme preference. jsdom does not implement it.
if (typeof window !== 'undefined' && typeof window.matchMedia !== 'function') {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string) => ({
      matches: false, // default to dark theme in tests
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  })
}
