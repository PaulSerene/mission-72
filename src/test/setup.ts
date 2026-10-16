/**
 * Vitest global test setup for Mission 72.
 *
 * This file runs before every test suite. Add global mocks,
 * custom matchers, or environment bootstrapping here.
 */

// Configure React 19 testing environment for act(...)
// @ts-expect-error global declaration for React testing
globalThis.IS_REACT_ACT_ENVIRONMENT = true
