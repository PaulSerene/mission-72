import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

/**
 * Vitest configuration — SignalForge
 *
 * Separated from vite.config.ts to avoid type incompatibilities between
 * Vite 8 (rolldown) and Vitest's bundled Vite version.
 *
 * Uses pool: 'vmThreads' for Vitest 5 compatibility — this resolves the
 * "Cannot read properties of undefined (reading 'config')" error that occurs
 * with the default 'forks' pool when globals: true is set.
 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': '/src',
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    pool: 'vmThreads',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/test/**', 'src/main.tsx', 'src/**/*.d.ts'],
    },
  },
})
