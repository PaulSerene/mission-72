import { describe, it, expect } from 'vitest'
import rawAssets from '../data/fixtures/assets.csv?raw'

describe('Raw import test', () => {
  it('imports raw csv', () => {
    expect(typeof rawAssets).toBe('string')
    expect(rawAssets.length).toBeGreaterThan(0)
  })
})
