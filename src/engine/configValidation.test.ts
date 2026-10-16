import { describe, expect, it } from 'vitest'
import {
  validateConfig,
  validateMaintenanceWindow,
  isValidIanaTimezone,
  isValidIpv4Cidr,
} from './configValidation'
import { createDefaultConfig } from './pipeline'

describe('Configuration Validation (Phase 2)', () => {
  it('passes on valid default configuration', () => {
    const config = createDefaultConfig()
    const result = validateConfig(config)
    expect(result.valid).toBe(true)
    expect(result.errors).toHaveLength(0)
  })

  describe('Timezone validation', () => {
    it('accepts standard IANA timezones', () => {
      expect(isValidIanaTimezone('UTC')).toBe(true)
      expect(isValidIanaTimezone('America/New_York')).toBe(true)
      expect(isValidIanaTimezone('Europe/London')).toBe(true)
      expect(isValidIanaTimezone('Asia/Tokyo')).toBe(true)
    })

    it('rejects invalid timezones', () => {
      expect(isValidIanaTimezone('Invalid/Timezone')).toBe(false)
      expect(isValidIanaTimezone('')).toBe(false)
      expect(isValidIanaTimezone('Mars/Olympus')).toBe(false)
    })

    it('flags invalid global timezone in validateConfig', () => {
      const config = createDefaultConfig({ timezone: 'Invalid/Zone' })
      const res = validateConfig(config)
      expect(res.valid).toBe(false)
      expect(res.errors.some(e => e.includes('Invalid global timezone'))).toBe(true)
    })
  })

  describe('CIDR validation', () => {
    it('accepts valid IPv4 CIDRs', () => {
      expect(isValidIpv4Cidr('192.0.2.0/24')).toBe(true)
      expect(isValidIpv4Cidr('10.0.0.0/8')).toBe(true)
      expect(isValidIpv4Cidr('0.0.0.0/0')).toBe(true)
      expect(isValidIpv4Cidr('255.255.255.255/32')).toBe(true)
    })

    it('rejects malformed CIDRs', () => {
      expect(isValidIpv4Cidr('192.0.2.0')).toBe(false) // missing prefix
      expect(isValidIpv4Cidr('192.0.2.0/33')).toBe(false) // prefix > 32
      expect(isValidIpv4Cidr('256.0.0.1/24')).toBe(false) // octet > 255
      expect(isValidIpv4Cidr('invalid/24')).toBe(false)
      expect(isValidIpv4Cidr('')).toBe(false)
    })

    it('flags bad CIDRs in approvedVpnCidrs', () => {
      const config = createDefaultConfig({
        approvedVpnCidrs: ['192.0.2.0/24', 'bad-cidr/99'],
      })
      const res = validateConfig(config)
      expect(res.valid).toBe(false)
      expect(res.errors.some(e => e.includes('invalid IPv4 CIDR'))).toBe(true)
    })
  })

  describe('Time window validation', () => {
    it('rejects training start after end', () => {
      const config = createDefaultConfig({
        trainingPeriod: {
          start: '2026-10-08T00:00:00Z',
          end: '2026-10-01T00:00:00Z',
        },
      })
      const res = validateConfig(config)
      expect(res.valid).toBe(false)
      expect(res.errors.some(e => e.includes('Training period start'))).toBe(true)
    })

    it('rejects analysis start after end', () => {
      const config = createDefaultConfig({
        analysisPeriod: {
          start: '2026-10-15T00:00:00Z',
          end: '2026-10-08T00:00:00Z',
        },
      })
      const res = validateConfig(config)
      expect(res.valid).toBe(false)
      expect(res.errors.some(e => e.includes('Analysis period start'))).toBe(true)
    })
  })

  describe('Maintenance window validation', () => {
    it('rejects identical startHour and endHour (zero duration)', () => {
      const errors = validateMaintenanceWindow({
        startHour: 4,
        endHour: 4,
      })
      expect(errors.some(e => e.includes('cannot be identical'))).toBe(true)
    })

    it('rejects out of range hours', () => {
      const errors = validateMaintenanceWindow({
        startHour: -1,
        endHour: 25,
      })
      expect(errors.some(e => e.includes('startHour must be an integer between 0 and 23'))).toBe(true)
      expect(errors.some(e => e.includes('endHour must be an integer between 0 and 23'))).toBe(true)
    })

    it('rejects invalid daysOfWeek', () => {
      const errors = validateMaintenanceWindow({
        startHour: 2,
        endHour: 4,
        daysOfWeek: [0, 7], // 7 is invalid
      })
      expect(errors.some(e => e.includes('invalid day in daysOfWeek: 7'))).toBe(true)
    })

    it('validates window-specific timezone', () => {
      const errors = validateMaintenanceWindow({
        startHour: 2,
        endHour: 4,
        timezone: 'NonExistent/Zone',
      })
      expect(errors.some(e => e.includes('invalid IANA timezone'))).toBe(true)
    })
  })

  describe('Account role validation', () => {
    it('rejects unrecognized account roles', () => {
      const config = createDefaultConfig({
        accountRoles: {
          alice: 'super-admin' as any,
        },
      })
      const res = validateConfig(config)
      expect(res.valid).toBe(false)
      expect(res.errors.some(e => e.includes('Invalid account role "super-admin"'))).toBe(true)
    })
  })

  describe('Rule threshold validation', () => {
    it('rejects negative or zero thresholds', () => {
      const config = createDefaultConfig({
        rules: {
          ...createDefaultConfig().rules,
          bruteForce: { failureCount: 0, windowSeconds: -10 },
        },
      })
      const res = validateConfig(config)
      expect(res.valid).toBe(false)
      expect(res.errors.some(e => e.includes('rules.bruteForce.failureCount'))).toBe(true)
      expect(res.errors.some(e => e.includes('rules.bruteForce.windowSeconds'))).toBe(true)
    })
  })
})
