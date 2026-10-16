/**
 * Configuration Validation — Mission 72
 *
 * Validates AnalysisConfig and security context configurations.
 * Rejects invalid, malformed, or contradictory configuration inputs
 * with clear, actionable error messages.
 */

import type { AnalysisConfig, MaintenanceWindow, AccountRole } from '@/types'

export interface ConfigValidationResult {
  valid: boolean
  errors: string[]
}

const VALID_ROLES = new Set<AccountRole>(['admin', 'helpdesk', 'service', 'developer', 'regular'])

/**
 * Check if a timezone identifier is a valid IANA timezone supported by Intl.
 */
export function isValidIanaTimezone(tz: string): boolean {
  if (!tz || typeof tz !== 'string') return false
  try {
    Intl.DateTimeFormat(undefined, { timeZone: tz.trim() })
    return true
  } catch {
    return false
  }
}

/**
 * Validate an IPv4 CIDR string (e.g. '192.0.2.0/24').
 */
export function isValidIpv4Cidr(cidr: string): boolean {
  if (!cidr || typeof cidr !== 'string') return false
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr.trim())
  if (!match) return false

  const [, o1, o2, o3, o4, prefix] = match
  const octets = [Number(o1), Number(o2), Number(o3), Number(o4)]
  for (const o of octets) {
    if (o < 0 || o > 255) return false
  }

  const prefixLen = Number(prefix)
  return prefixLen >= 0 && prefixLen <= 32
}

/**
 * Validate a single MaintenanceWindow.
 */
export function validateMaintenanceWindow(
  window: MaintenanceWindow,
  index: number = 0,
): string[] {
  const errors: string[] = []
  const prefix = `Maintenance window #${index + 1}`

  if (window.start && window.end) {
    const s = new Date(window.start).getTime()
    const e = new Date(window.end).getTime()
    if (isNaN(s)) {
      errors.push(`${prefix}: start must be a valid ISO 8601 timestamp string.`)
    }
    if (isNaN(e)) {
      errors.push(`${prefix}: end must be a valid ISO 8601 timestamp string.`)
    }
    if (!isNaN(s) && !isNaN(e) && s >= e) {
      errors.push(`${prefix}: start must be strictly before end.`)
    }
  } else {
    if (typeof window.startHour !== 'number' || window.startHour < 0 || window.startHour > 23 || !Number.isInteger(window.startHour)) {
      errors.push(`${prefix}: startHour must be an integer between 0 and 23. Got ${window.startHour}.`)
    }

    if (typeof window.endHour !== 'number' || window.endHour < 0 || window.endHour > 23 || !Number.isInteger(window.endHour)) {
      errors.push(`${prefix}: endHour must be an integer between 0 and 23. Got ${window.endHour}.`)
    }

    if (window.startHour !== undefined && window.endHour !== undefined && window.startHour === window.endHour) {
      errors.push(`${prefix}: startHour and endHour cannot be identical (${window.startHour}:00). Window must have a non-zero duration.`)
    }
  }

  if (window.timezone && !isValidIanaTimezone(window.timezone)) {
    errors.push(`${prefix}: invalid IANA timezone "${window.timezone}".`)
  }

  if (window.daysOfWeek !== undefined) {
    if (!Array.isArray(window.daysOfWeek)) {
      errors.push(`${prefix}: daysOfWeek must be an array of integers (0=Sun, 6=Sat).`)
    } else {
      for (const day of window.daysOfWeek) {
        if (!Number.isInteger(day) || day < 0 || day > 6) {
          errors.push(`${prefix}: invalid day in daysOfWeek: ${day}. Must be between 0 (Sunday) and 6 (Saturday).`)
        }
      }
    }
  }

  if (window.allowedUsers !== undefined && !Array.isArray(window.allowedUsers)) {
    errors.push(`${prefix}: allowedUsers must be an array of usernames.`)
  }

  if (window.authorizedHelpdeskAccounts !== undefined && !Array.isArray(window.authorizedHelpdeskAccounts)) {
    errors.push(`${prefix}: authorizedHelpdeskAccounts must be an array of usernames.`)
  }

  if (window.permittedHosts !== undefined && !Array.isArray(window.permittedHosts)) {
    errors.push(`${prefix}: permittedHosts must be an array of host strings.`)
  }

  if (window.permittedActivities !== undefined && !Array.isArray(window.permittedActivities)) {
    errors.push(`${prefix}: permittedActivities must be an array of activity strings.`)
  }

  return errors
}

/**
 * Validate full AnalysisConfig, including security context and rule thresholds.
 */
export function validateConfig(config: AnalysisConfig): ConfigValidationResult {
  const errors: string[] = []

  // 1. Timezone
  if (!config.timezone || !isValidIanaTimezone(config.timezone)) {
    errors.push(`Invalid global timezone: "${config.timezone}". Must be a valid IANA timezone (e.g. "UTC", "America/New_York").`)
  }

  // 2. Training period
  if (!config.trainingPeriod?.start || isNaN(Date.parse(config.trainingPeriod.start))) {
    errors.push(`Invalid trainingPeriod.start: "${config.trainingPeriod?.start}". Must be a valid ISO 8601 timestamp.`)
  }
  if (!config.trainingPeriod?.end || isNaN(Date.parse(config.trainingPeriod.end))) {
    errors.push(`Invalid trainingPeriod.end: "${config.trainingPeriod?.end}". Must be a valid ISO 8601 timestamp.`)
  }
  if (config.trainingPeriod?.start && config.trainingPeriod?.end) {
    const tStart = Date.parse(config.trainingPeriod.start)
    const tEnd = Date.parse(config.trainingPeriod.end)
    if (tStart >= tEnd) {
      errors.push(`Training period start (${config.trainingPeriod.start}) must be strictly earlier than end (${config.trainingPeriod.end}).`)
    }
  }

  // 3. Analysis period
  if (!config.analysisPeriod?.start || isNaN(Date.parse(config.analysisPeriod.start))) {
    errors.push(`Invalid analysisPeriod.start: "${config.analysisPeriod?.start}". Must be a valid ISO 8601 timestamp.`)
  }
  if (!config.analysisPeriod?.end || isNaN(Date.parse(config.analysisPeriod.end))) {
    errors.push(`Invalid analysisPeriod.end: "${config.analysisPeriod?.end}". Must be a valid ISO 8601 timestamp.`)
  }
  if (config.analysisPeriod?.start && config.analysisPeriod?.end) {
    const aStart = Date.parse(config.analysisPeriod.start)
    const aEnd = Date.parse(config.analysisPeriod.end)
    if (aStart >= aEnd) {
      errors.push(`Analysis period start (${config.analysisPeriod.start}) must be strictly earlier than end (${config.analysisPeriod.end}).`)
    }
  }

  // 4. Approved VPN CIDRs
  if (config.approvedVpnCidrs) {
    if (!Array.isArray(config.approvedVpnCidrs)) {
      errors.push(`approvedVpnCidrs must be an array of CIDR strings or VpnRangeConfig objects.`)
    } else {
      config.approvedVpnCidrs.forEach((entry, idx) => {
        const cidr = typeof entry === 'string' ? entry : entry?.cidr
        if (!cidr || !isValidIpv4Cidr(cidr)) {
          errors.push(`approvedVpnCidrs[${idx}]: invalid IPv4 CIDR "${cidr}". Must be valid notation (e.g. "192.0.2.0/24").`)
        }
      })
    }
  }

  // 5. Maintenance Windows
  if (config.maintenanceWindows) {
    if (!Array.isArray(config.maintenanceWindows)) {
      errors.push(`maintenanceWindows must be an array.`)
    } else {
      config.maintenanceWindows.forEach((w, idx) => {
        errors.push(...validateMaintenanceWindow(w, idx))
      })
    }
  }

  // 6. Account Roles
  if (config.accountRoles) {
    if (typeof config.accountRoles !== 'object' || Array.isArray(config.accountRoles)) {
      errors.push(`accountRoles must be a key-value record mapping usernames to roles.`)
    } else {
      for (const [username, role] of Object.entries(config.accountRoles)) {
        if (!VALID_ROLES.has(role)) {
          errors.push(`Invalid account role "${role}" for user "${username}". Allowed roles: ${[...VALID_ROLES].join(', ')}.`)
        }
      }
    }
  }

  // 7. Authorized Helpdesk Accounts
  if (config.authorizedHelpdeskAccounts) {
    if (!Array.isArray(config.authorizedHelpdeskAccounts)) {
      errors.push(`authorizedHelpdeskAccounts must be an array of usernames.`)
    }
  }

  // 8. Rule Thresholds
  if (config.rules) {
    const { bruteForce, burstSuccess, passwordSpray, unusualHours, newHosts } = config.rules

    if (bruteForce) {
      if (typeof bruteForce.failureCount !== 'number' || bruteForce.failureCount <= 0) {
        errors.push(`rules.bruteForce.failureCount must be a positive number. Got ${bruteForce.failureCount}.`)
      }
      if (typeof bruteForce.windowSeconds !== 'number' || bruteForce.windowSeconds <= 0) {
        errors.push(`rules.bruteForce.windowSeconds must be a positive number. Got ${bruteForce.windowSeconds}.`)
      }
    }

    if (burstSuccess) {
      if (typeof burstSuccess.failureCount !== 'number' || burstSuccess.failureCount <= 0) {
        errors.push(`rules.burstSuccess.failureCount must be a positive number. Got ${burstSuccess.failureCount}.`)
      }
      if (typeof burstSuccess.windowSeconds !== 'number' || burstSuccess.windowSeconds <= 0) {
        errors.push(`rules.burstSuccess.windowSeconds must be a positive number. Got ${burstSuccess.windowSeconds}.`)
      }
    }

    if (passwordSpray) {
      if (typeof passwordSpray.userCount !== 'number' || passwordSpray.userCount <= 0) {
        errors.push(`rules.passwordSpray.userCount must be a positive number. Got ${passwordSpray.userCount}.`)
      }
      if (typeof passwordSpray.windowSeconds !== 'number' || passwordSpray.windowSeconds <= 0) {
        errors.push(`rules.passwordSpray.windowSeconds must be a positive number. Got ${passwordSpray.windowSeconds}.`)
      }
    }

    if (unusualHours) {
      if (typeof unusualHours.offHoursStart !== 'number' || unusualHours.offHoursStart < 0 || unusualHours.offHoursStart > 23) {
        errors.push(`rules.unusualHours.offHoursStart must be an integer between 0 and 23. Got ${unusualHours.offHoursStart}.`)
      }
      if (typeof unusualHours.offHoursEnd !== 'number' || unusualHours.offHoursEnd < 0 || unusualHours.offHoursEnd > 23) {
        errors.push(`rules.unusualHours.offHoursEnd must be an integer between 0 and 23. Got ${unusualHours.offHoursEnd}.`)
      }
      if (unusualHours.offHoursStart === unusualHours.offHoursEnd) {
        errors.push(`rules.unusualHours: offHoursStart and offHoursEnd cannot be identical.`)
      }
    }

    if (newHosts) {
      if (typeof newHosts.newHostCount !== 'number' || newHosts.newHostCount <= 0) {
        errors.push(`rules.newHosts.newHostCount must be a positive number. Got ${newHosts.newHostCount}.`)
      }
      if (typeof newHosts.windowHours !== 'number' || newHosts.windowHours <= 0) {
        errors.push(`rules.newHosts.windowHours must be a positive number. Got ${newHosts.windowHours}.`)
      }
    }

    if (config.rules.impossibleTravel) {
      const { maxSpeedKmH, minDistanceKm } = config.rules.impossibleTravel
      if (typeof maxSpeedKmH !== 'number' || maxSpeedKmH <= 0) {
        errors.push(`rules.impossibleTravel.maxSpeedKmH must be a positive number. Got ${maxSpeedKmH}.`)
      }
      if (typeof minDistanceKm !== 'number' || minDistanceKm <= 0) {
        errors.push(`rules.impossibleTravel.minDistanceKm must be a positive number. Got ${minDistanceKm}.`)
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  }
}
