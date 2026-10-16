/**
 * Asset & IP-Location Parsers — Mission 72
 *
 * Parses asset inventory and IP-to-location mapping CSVs.
 * Implements correct IPv4 CIDR matching using bit arithmetic.
 *
 * IPv6 CIDR limitation: IPv6 addresses and CIDRs are not supported.
 * Rows containing IPv6 CIDRs are rejected with a diagnostic message.
 * Source events with IPv6 source IPs will not match any location.
 */

import Papa from 'papaparse'
import type { AssetRecord, AssetParseResult, IpLocationRecord, IpLocationParseResult } from '@/types'
import { isValidCoordinate } from './geo'

// ─── IPv4 Bit Arithmetic ─────────────────────────────────────────────────────

/**
 * Convert a dotted-decimal IPv4 string to a 32-bit unsigned integer.
 * Returns null for malformed addresses.
 */
export function ipv4ToInt(ip: string): number | null {
  const parts = ip.trim().split('.')
  if (parts.length !== 4) return null
  let result = 0
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null
    const n = parseInt(part, 10)
    if (n < 0 || n > 255) return null
    result = ((result << 8) | n) >>> 0
  }
  return result
}

/**
 * Parse an IPv4 CIDR string into a pre-computed network/mask pair.
 * Returns null for malformed CIDRs.
 *
 * The network address is AND-masked with the prefix mask, so supplying
 * host-bits in the CIDR (e.g. "192.168.1.100/24") is handled correctly.
 *
 * Special case: prefix 0 → mask 0 (matches all IPv4 addresses).
 * Special case: prefix 32 → mask 0xFFFFFFFF (matches single host).
 */
export function parseCidrV4(cidr: string): { network: number; mask: number } | null {
  const parts = cidr.trim().split('/')
  if (parts.length !== 2) return null
  const [ipStr, prefixStr] = parts
  const prefix = parseInt(prefixStr, 10)
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return null
  const ipInt = ipv4ToInt(ipStr)
  if (ipInt === null) return null
  // prefix 0: mask = 0; prefix 32: mask = 0xFFFFFFFF; others: shift
  const mask = prefix === 0 ? 0 : ((~0 << (32 - prefix)) >>> 0)
  const network = (ipInt & mask) >>> 0
  return { network, mask }
}

/**
 * Return true if the IPv4 address (string) falls within the given pre-parsed CIDR.
 * Correctly includes the network address (e.g. 192.168.1.0) and broadcast
 * address (e.g. 192.168.1.255) because the mask covers both.
 */
export function isIpv4InCidr(ip: string, cidr: { network: number; mask: number }): boolean {
  const ipInt = ipv4ToInt(ip)
  if (ipInt === null) return false
  return (ipInt & cidr.mask) >>> 0 === cidr.network
}

/**
 * Return true if the given IPv4 address falls within any of the given
 * pre-parsed CIDR records (e.g. approved VPN ranges).
 */
export function isIpInAnyCidr(
  ip: string,
  cidrs: Array<{ network: number; mask: number }>,
): boolean {
  return cidrs.some(cidr => isIpv4InCidr(ip, cidr))
}

// ─── Asset CSV Parser ─────────────────────────────────────────────────────────

/**
 * Parse an asset inventory CSV.
 *
 * Required columns (case-insensitive, whitespace-tolerant):
 *   host, role, privileged
 *
 * The 'privileged' column is normalized from common boolean representations:
 *   true/yes/1/y → true; false/no/0/n → false.
 *
 * Hostnames are lowercased and trimmed.
 */
export function parseAssets(csvText: string): AssetParseResult {
  const parsed = Papa.parse<Record<string, string>>(csvText, {
    header: true,
    skipEmptyLines: true,
    transformHeader: (h) => h.toLowerCase().trim(),
  })

  const assets: AssetRecord[] = []
  const invalidRows: AssetParseResult['invalidRows'] = []

  for (let i = 0; i < parsed.data.length; i++) {
    const row = parsed.data[i]
    const host = (row['host'] ?? '').trim().toLowerCase()
    const role = (row['role'] ?? row['host_role'] ?? '').trim()
    const privRaw = (row['privileged'] ?? '').trim().toLowerCase()

    if (!host) {
      invalidRows.push({ rowIndex: i, reason: 'Missing or empty host', raw: row })
      continue
    }
    if (!role) {
      invalidRows.push({ rowIndex: i, reason: 'Missing or empty role', raw: row })
      continue
    }

    let privileged: boolean
    if (privRaw === 'true' || privRaw === 'yes' || privRaw === '1' || privRaw === 'y') {
      privileged = true
    } else if (privRaw === 'false' || privRaw === 'no' || privRaw === '0' || privRaw === 'n' || privRaw === '') {
      privileged = false
    } else {
      invalidRows.push({ rowIndex: i, reason: `Unrecognized privileged value: "${privRaw}"`, raw: row })
      continue
    }

    assets.push({ host, role, privileged })
  }

  return { assets, invalidRows }
}

// ─── IP-Location CSV Parser ───────────────────────────────────────────────────

/**
 * Parse an IP-to-location CSV.
 *
 * Required columns (case-insensitive):
 *   cidr, location
 *
 * Each CIDR is validated and pre-computed to network/mask integers for fast lookup.
 * IPv6 CIDRs are not supported — rows containing colons (':') in the CIDR are rejected.
 */
export function parseIpLocations(csvText: string): IpLocationParseResult {
  const parsed = Papa.parse<Record<string, string>>(csvText, {
    header: true,
    skipEmptyLines: true,
    transformHeader: (h) => h.toLowerCase().trim(),
  })

  const locations: IpLocationRecord[] = []
  const invalidRows: IpLocationParseResult['invalidRows'] = []

  for (let i = 0; i < parsed.data.length; i++) {
    const row = parsed.data[i]
    const cidr = (row['cidr'] ?? row['ip_range_cidr'] ?? row['ip_range'] ?? row['subnet'] ?? row['network'] ?? '').trim()
    let location = (row['location'] ?? '').trim()
    if (!location) {
      const city = (row['city'] ?? '').trim()
      const country = (row['country'] ?? '').trim()
      if (city && country) {
        location = `${city}, ${country}`
      } else {
        location = city || country
      }
    }

    if (!cidr) {
      invalidRows.push({ rowIndex: i, reason: 'Missing or empty CIDR', raw: row })
      continue
    }
    if (!location) {
      invalidRows.push({ rowIndex: i, reason: 'Missing or empty location', raw: row })
      continue
    }
    // IPv6 check (contains colon)
    if (cidr.includes(':')) {
      invalidRows.push({
        rowIndex: i,
        reason: `IPv6 CIDRs are not supported (limitation): "${cidr}"`,
        raw: row,
      })
      continue
    }

    const parsed4 = parseCidrV4(cidr)
    if (!parsed4) {
      invalidRows.push({ rowIndex: i, reason: `Invalid IPv4 CIDR: "${cidr}"`, raw: row })
      continue
    }

    // Optional geographic coordinates
    let latitude: number | undefined
    let longitude: number | undefined
    const rawLat = (row['latitude'] ?? row['lat'] ?? '').trim()
    const rawLon = (row['longitude'] ?? row['lon'] ?? row['long'] ?? row['lng'] ?? '').trim()

    if (rawLat !== '' || rawLon !== '') {
      const latNum = parseFloat(rawLat)
      const lonNum = parseFloat(rawLon)
      if (isValidCoordinate(latNum, lonNum)) {
        latitude = latNum
        longitude = lonNum
      } else {
        // Invalid coordinate treated as unavailable without rejecting the subnet mapping
        latitude = undefined
        longitude = undefined
      }
    }

    const networkType = (row['network_type'] ?? row['type'] ?? '').trim() || undefined

    locations.push({
      cidr,
      location,
      networkInt: parsed4.network,
      maskInt: parsed4.mask,
      ...(latitude !== undefined && longitude !== undefined ? { latitude, longitude } : {}),
      ...(networkType ? { networkType } : {}),
    })
  }

  return { locations, invalidRows }
}

// ─── Location Lookup ──────────────────────────────────────────────────────────

/**
 * Find the matching IpLocationRecord for a given IPv4 address using the pre-parsed
 * IP-location records. Returns the first matching record (including optional coordinates),
 * or null if no CIDR contains the address.
 *
 * Matching is done with correct bit arithmetic — no string-prefix comparison.
 */
export function lookupLocationRecord(
  ip: string,
  locations: IpLocationRecord[],
): IpLocationRecord | null {
  for (const loc of locations) {
    if (isIpv4InCidr(ip, { network: loc.networkInt, mask: loc.maskInt })) {
      return loc
    }
  }
  return null
}

/**
 * Find the location label for a given IPv4 address using the pre-parsed
 * IP-location records. Returns the first matching record's location,
 * or null if no CIDR contains the address.
 */
export function lookupLocation(ip: string, locations: IpLocationRecord[]): string | null {
  return lookupLocationRecord(ip, locations)?.location ?? null
}

import type { VpnRangeConfig } from '@/types'

export interface ParsedVpnCidr {
  network: number
  mask: number
  cidr: string
  id?: string
  description?: string
}

/**
 * Parse CIDR strings or VpnRangeConfig objects (e.g. from config.approvedVpnCidrs)
 * into pre-computed network/mask objects for fast repeated matching.
 * Silently skips invalid or IPv6 CIDRs.
 */
export function parseVpnCidrs(cidrs: Array<string | VpnRangeConfig>): ParsedVpnCidr[] {
  const result: ParsedVpnCidr[] = []
  for (const c of cidrs) {
    const cidrStr = typeof c === 'string' ? c : c?.cidr
    const id = typeof c === 'object' ? c.id : undefined
    const description = typeof c === 'object' ? c.description : undefined
    if (!cidrStr || cidrStr.includes(':')) continue
    const parsed = parseCidrV4(cidrStr)
    if (!parsed) continue
    result.push({
      network: parsed.network,
      mask: parsed.mask,
      cidr: cidrStr,
      id,
      description,
    })
  }
  return result
}

/**
 * Match a source IP against parsed approved VPN CIDRs using bit arithmetic.
 * Returns the matching VPN range record (with description/id) or null.
 */
export function lookupMatchingVpn(ip: string, vpnCidrs: ParsedVpnCidr[]): ParsedVpnCidr | null {
  for (const vpn of vpnCidrs) {
    if (isIpv4InCidr(ip, vpn)) {
      return vpn
    }
  }
  return null
}

// ─── Asset Lookup ─────────────────────────────────────────────────────────────

/**
 * Look up an AssetRecord by hostname (case-insensitive).
 * Returns undefined if the host is not in the asset inventory.
 */
export function lookupAsset(host: string, assets: AssetRecord[]): AssetRecord | undefined {
  const normalized = host.toLowerCase().trim()
  return assets.find(a => a.host === normalized)
}
