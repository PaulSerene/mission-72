/**
 * Unit tests for Asset and IP-Location Parsers & CIDR Matching — Mission 72
 */

import { describe, expect, it } from 'vitest'
import {
  parseAssets,
  parseIpLocations,
  parseCidrV4,
  isIpv4InCidr,
  isIpInAnyCidr,
  lookupLocation,
  lookupAsset,
  ipv4ToInt,
} from './assets'

describe('ipv4ToInt', () => {
  it('converts dotted quad to correct 32-bit unsigned integer', () => {
    expect(ipv4ToInt('0.0.0.0')).toBe(0)
    expect(ipv4ToInt('255.255.255.255')).toBe(0xffffffff >>> 0)
    expect(ipv4ToInt('192.168.1.1')).toBe(((192 << 24) | (168 << 16) | (1 << 8) | 1) >>> 0)
  })

  it('returns null for invalid IPv4', () => {
    expect(ipv4ToInt('256.0.0.1')).toBeNull()
    expect(ipv4ToInt('192.168.1')).toBeNull()
    expect(ipv4ToInt('invalid')).toBeNull()
  })
})

describe('parseCidrV4 and isIpv4InCidr (Bit Arithmetic)', () => {
  it('correctly matches within a standard /24 subnet', () => {
    const cidr = parseCidrV4('192.168.1.0/24')!
    expect(cidr).not.toBeNull()

    // Network address boundary
    expect(isIpv4InCidr('192.168.1.0', cidr)).toBe(true)
    // Broadcast address boundary
    expect(isIpv4InCidr('192.168.1.255', cidr)).toBe(true)
    // Internal host
    expect(isIpv4InCidr('192.168.1.42', cidr)).toBe(true)

    // Outside boundary
    expect(isIpv4InCidr('192.168.0.255', cidr)).toBe(false)
    expect(isIpv4InCidr('192.168.2.0', cidr)).toBe(false)
  })

  it('correctly matches /0 prefix (all IPv4)', () => {
    const cidr = parseCidrV4('0.0.0.0/0')!
    expect(isIpv4InCidr('10.0.0.1', cidr)).toBe(true)
    expect(isIpv4InCidr('203.0.113.5', cidr)).toBe(true)
    expect(isIpv4InCidr('255.255.255.255', cidr)).toBe(true)
  })

  it('correctly matches /32 prefix (single host)', () => {
    const cidr = parseCidrV4('192.0.2.55/32')!
    expect(isIpv4InCidr('192.0.2.55', cidr)).toBe(true)
    expect(isIpv4InCidr('192.0.2.54', cidr)).toBe(false)
    expect(isIpv4InCidr('192.0.2.56', cidr)).toBe(false)
  })

  it('handles host-bits in the CIDR specification correctly (masks network)', () => {
    // 192.168.1.100/24 should have network 192.168.1.0
    const cidr = parseCidrV4('192.168.1.100/24')!
    expect(isIpv4InCidr('192.168.1.1', cidr)).toBe(true)
    expect(isIpv4InCidr('192.168.1.254', cidr)).toBe(true)
    expect(isIpv4InCidr('192.168.2.1', cidr)).toBe(false)
  })

  it('avoids false location matches caused by naive string-prefix comparison', () => {
    // With naive string-prefix comparison: "10.0.10.5".startsWith("10.0.1") would be TRUE!
    // But bit arithmetic correctly identifies that 10.0.10.5 is NOT in 10.0.1.0/24.
    const cidr = parseCidrV4('10.0.1.0/24')!
    expect(isIpv4InCidr('10.0.10.5', cidr)).toBe(false)
    expect(isIpv4InCidr('10.0.100.5', cidr)).toBe(false)
    expect(isIpv4InCidr('10.0.1.5', cidr)).toBe(true)

    // Another example: "10.0.1.100".startsWith("10.0.1.10") would be TRUE for /32
    const singleHostCidr = parseCidrV4('10.0.1.10/32')!
    expect(isIpv4InCidr('10.0.1.100', singleHostCidr)).toBe(false)
    expect(isIpv4InCidr('10.0.1.10', singleHostCidr)).toBe(true)
  })

  it('isIpInAnyCidr matches across an array of pre-parsed CIDRs', () => {
    const cidrs = [parseCidrV4('10.0.1.0/24')!, parseCidrV4('192.0.2.0/24')!]
    expect(isIpInAnyCidr('10.0.1.42', cidrs)).toBe(true)
    expect(isIpInAnyCidr('192.0.2.100', cidrs)).toBe(true)
    expect(isIpInAnyCidr('172.16.0.1', cidrs)).toBe(false)
  })
})

describe('parseAssets', () => {
  it('normalizes hostnames to lowercase and handles boolean aliases', () => {
    const csv = [
      'Host,Role,Privileged',
      'DC-PRIMARY.CORP.LOCAL,domain-controller,true',
      'db-01.corp.local,database,yes',
      'app-01.corp.local,web,1',
      'fs-01.corp.local,files,y',
      'workstation-1.corp.local,workstation,false',
      'workstation-2.corp.local,workstation,no',
      'workstation-3.corp.local,workstation,0',
      'workstation-4.corp.local,workstation,n',
    ].join('\n')

    const { assets, invalidRows } = parseAssets(csv)
    expect(invalidRows).toHaveLength(0)
    expect(assets).toHaveLength(8)

    expect(assets[0]).toEqual({
      host: 'dc-primary.corp.local',
      role: 'domain-controller',
      privileged: true,
    })
    expect(assets[1].privileged).toBe(true)
    expect(assets[2].privileged).toBe(true)
    expect(assets[3].privileged).toBe(true)
    expect(assets[4].privileged).toBe(false)
    expect(assets[5].privileged).toBe(false)
    expect(assets[6].privileged).toBe(false)
    expect(assets[7].privileged).toBe(false)
  })

  it('rejects rows with missing host or role or unparseable privileged values', () => {
    const csv = [
      'host,role,privileged',
      ',web,true',
      'host-1,,false',
      'host-2,web,maybe',
    ].join('\n')

    const { assets, invalidRows } = parseAssets(csv)
    expect(assets).toHaveLength(0)
    expect(invalidRows).toHaveLength(3)
  })

  it('lookupAsset finds assets case-insensitively', () => {
    const assets = [
      { host: 'server-01.corp.local', role: 'web', privileged: false },
    ]
    expect(lookupAsset('SERVER-01.CORP.LOCAL', assets)).toBeDefined()
    expect(lookupAsset('other.corp.local', assets)).toBeUndefined()
  })
})

describe('parseIpLocations & IPv6 Limitation', () => {
  it('parses valid IPv4 CIDRs and matches locations', () => {
    const csv = [
      'cidr,location',
      '10.0.0.0/16,Corporate Headquarters',
      '172.16.0.0/16,Datacenter East',
      '192.0.2.0/24,Approved VPN Pool',
    ].join('\n')

    const { locations, invalidRows } = parseIpLocations(csv)
    expect(invalidRows).toHaveLength(0)
    expect(locations).toHaveLength(3)

    expect(lookupLocation('10.0.5.12', locations)).toBe('Corporate Headquarters')
    expect(lookupLocation('172.16.1.1', locations)).toBe('Datacenter East')
    expect(lookupLocation('192.0.2.100', locations)).toBe('Approved VPN Pool')
    expect(lookupLocation('8.8.8.8', locations)).toBeNull()
  })

  it('clearly reports IPv6 limitation and rejects IPv6 CIDRs without crashing', () => {
    const csv = [
      'cidr,location',
      '2001:db8::/32,IPv6 Range',
      '10.0.0.0/24,Valid Range',
    ].join('\n')

    const { locations, invalidRows } = parseIpLocations(csv)
    expect(locations).toHaveLength(1)
    expect(invalidRows).toHaveLength(1)
    expect(invalidRows[0].reason).toContain('IPv6 CIDRs are not supported (limitation)')
  })
})
