/**
 * Unit tests for CSV Ingestion Pipeline — Mission 72
 */

import { describe, expect, it } from 'vitest'
import {
  parseAuthCsv,
  parseTimestamp,
  parseNaiveDatetime,
  parseZonedDatetime,
  parseUnixTimestamp,
  isValidIpv4,
  stableEventId,
} from './ingest'
import { createDefaultConfig } from './pipeline'

describe('parseTimestamp & Timezone Normalization', () => {
  it('parses ISO UTC string with Z suffix', () => {
    const res = parseTimestamp('2026-10-09T14:30:00Z', 'UTC')
    expect(res).toBe('2026-10-09T14:30:00.000Z')
  })

  it('parses ISO string with timezone offset (+02:00)', () => {
    const res = parseTimestamp('2026-10-09T16:30:00+02:00', 'UTC')
    expect(res).toBe('2026-10-09T14:30:00.000Z')
    expect(parseZonedDatetime('2026-10-09T16:30:00+02:00')).toBe('2026-10-09T14:30:00.000Z')
    expect(parseZonedDatetime('2026-10-09 10:00:00')).toBeNull()
  })

  it('interprets naive timestamp using config timezone (America/New_York is UTC-4 in October)', () => {
    // 2026-10-09 10:00:00 EDT (UTC-4) -> 14:00:00 UTC
    const res = parseNaiveDatetime('2026-10-09 10:00:00', 'America/New_York')
    expect(res).toBe('2026-10-09T14:00:00.000Z')
  })

  it('interprets naive timestamp in UTC by default', () => {
    const res = parseNaiveDatetime('2026-10-09 10:00:00', 'UTC')
    expect(res).toBe('2026-10-09T10:00:00.000Z')
  })

  it('parses US date format MM/DD/YYYY HH:mm:ss', () => {
    const res = parseNaiveDatetime('10/09/2026 12:00:00', 'UTC')
    expect(res).toBe('2026-10-09T12:00:00.000Z')
  })

  it('parses 10-digit unix timestamps', () => {
    const res = parseUnixTimestamp('1760000000')
    expect(res).toBe(new Date(1760000000 * 1000).toISOString())
  })

  it('parses 13-digit millisecond unix timestamps', () => {
    const res = parseUnixTimestamp('1760000000000')
    expect(res).toBe(new Date(1760000000000).toISOString())
  })

  it('returns null for unparseable timestamps', () => {
    expect(parseTimestamp('not-a-timestamp', 'UTC')).toBeNull()
    expect(parseTimestamp('2026-99-99 99:99:99', 'UTC')).toBeNull()
    expect(parseTimestamp('', 'UTC')).toBeNull()
  })
})

describe('isValidIpv4', () => {
  it('accepts valid IPv4 addresses', () => {
    expect(isValidIpv4('192.168.1.1')).toBe(true)
    expect(isValidIpv4('10.0.0.1')).toBe(true)
    expect(isValidIpv4('0.0.0.0')).toBe(true)
    expect(isValidIpv4('255.255.255.255')).toBe(true)
  })

  it('rejects invalid octets or formats', () => {
    expect(isValidIpv4('256.1.1.1')).toBe(false)
    expect(isValidIpv4('192.168.1')).toBe(false)
    expect(isValidIpv4('192.168.1.1.1')).toBe(false)
    expect(isValidIpv4('abc.def.ghi.jkl')).toBe(false)
    expect(isValidIpv4('')).toBe(false)
  })
})

describe('stableEventId', () => {
  it('generates consistent ID for identical field content', () => {
    const id1 = stableEventId('alice', '10.0.0.1', '2026-10-09T12:00:00.000Z', 'success', 'host-1')
    const id2 = stableEventId('alice', '10.0.0.1', '2026-10-09T12:00:00.000Z', 'success', 'host-1')
    expect(id1).toBe(id2)
    expect(id1).toMatch(/^ev-[0-9a-f]{8}$/)
  })

  it('generates different IDs for different content', () => {
    const id1 = stableEventId('alice', '10.0.0.1', '2026-10-09T12:00:00.000Z', 'success', 'host-1')
    const id2 = stableEventId('bob', '10.0.0.1', '2026-10-09T12:00:00.000Z', 'success', 'host-1')
    expect(id1).not.toBe(id2)
  })
})

describe('parseAuthCsv & Field Aliases', () => {
  const config = createDefaultConfig()

  it('handles flexible field aliases correctly', () => {
    const csv = [
      'user,source_ip,destination,time,action,status,login_type',
      'bob,10.0.1.5,server-01,2026-10-09T08:00:00Z,login,succeeded,interactive',
    ].join('\n')

    const { events, report } = parseAuthCsv(csv, config)
    expect(report.totalRows).toBe(1)
    expect(report.validEvents).toBe(1)
    expect(events[0].username).toBe('bob')
    expect(events[0].sourceIp).toBe('10.0.1.5')
    expect(events[0].destination).toBe('server-01')
    expect(events[0].eventType).toBe('authentication')
    expect(events[0].outcome).toBe('success')
    expect(events[0].logonType).toBe('interactive')
  })

  it('handles account, ip, host, datetime, event, result aliases', () => {
    const csv = [
      'account,ip,host,datetime,event,result',
      'charlie,172.16.0.20,db-01,2026-10-09 09:15:00,auth,failure',
    ].join('\n')

    const { events, report } = parseAuthCsv(csv, config)
    expect(report.validEvents).toBe(1)
    expect(events[0].username).toBe('charlie')
    expect(events[0].sourceIp).toBe('172.16.0.20')
    expect(events[0].destination).toBe('db-01')
    expect(events[0].outcome).toBe('failure')
  })

  it('tracks missing optional destination and reports missingFields diagnostic', () => {
    const csv = [
      'username,src_ip,timestamp,result',
      'alice,10.0.1.1,2026-10-09T10:00:00Z,success',
    ].join('\n')

    const { events, report } = parseAuthCsv(csv, config)
    expect(events[0].destination).toBeNull()
    expect(report.missingFields).toHaveLength(1)
    expect(report.missingFields[0].field).toBe('destination')
    expect(report.missingFields[0].requiredByRules).toContain('new_hosts')
    expect(report.missingFields[0].affectedRowCount).toBe(1)
  })

  it('rejects malformed rows without crashing', () => {
    const csv = [
      'username,src_ip,timestamp,result',
      ',10.0.1.1,2026-10-09T10:00:00Z,success', // missing username
      'alice,,2026-10-09T10:00:00Z,success', // missing IP
      'bob,999.999.999.999,2026-10-09T10:00:00Z,success', // invalid IPv4
      'charlie,10.0.1.2,not-a-date,success', // invalid timestamp
      'valid_user,10.0.1.3,2026-10-09T10:00:00Z,success', // valid
    ].join('\n')

    const { events, report } = parseAuthCsv(csv, config)
    expect(report.totalRows).toBe(5)
    expect(report.validEvents).toBe(1)
    expect(report.invalidRows).toHaveLength(4)
    expect(events[0].username).toBe('valid_user')
  })

  it('detects and counts duplicate records', () => {
    const csv = [
      'username,src_ip,timestamp,result,dest',
      'alice,10.0.1.1,2026-10-09T10:00:00Z,success,host1',
      'alice,10.0.1.1,2026-10-09T10:00:00Z,success,host1', // duplicate 1
      'alice,10.0.1.1,2026-10-09T10:00:00Z,success,host1', // duplicate 2
      'bob,10.0.1.2,2026-10-09T10:00:00Z,success,host1',
    ].join('\n')

    const { events, report } = parseAuthCsv(csv, config)
    expect(report.totalRows).toBe(4)
    expect(report.duplicateCount).toBe(2)
    expect(events.filter(e => e.isDuplicate)).toHaveLength(2)
  })
})
