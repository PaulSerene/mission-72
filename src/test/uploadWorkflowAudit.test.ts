import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { runDetectionPipeline } from '../engine/pipeline'

describe('Upload Workflow UI Reproduction Audit', () => {
  const readData = (relPath: string) =>
    fs.readFileSync(path.resolve(process.cwd(), 'PS2_Suspicious_Login_Detector', relPath), 'utf8')
  it('TC01_A: normal logins produce 0 attack incidents in pure upload workflow', () => {
    const raw = readData('data/mission04_tests/TC01_normal_logins_A.csv')
    const res = runDetectionPipeline({ authData: raw })
    const b = res.baselines.get('aarav.nair')
    console.log('aarav.nair baseline:', {
      knownIps: b ? Array.from(b.knownIps) : [],
      knownLocations: b ? Array.from(b.knownLocations) : [],
      status: b?.status,
      count: b?.trainingEventCount,
    })
    console.log('TC01_A matches for aarav:', res.ruleMatches.filter(m => m.username === 'aarav.nair').map(m => m.evidence.description))
    const attacks = res.ruleMatches.filter(m =>
      ['brute_force', 'burst_success', 'password_spray', 'impossible_travel', 'new_hosts'].includes(m.ruleId)
    )
    expect(attacks).toHaveLength(0)
    expect(res.incidents).toHaveLength(0)
  })

  it('TC01_B: normal logins produce 0 attack incidents in pure upload workflow', () => {
    const raw = readData('data/mission04_tests/TC01_normal_logins_B.csv')
    const res = runDetectionPipeline({ authData: raw })
    const attacks = res.ruleMatches.filter(m =>
      ['brute_force', 'burst_success', 'password_spray', 'impossible_travel', 'new_hosts'].includes(m.ruleId)
    )
    expect(attacks).toHaveLength(0)
    expect(res.incidents).toHaveLength(0)
  })

  it('TC02_A: repeated failures produce brute_force incident for pooja.reddy', () => {
    const raw = readData('data/mission04_tests/TC02_repeated_failures_A.csv')
    const res = runDetectionPipeline({ authData: raw })
    expect(res.ruleMatches.some(m => m.ruleId === 'brute_force')).toBe(true)
    expect(res.incidents).toHaveLength(1)
    expect(res.incidents[0].username).toBe('pooja.reddy')
  })

  it('TC02_B: repeated failures produce brute_force incident for leela_pillai', () => {
    const raw = readData('data/mission04_tests/TC02_repeated_failures_B.csv')
    const res = runDetectionPipeline({ authData: raw })
    expect(res.ruleMatches.some(m => m.ruleId === 'brute_force')).toBe(true)
    expect(res.incidents).toHaveLength(1)
    expect(res.incidents[0].username).toBe('leela_pillai')
  })

  it('TC03_A: failure then success produces burst_success incident for rahul.gupta', () => {
    const raw = readData('data/mission04_tests/TC03_failure_then_success_A.csv')
    const res = runDetectionPipeline({ authData: raw })
    expect(res.ruleMatches.some(m => m.ruleId === 'burst_success')).toBe(true)
    expect(res.incidents).toHaveLength(1)
    expect(res.incidents[0].username).toBe('rahul.gupta')
  })

  it('TC03_B: failure then success produces burst_success incident for mohan_das', () => {
    const raw = readData('data/mission04_tests/TC03_failure_then_success_B.csv')
    const res = runDetectionPipeline({ authData: raw })
    expect(res.ruleMatches.some(m => m.ruleId === 'burst_success')).toBe(true)
    expect(res.incidents).toHaveLength(1)
    expect(res.incidents[0].username).toBe('mohan_das')
  })

  it('TC04_A: password spraying produces password_spray incidents', () => {
    const raw = readData('data/mission04_tests/TC04_password_spraying_A.csv')
    const res = runDetectionPipeline({ authData: raw })
    expect(res.ruleMatches.some(m => m.ruleId === 'password_spray')).toBe(true)
    expect(res.incidents.length).toBeGreaterThanOrEqual(10)
  })

  it('TC04_B: password spraying produces password_spray incidents', () => {
    const raw = readData('data/mission04_tests/TC04_password_spraying_B.csv')
    const res = runDetectionPipeline({ authData: raw })
    expect(res.ruleMatches.some(m => m.ruleId === 'password_spray')).toBe(true)
    expect(res.incidents.length).toBeGreaterThanOrEqual(10)
  })

  it('TC05_A: detects impossible_travel for sneha.nair and suppresses aditya.iyer approved VPN', () => {
    const raw = readData('data/mission04_tests/TC05_impossible_travel_vs_vpn_A.csv')
    const res = runDetectionPipeline({ authData: raw })
    const travel = res.ruleMatches.filter(m => m.ruleId === 'impossible_travel')
    expect(travel).toHaveLength(1)
    expect(travel[0].username).toBe('sneha.nair')
    expect(res.suppressedAlerts.some(s => s.username === 'aditya.iyer')).toBe(true)
  })

  it('TC05_B: detects impossible_travel for neha_das and suppresses om_khan approved VPN', () => {
    const raw = readData('data/mission04_tests/TC05_impossible_travel_vs_vpn_B.csv')
    const res = runDetectionPipeline({ authData: raw })
    const travel = res.ruleMatches.filter(m => m.ruleId === 'impossible_travel')
    expect(travel).toHaveLength(1)
    expect(travel[0].username).toBe('neha_das')
    expect(res.suppressedAlerts.some(s => s.username === 'om_khan')).toBe(true)
  })

  it('TC06_A: detects fan-out for kavya.reddy and suppresses helpdesk.svc during maintenance', () => {
    const raw = readData('data/mission04_tests/TC06_fan_out_vs_maintenance_A.csv')
    const res = runDetectionPipeline({ authData: raw })
    const fanout = res.ruleMatches.filter(m => m.ruleId === 'new_hosts')
    expect(fanout.some(m => m.username === 'kavya.reddy')).toBe(true)
    expect(fanout.some(m => m.username === 'helpdesk.svc')).toBe(false)
  })

  it('TC06_B: detects fan-out for priya_das and suppresses helpdesk_svc during maintenance', () => {
    const raw = readData('data/mission04_tests/TC06_fan_out_vs_maintenance_B.csv')
    const res = runDetectionPipeline({ authData: raw })
    const fanout = res.ruleMatches.filter(m => m.ruleId === 'new_hosts')
    expect(fanout.some(m => m.username === 'priya_das')).toBe(true)
    expect(fanout.some(m => m.username === 'helpdesk_svc')).toBe(false)
  })

  it('TC07_A: deduplicates rows and does not generate brute_force incident', () => {
    const raw = readData('data/mission04_tests/TC07_duplicated_rows_A.csv')
    const res = runDetectionPipeline({ authData: raw })
    expect(res.ingestionReport?.duplicateCount).toBeGreaterThan(0)
    expect(res.ruleMatches.some(m => m.ruleId === 'brute_force')).toBe(false)
  })

  it('TC07_B: deduplicates rows and does not generate brute_force incident', () => {
    const raw = readData('data/mission04_tests/TC07_duplicated_rows_B.csv')
    const res = runDetectionPipeline({ authData: raw })
    expect(res.ingestionReport?.duplicateCount).toBeGreaterThan(0)
    expect(res.ruleMatches.some(m => m.ruleId === 'brute_force')).toBe(false)
  })
})
