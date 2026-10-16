/**
 * Seeded Synthetic Log Generator — Mission 72
 *
 * Generates a reproducible synthetic dataset of ~15 users over 14 days
 * with realistic office-hours activity and 10 distinct, identifiable scenarios.
 *
 * Scenarios:
 *   1. Repeated authentication failures (brute force)
 *   2. Burst of failures followed by success
 *   3. Password spraying across multiple accounts
 *   4. Unusual nighttime login
 *   5. Successful login from new IP and location
 *   6. One account suddenly accessing many unfamiliar hosts
 *   7. Benign maintenance-window activity (suppressed)
 *   8. Approved VPN activity (suppressed)
 *   9. Duplicate records (deduplicated by ingestion)
 *  10. Malformed rows and invalid timestamps (rejected by ingestion)
 *
 * Uses RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and RFC 1918
 * reserved documentation IP addresses.
 *
 * Outputs:
 *   - auth_logs.csv
 *   - assets.csv
 *   - ip_locations.csv
 *   - expected.json
 *
 * Notice: This dataset is synthetic for testing and hackathon evaluation.
 * Results should not be labeled as proof of real-world detection accuracy.
 */
// ─── Deterministic PRNG (Mulberry32) ──────────────────────────────────────────

export function createRng(seed: number = 42) {
  let s = seed >>> 0
  return function next(): number {
    s = (s + 0x6d2b79f5) >>> 0
    let t = Math.imul(s ^ (s >>> 15), 1 | s)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

// ─── Synthetic Data Specifications ────────────────────────────────────────────

export interface ExpectedScenario {
  id: string
  name: string
  category: 'threat' | 'benign_exception' | 'data_hygiene'
  targetUser?: string
  sourceIp?: string
  timeRange: { start: string; end: string }
  expectedRule?: string
  expectedOutcome: 'alert' | 'suppressed' | 'rejected' | 'deduplicated'
  description: string
}

export interface ExpectedManifest {
  description: string
  notice: string
  generatedAt: string
  seed: number
  trainingPeriod: { start: string; end: string }
  analysisPeriod: { start: string; end: string }
  scenarios: ExpectedScenario[]
}

export interface SyntheticDataset {
  authCsv: string
  assetsCsv: string
  ipLocationsCsv: string
  manifest: ExpectedManifest
  stats: {
    totalRows: number
    trainingRows: number
    analysisRows: number
    duplicateRows: number
    malformedRows: number
    scenarioCount: number
  }
}

// ─── Assets CSV Generation ────────────────────────────────────────────────────

export function generateAssetsCsv(): string {
  const rows = [
    'host,role,privileged',
    'dc-primary.corp.local,domain-controller,true',
    'dc-secondary.corp.local,domain-controller,true',
    'db-prod-01.corp.local,database,true',
    'db-prod-02.corp.local,database,true',
    'ldap-auth.corp.local,authentication-server,true',
    'app-web-01.corp.local,web-server,false',
    'app-web-02.corp.local,web-server,false',
    'app-api-01.corp.local,api-gateway,false',
    'fs-storage-01.corp.local,file-server,false',
    'ci-runner-01.corp.local,build-server,false',
    'workstation-alice.corp.local,workstation,false',
    'workstation-bob.corp.local,workstation,false',
    'workstation-charlie.corp.local,workstation,false',
    'workstation-david.corp.local,workstation,false',
    'workstation-emma.corp.local,workstation,false',
    'workstation-frank.corp.local,workstation,false',
    'workstation-grace.corp.local,workstation,false',
    'workstation-hannah.corp.local,workstation,false',
  ]
  return rows.join('\n') + '\n'
}

// ─── IP Locations CSV Generation ──────────────────────────────────────────────

export function generateIpLocationsCsv(): string {
  const rows = [
    'cidr,location',
    '10.0.0.0/16,Corporate LAN',
    '172.16.0.0/16,Engineering Datacenter',
    '192.0.2.0/24,Approved Corporate VPN',
    '198.51.100.0/24,Branch Office',
    '203.0.113.0/24,External / Remote Access',
  ]
  return rows.join('\n') + '\n'
}

// ─── Synthetic Dataset Generator ──────────────────────────────────────────────

export function generateSyntheticDataset(seed: number = 42): SyntheticDataset {
  const rng = createRng(seed)

  const trainingStart = '2026-10-01T00:00:00Z'
  const trainingEnd = '2026-10-08T00:00:00Z'
  const analysisStart = '2026-10-08T00:00:00Z'
  const analysisEnd = '2026-10-15T00:00:00Z'

  interface RawRow {
    timestamp: string
    username: string
    src_ip: string
    dest: string
    event_type: string
    result: string
    logon_type: string
    note?: string
  }

  const rawRows: (RawRow | string)[] = []

  // Normal users definition
  const users = [
    { username: 'alice', ip: '10.0.1.10', host: 'workstation-alice.corp.local' },
    { username: 'bob', ip: '10.0.1.11', host: 'workstation-bob.corp.local' },
    { username: 'charlie', ip: '10.0.1.12', host: 'workstation-charlie.corp.local' },
    { username: 'david', ip: '10.0.1.13', host: 'workstation-david.corp.local' },
    { username: 'emma', ip: '10.0.1.14', host: 'workstation-emma.corp.local' },
    { username: 'frank', ip: '10.0.1.15', host: 'workstation-frank.corp.local' },
    { username: 'grace', ip: '10.0.1.16', host: 'workstation-grace.corp.local' },
    { username: 'hannah', ip: '10.0.1.17', host: 'workstation-hannah.corp.local' },
    { username: 'ian', ip: '10.0.1.18', host: 'app-web-01.corp.local' },
    { username: 'julia', ip: '10.0.1.19', host: 'app-web-02.corp.local' },
    { username: 'victor', ip: '10.0.1.20', host: 'workstation-alice.corp.local' },
    { username: 'diana', ip: '10.0.2.20', host: 'app-api-01.corp.local' },
    { username: 'edward', ip: '10.0.1.50', host: 'app-web-01.corp.local' },
    { username: 'alice_vpn', ip: '10.0.1.25', host: 'ci-runner-01.corp.local' },
    { username: 'svc_backup', ip: '172.16.1.10', host: 'db-prod-01.corp.local' },
  ]

  // 1. Generate ordinary office-hours activity for 14 days (Days 1 to 14)
  // Day 1 = 2026-10-01, Day 14 = 2026-10-14
  for (let day = 1; day <= 14; day++) {
    const dayStr = String(day).padStart(2, '0')
    const isWeekend = day === 3 || day === 4 || day === 10 || day === 11 // Oct 3, 4, 10, 11 are weekends

    for (const u of users) {
      // Service accounts and backup might run every day, regular users mostly on weekdays
      if (isWeekend && u.username !== 'svc_backup' && rng() > 0.15) {
        continue
      }

      // 1 to 3 regular logins per day during working hours (08:00 to 17:00 UTC)
      const logins = 1 + Math.floor(rng() * 2)
      for (let l = 0; l < logins; l++) {
        const hour = 8 + Math.floor(rng() * 9) // 8 to 16
        const min = Math.floor(rng() * 60)
        const sec = Math.floor(rng() * 60)
        const time = `2026-10-${dayStr}T${String(hour).padStart(2, '0')}:${String(min).padStart(2, '0')}:${String(sec).padStart(2, '0')}Z`

        rawRows.push({
          timestamp: time,
          username: u.username,
          src_ip: u.ip,
          dest: u.host,
          event_type: 'authentication',
          result: 'success',
          logon_type: 'interactive',
        })
      }
    }
  }

  // ─── Planted Scenarios (All in Analysis Period: Oct 8 – Oct 14) ──────────────

  // Scenario 1: Repeated authentication failures consistent with brute force
  // User: victor, 6 failures within 60s
  for (let i = 0; i < 6; i++) {
    rawRows.push({
      timestamp: `2026-10-09T14:15:${String(i * 10).padStart(2, '0')}Z`,
      username: 'victor',
      src_ip: '203.0.113.45',
      dest: 'app-web-01.corp.local',
      event_type: 'authentication',
      result: 'failure',
      logon_type: 'network',
      note: 'SCENARIO-01: brute force failure',
    })
  }

  // Scenario 2: Burst of failures followed by a successful login
  // User: charlie, 4 failures then 1 success within 90s
  for (let i = 0; i < 4; i++) {
    rawRows.push({
      timestamp: `2026-10-10T10:30:${String(i * 15).padStart(2, '0')}Z`,
      username: 'charlie',
      src_ip: '203.0.113.77',
      dest: 'workstation-charlie.corp.local',
      event_type: 'authentication',
      result: 'failure',
      logon_type: 'network',
      note: 'SCENARIO-02: burst failure',
    })
  }
  rawRows.push({
    timestamp: '2026-10-10T10:31:15Z',
    username: 'charlie',
    src_ip: '203.0.113.77',
    dest: 'workstation-charlie.corp.local',
    event_type: 'authentication',
    result: 'success',
    logon_type: 'network',
    note: 'SCENARIO-02: burst success',
  })

  // Scenario 3: Password spraying across multiple accounts from a common source
  // Source IP: 198.51.100.99, 5 targets within 120s
  const sprayTargets = ['david', 'emma', 'grace', 'hannah', 'ian']
  sprayTargets.forEach((target, i) => {
    rawRows.push({
      timestamp: `2026-10-11T16:01:${String(i * 10).padStart(2, '0')}Z`,
      username: target,
      src_ip: '198.51.100.99',
      dest: 'app-api-01.corp.local',
      event_type: 'authentication',
      result: 'failure',
      logon_type: 'network',
      note: 'SCENARIO-03: password spray',
    })
  })

  // Scenario 4: Unusual nighttime login
  // User: diana, 03:15 UTC (normal is 08-16 UTC)
  rawRows.push({
    timestamp: '2026-10-12T03:15:22Z',
    username: 'diana',
    src_ip: '10.0.2.20',
    dest: 'app-api-01.corp.local',
    event_type: 'authentication',
    result: 'success',
    logon_type: 'interactive',
    note: 'SCENARIO-04: unusual night login',
  })

  // Scenario 5: Successful login from new IP and location
  // User: edward, from 203.0.113.190 (External / Remote Access)
  rawRows.push({
    timestamp: '2026-10-13T11:00:35Z',
    username: 'edward',
    src_ip: '203.0.113.190',
    dest: 'app-web-01.corp.local',
    event_type: 'authentication',
    result: 'success',
    logon_type: 'interactive',
    note: 'SCENARIO-05: new IP and location',
  })

  // Scenario 6: One account suddenly accessing many previously unfamiliar hosts
  // User: frank, accesses 5 new hosts within 2h
  const newHosts = [
    'dc-primary.corp.local',
    'dc-secondary.corp.local',
    'db-prod-01.corp.local',
    'db-prod-02.corp.local',
    'ldap-auth.corp.local',
  ]
  newHosts.forEach((host, i) => {
    rawRows.push({
      timestamp: `2026-10-13T15:${String(10 + i * 10).padStart(2, '0')}:00Z`,
      username: 'frank',
      src_ip: '10.0.1.15',
      dest: host,
      event_type: 'authentication',
      result: 'success',
      logon_type: 'network',
      note: 'SCENARIO-06: new host access',
    })
  })

  // Scenario 7: Benign maintenance-window activity (suppressed)
  // User: svc_backup, Sunday 02:30 UTC (during configured window Sun 02-04 for svc_backup)
  rawRows.push({
    timestamp: '2026-10-11T02:30:00Z',
    username: 'svc_backup',
    src_ip: '172.16.1.10',
    dest: 'db-prod-01.corp.local',
    event_type: 'authentication',
    result: 'success',
    logon_type: 'service',
    note: 'SCENARIO-07: maintenance window backup',
  })

  // Scenario 8: Approved VPN activity (suppressed)
  // User: alice_vpn, from 192.0.2.88 (inside 192.0.2.0/24 approved VPN)
  rawRows.push({
    timestamp: '2026-10-09T09:30:00Z',
    username: 'alice_vpn',
    src_ip: '192.0.2.88',
    dest: 'ci-runner-01.corp.local',
    event_type: 'authentication',
    result: 'success',
    logon_type: 'interactive',
    note: 'SCENARIO-08: approved VPN login',
  })

  // Scenario 9: Duplicate records
  // Repeat 2 exact records
  const dup1: RawRow = {
    timestamp: '2026-10-04T09:00:00Z',
    username: 'alice',
    src_ip: '10.0.1.10',
    dest: 'workstation-alice.corp.local',
    event_type: 'authentication',
    result: 'success',
    logon_type: 'interactive',
  }
  const dup2: RawRow = {
    timestamp: '2026-10-10T11:00:00Z',
    username: 'bob',
    src_ip: '10.0.1.11',
    dest: 'workstation-bob.corp.local',
    event_type: 'authentication',
    result: 'success',
    logon_type: 'interactive',
  }
  rawRows.push(dup1, dup1, dup1) // dup1 original + 2 duplicates
  rawRows.push(dup2, dup2) // dup2 original + 1 duplicate (total 3 duplicates)

  // Scenario 10: Malformed rows and invalid timestamps
  // 5 invalid rows in total
  const malformedLines = [
    ',alice,10.0.1.10,workstation-alice.corp.local,authentication,success,interactive', // missing timestamp
    '2026-99-99 99:99:99,bob,10.0.1.11,workstation-bob.corp.local,authentication,success,interactive', // invalid timestamp
    '2026-10-09T10:00:00Z,,10.0.1.12,workstation-charlie.corp.local,authentication,success,interactive', // missing username
    '2026-10-09T10:00:00Z,david,999.123.456.1,workstation-david.corp.local,authentication,success,interactive', // invalid IPv4
    '2026-10-09T10:00:00Z,emma,,workstation-emma.corp.local,authentication,success,interactive', // missing source IP
  ]

  // Build CSV content
  const header = 'timestamp,username,src_ip,dest,event_type,result,logon_type'
  const csvLines: string[] = [header]

  let validCount = 0
  for (const item of rawRows) {
    if (typeof item === 'string') {
      csvLines.push(item)
    } else {
      csvLines.push(`${item.timestamp},${item.username},${item.src_ip},${item.dest},${item.event_type},${item.result},${item.logon_type}`)
      validCount++
    }
  }

  // Append malformed lines
  for (const line of malformedLines) {
    csvLines.push(line)
  }

  const authCsv = csvLines.join('\n') + '\n'
  const assetsCsv = generateAssetsCsv()
  const ipLocationsCsv = generateIpLocationsCsv()

  // Build expected manifest
  const manifest: ExpectedManifest = {
    description: 'Ground-truth manifest of planted synthetic scenarios for Mission 72 verification.',
    notice: 'This manifest is strictly for automated test validation and verification reporting. Detection engine code must NEVER import or consult this manifest.',
    generatedAt: new Date().toISOString(),
    seed,
    trainingPeriod: {
      start: trainingStart,
      end: trainingEnd,
    },
    analysisPeriod: {
      start: analysisStart,
      end: analysisEnd,
    },
    scenarios: [
      {
        id: 'SCENARIO-01',
        name: 'Repeated Authentication Failures (Brute Force)',
        category: 'threat',
        targetUser: 'victor',
        sourceIp: '203.0.113.45',
        timeRange: { start: '2026-10-09T14:15:00Z', end: '2026-10-09T14:16:30Z' },
        expectedRule: 'brute_force',
        expectedOutcome: 'alert',
        description: '6 consecutive failed logins within 60 seconds from external IP 203.0.113.45 targeting user victor.',
      },
      {
        id: 'SCENARIO-02',
        name: 'Failure Burst Followed by Successful Login',
        category: 'threat',
        targetUser: 'charlie',
        sourceIp: '203.0.113.77',
        timeRange: { start: '2026-10-10T10:30:00Z', end: '2026-10-10T10:31:30Z' },
        expectedRule: 'burst_success',
        expectedOutcome: 'alert',
        description: '4 consecutive failures followed immediately by a successful authentication within 90 seconds for charlie.',
      },
      {
        id: 'SCENARIO-03',
        name: 'Password Spraying Across Multiple Accounts',
        category: 'threat',
        sourceIp: '198.51.100.99',
        timeRange: { start: '2026-10-11T16:00:00Z', end: '2026-10-11T16:02:00Z' },
        expectedRule: 'password_spray',
        expectedOutcome: 'alert',
        description: 'Single source IP 198.51.100.99 attempts authentication across 5 distinct user accounts within 120s, all failing.',
      },
      {
        id: 'SCENARIO-04',
        name: 'Unusual Nighttime Login',
        category: 'threat',
        targetUser: 'diana',
        timeRange: { start: '2026-10-12T03:15:00Z', end: '2026-10-12T03:16:00Z' },
        expectedRule: 'unusual_hours',
        expectedOutcome: 'alert',
        description: 'Successful login at 03:15 UTC for diana, who exclusively authenticated during 08:00–16:00 UTC in training.',
      },
      {
        id: 'SCENARIO-05',
        name: 'Successful Login from New IP and Location',
        category: 'threat',
        targetUser: 'edward',
        sourceIp: '203.0.113.190',
        timeRange: { start: '2026-10-13T11:00:00Z', end: '2026-10-13T11:01:00Z' },
        expectedRule: 'new_ip_location',
        expectedOutcome: 'alert',
        description: 'Successful login from external IP 203.0.113.190 (External / Remote Access) not seen during training for edward.',
      },
      {
        id: 'SCENARIO-06',
        name: 'Sudden Access to Many Unfamiliar Hosts',
        category: 'threat',
        targetUser: 'frank',
        timeRange: { start: '2026-10-13T15:00:00Z', end: '2026-10-13T16:30:00Z' },
        expectedRule: 'new_hosts',
        expectedOutcome: 'alert',
        description: 'User frank accesses 5 previously-unseen servers (DCs, databases, LDAP) within 90 minutes.',
      },
      {
        id: 'SCENARIO-07',
        name: 'Benign Maintenance-Window Activity',
        category: 'benign_exception',
        targetUser: 'svc_backup',
        timeRange: { start: '2026-10-11T02:00:00Z', end: '2026-10-11T04:00:00Z' },
        expectedRule: 'unusual_hours',
        expectedOutcome: 'suppressed',
        description: 'Off-hours backup job on Sunday at 02:30 UTC for svc_backup is suppressed by maintenance window policy.',
      },
      {
        id: 'SCENARIO-08',
        name: 'Approved VPN Activity',
        category: 'benign_exception',
        targetUser: 'alice_vpn',
        sourceIp: '192.0.2.88',
        timeRange: { start: '2026-10-09T09:30:00Z', end: '2026-10-09T09:31:00Z' },
        expectedRule: 'new_ip_location',
        expectedOutcome: 'suppressed',
        description: 'Login from 192.0.2.88 inside approved corporate VPN CIDR 192.0.2.0/24 is suppressed by VPN policy.',
      },
      {
        id: 'SCENARIO-09',
        name: 'Duplicate Records',
        category: 'data_hygiene',
        timeRange: { start: '2026-10-01T00:00:00Z', end: '2026-10-15T00:00:00Z' },
        expectedOutcome: 'deduplicated',
        description: 'Identical rows are detected by stable content hash; duplicate count is tracked in IngestionReport.',
      },
      {
        id: 'SCENARIO-10',
        name: 'Malformed Rows and Invalid Timestamps',
        category: 'data_hygiene',
        timeRange: { start: '2026-10-01T00:00:00Z', end: '2026-10-15T00:00:00Z' },
        expectedOutcome: 'rejected',
        description: 'Malformed rows with missing fields, invalid dates, or illegal IPs are safely rejected into invalidRows.',
      },
    ],
  }

  return {
    authCsv,
    assetsCsv,
    ipLocationsCsv,
    manifest,
    stats: {
      totalRows: csvLines.length - 1,
      trainingRows: 0, // calculated upon parse
      analysisRows: 0,
      duplicateRows: 3,
      malformedRows: malformedLines.length,
      scenarioCount: manifest.scenarios.length,
    },
  }
}
