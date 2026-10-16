# PS 2 — Suspicious Login and Activity Detector (sample data)

Synthetic authentication logs for detecting suspicious logins. Two variants: `_A`, `_B`.

## What participants get

| Path | Purpose |
|------|---------|
| `data/training_auth_logs_days1-5_{A,B}.csv` | Days 1–5, normal activity only — learn each user's baseline (usual hours, IPs, hosts) |
| `data/mission01_auth_logs_days6-7_{A,B}.csv` | Mission 01 test logs: failure bursts, failure-then-success, password spraying + benign lookalikes |
| `data/mission02_auth_logs_days6-7_{A,B}.csv` | Mission 02: adds host fan-out, impossible travel, privileged off-hours; plus helpdesk-maintenance and VPN-travel benign lookalikes |
| `data/mission04_tests/TC01..TC11_*` | One file per Mission 04 test case |
| `reference/asset_list_*`, `privileged_accounts_*`, `user_directory_*`, `ip_locations_*` | Lookups: hosts, admin accounts, shifts, IP→location (no live geolocation) |
| `config/detector_config_{A,B}.yaml` | All thresholds, business hours, VPN ranges, maintenance windows, risk weights |
| `labels/mission01_*` | Ground truth for Mission 01 (self-check) |

## Log columns
`event_id, timestamp, username, source_ip, destination_host, event_type, result, logon_type, failure_reason`

Variant A timestamps are IST (+05:30); variant B are UTC (Z) — teams must normalise, per the config.

## Rules exercised
failure_burst, failure_then_success, password_spraying, unusual_time, new_ip_or_location,
impossible_travel, host_fan_out, privileged_off_hours (defaults in the config).

## Benign lookalikes (must NOT be flagged)
3 typos then success from the user's own IP; an SSO outage where many users fail once from their own IPs
(not spraying); helpdesk visiting many hosts inside a declared maintenance window; an employee on the
company VPN appearing in a new city; a shift worker logging in at night.

## Answer keys (organiser only)
`ORGANISER_ONLY_Answer_Keys/PS2/` — Mission 02 scenarios + per-event labels, Mission 04 expected results.
