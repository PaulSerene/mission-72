/**
 * Synthetic Dataset CLI Generator — Mission 72
 *
 * Standalone Node.js development script for generating and persisting
 * synthetic log fixtures to disk.
 *
 * Usage:
 *   npm run generate-data
 */

import * as fs from 'node:fs'
import * as path from 'node:path'
import { generateSyntheticDataset, type SyntheticDataset } from './generate.ts'

export function writeDatasetFiles(outputDir: string, dataset: SyntheticDataset): void {
  fs.mkdirSync(outputDir, { recursive: true })
  fs.writeFileSync(path.join(outputDir, 'auth_logs.csv'), dataset.authCsv, 'utf-8')
  fs.writeFileSync(path.join(outputDir, 'assets.csv'), dataset.assetsCsv, 'utf-8')
  fs.writeFileSync(path.join(outputDir, 'ip_locations.csv'), dataset.ipLocationsCsv, 'utf-8')
  fs.writeFileSync(path.join(outputDir, 'expected.json'), JSON.stringify(dataset.manifest, null, 2), 'utf-8')
}

// ─── CLI Execution ────────────────────────────────────────────────────────────

const fixturesDir = path.resolve(process.cwd(), 'src/data/fixtures')
const publicFixturesDir = path.resolve(process.cwd(), 'public/fixtures')

console.log(`Generating synthetic dataset (Seed: 42)...`)
const dataset = generateSyntheticDataset(42)

console.log(`Writing fixtures to: ${fixturesDir}`)
writeDatasetFiles(fixturesDir, dataset)

console.log(`Writing public fixtures to: ${publicFixturesDir}`)
writeDatasetFiles(publicFixturesDir, dataset)

console.log(`✓ Synthetic dataset generated successfully:`)
console.log(`  - Total Rows: ${dataset.stats.totalRows}`)
console.log(`  - Malformed Rows: ${dataset.stats.malformedRows}`)
console.log(`  - Duplicate Rows: ${dataset.stats.duplicateRows}`)
console.log(`  - Planted Scenarios: ${dataset.stats.scenarioCount}`)
