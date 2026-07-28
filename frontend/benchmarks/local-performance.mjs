import { performance } from 'node:perf_hooks'

import {
  createPassGuard,
  PasswordBlocklist,
} from '../dist/index.js'

const initStarted = performance.now()
const guard = createPassGuard({
  strengthEstimator: false,
  pwnedChecker: false,
  contextWords: ['PassGuard', 'Example Corp'],
})
const initMs = performance.now() - initStarted

const list = PasswordBlocklist.fromText(
  await (await import('node:fs/promises')).readFile(
    new URL('../public/passwords/frontend-blocklist.txt', import.meta.url),
    'utf8',
  ),
)
const lookups = 1_000_000
const lookupStarted = performance.now()
for (let index = 0; index < lookups; index += 1) {
  list.contains(index % 2 === 0 ? '123456' : 'not-in-the-list-2026')
}
const lookupMs = performance.now() - lookupStarted

const assessments = 50_000
const assessmentStarted = performance.now()
for (let index = 0; index < assessments; index += 1) {
  await guard.check(`a genuinely long candidate ${index}!`)
}
const assessmentMs = performance.now() - assessmentStarted

console.log(JSON.stringify({
  runtime: process.version,
  blocklistEntries: list.size,
  initializationMs: Number(initMs.toFixed(2)),
  localLookups: lookups,
  localLookupsPerSecond: Math.round(lookups / (lookupMs / 1_000)),
  localAssessments: assessments,
  localAssessmentsPerSecond: Math.round(assessments / (assessmentMs / 1_000)),
}, null, 2))
