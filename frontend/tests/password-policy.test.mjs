import assert from 'node:assert/strict'
import test from 'node:test'

import {
  ContextPasswordChecker,
  createPassGuard,
  HibpPwnedPasswordClient,
  PasswordBlocklist,
  PasswordPolicy,
} from '../dist/index.js'

const strongEstimator = { estimate: () => ({ score: 4 }) }
const weakEstimator = { estimate: () => ({ score: 1 }) }
const clearPwned = { check: async () => ({ status: 'clear', count: 0 }) }
const pwned = { check: async () => ({ status: 'pwned', count: 42 }) }

test('preserves spaces and uses NFC exact matching', () => {
  const list = PasswordBlocklist.fromText(' password\npa\\ssword\ne\u0301xample\n')
  assert.equal(list.contains(' password'), true)
  assert.equal(list.contains('password'), false)
  assert.equal(list.contains('éxample'), true)
})

test('rejects a common password locally', async () => {
  const policy = new PasswordPolicy({
    blocklist: PasswordBlocklist.fromText('correct horse battery staple\n'),
    strengthEstimator: strongEstimator,
    pwnedChecker: clearPwned,
  })
  const result = await policy.assess('correct horse battery staple', { mfaProtected: false })
  assert.equal(result.accepted, false)
  assert.ok(result.violations.some(({ code }) => code === 'COMMON_PASSWORD'))
  assert.equal(result.pwnedStatus, 'skipped')
})

test('rejects organization and username variants as whole values', async () => {
  const policy = new PasswordPolicy({
    blocklist: new PasswordBlocklist([]),
    contextChecker: new ContextPasswordChecker(['Flyfish']),
    strengthEstimator: strongEstimator,
  })
  const currentYear = new Date().getUTCFullYear()
  const result = await policy.assess(`flyfish@${currentYear}`, {
    mfaProtected: false,
    context: { username: 'wangyu' },
  })
  assert.ok(result.violations.some(({ code }) => code === 'CONTEXT_PASSWORD'))
})

test('rejects a pwned password after local checks pass', async () => {
  const policy = new PasswordPolicy({
    blocklist: new PasswordBlocklist([]),
    strengthEstimator: strongEstimator,
    pwnedChecker: pwned,
  })
  const result = await policy.assess('a genuinely long candidate 2026!', { mfaProtected: false })
  assert.equal(result.pwnedStatus, 'pwned')
  assert.equal(result.pwnedCount, 42)
  assert.ok(result.violations.some(({ code }) => code === 'PWNED_PASSWORD'))
})

test('uses 15 chars without MFA, 8 with MFA, and strength signal', async () => {
  const blocklist = new PasswordBlocklist([])
  const noMfa = new PasswordPolicy({ blocklist, strengthEstimator: strongEstimator })
  const withMfa = new PasswordPolicy({ blocklist, strengthEstimator: weakEstimator })

  const short = await noMfa.assess('12345678901234', { mfaProtected: false })
  assert.ok(short.violations.some(({ code }) => code === 'TOO_SHORT'))

  const weak = await withMfa.assess('long-enough', { mfaProtected: true })
  assert.ok(weak.violations.some(({ code }) => code === 'LOW_STRENGTH'))
})



test('rejects invalid policy configuration', () => {
  const blocklist = new PasswordBlocklist([])
  assert.throws(
    () => new PasswordPolicy({ blocklist, config: { maxLength: 63 } }),
    /at least 64/,
  )
  assert.throws(
    () => new PasswordPolicy({ blocklist, config: { minimumStrengthScore: 5 } }),
    /0\.\.4/,
  )
})

test('uses HIBP k-anonymity prefix and Add-Padding', async () => {
  let requestedUrl = ''
  let requestedHeaders
  const fakeFetch = async (input, init) => {
    requestedUrl = String(input)
    requestedHeaders = init?.headers
    return new Response('1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n00000000000000000000000000000000000:0\n')
  }
  const client = new HibpPwnedPasswordClient({ fetchImpl: fakeFetch })
  const result = await client.check('password')
  assert.equal(requestedUrl.endsWith('/5BAA6'), true)
  assert.equal(requestedHeaders['Add-Padding'], 'true')
  assert.equal(result.status, 'pwned')
  assert.equal(result.count, 42)
})

test('creates a complete PassGuard with one call and supports local-only mode', async () => {
  const guard = createPassGuard({
    contextWords: ['Flyfish'],
    strengthEstimator: strongEstimator,
    pwnedChecker: false,
  })
  const common = await guard.check('123456', { mfaProtected: true })
  assert.equal(common.accepted, false)
  assert.ok(common.violations.some(({ code }) => code === 'COMMON_PASSWORD'))

  const context = await guard.check(`flyfish@${new Date().getUTCFullYear()}`)
  assert.ok(context.violations.some(({ code }) => code === 'CONTEXT_PASSWORD'))
})

test('honors strict HIBP failure mode and already-aborted signals', async () => {
  const unavailable = { check: async () => ({ status: 'unavailable', count: null }) }
  const guard = createPassGuard({
    blocklist: new PasswordBlocklist([]),
    strengthEstimator: strongEstimator,
    pwnedChecker: unavailable,
    config: { hibpFailureMode: 'REJECT' },
  })
  const result = await guard.check('a genuinely long candidate 2026!')
  assert.ok(result.violations.some(({ code }) => code === 'PWNED_CHECK_UNAVAILABLE'))

  let receivedAbortedSignal = false
  const client = new HibpPwnedPasswordClient({
    fetchImpl: async (_input, init) => {
      receivedAbortedSignal = Boolean(init?.signal?.aborted)
      throw new Error('aborted')
    },
  })
  const controller = new AbortController()
  controller.abort(new Error('caller cancelled'))
  const aborted = await client.check('candidate', controller.signal)
  assert.equal(receivedAbortedSignal, true)
  assert.equal(aborted.status, 'unavailable')
})

test('validates HIBP timeout configuration', () => {
  assert.throws(() => new HibpPwnedPasswordClient({ timeoutMs: 0 }), /positive/)
  assert.throws(() => new HibpPwnedPasswordClient({ timeoutMs: Number.NaN }), /positive/)
})
