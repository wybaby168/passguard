import assert from 'node:assert/strict'
import test from 'node:test'

import {
  DEFAULT_SYMBOLS,
  generatePassword,
} from '../dist/generator.js'

test('generates different passwords with every default category', () => {
  const first = generatePassword()
  const second = generatePassword()
  assert.equal(Array.from(first).length, 20)
  assert.notEqual(first, second)
  assert.match(first, /[a-z]/u)
  assert.match(first, /[A-Z]/u)
  assert.match(first, /[0-9]/u)
  assert.ok(Array.from(first).some((value) => DEFAULT_SYMBOLS.includes(value)))
})

test('supports strict category counts and ambiguous filtering', () => {
  const password = generatePassword({
    length: 32,
    minimumLowercase: 4,
    minimumUppercase: 4,
    minimumDigits: 4,
    minimumSymbols: 4,
    excludeAmbiguous: true,
  })
  assert.equal(Array.from(password).length, 32)
  assert.doesNotMatch(password, /[0O1lI]/u)
})

test('rejects impossible or empty alphabets', () => {
  assert.throws(
    () => generatePassword({ length: 4, minimumSymbols: 5 }),
    /smaller/,
  )
  assert.throws(
    () => generatePassword({ lowercaseAlphabet: '' }),
    /must not be empty/,
  )
})

test('counts supplementary Unicode code points as one character', () => {
  const password = generatePassword({
    length: 12,
    lowercaseAlphabet: '😀🔐',
    uppercaseAlphabet: '🛡️',
    digitsAlphabet: '１２３',
    symbolsAlphabet: '✨',
    minimumLowercase: 12,
    minimumUppercase: 0,
    minimumDigits: 0,
    minimumSymbols: 0,
  })
  assert.equal(Array.from(password).length, 12)
  assert.ok(Array.from(password).every((value) => value === '😀' || value === '🔐'))
})
