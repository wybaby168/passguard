/**
 * 安全密码生成器配置。
 */
export interface PasswordGenerationOptions {
  /** 总长度，默认 20，至少为 4。 */
  readonly length?: number
  /** 最少小写字母数，默认 1。 */
  readonly minimumLowercase?: number
  /** 最少大写字母数，默认 1。 */
  readonly minimumUppercase?: number
  /** 最少数字数，默认 1。 */
  readonly minimumDigits?: number
  /** 最少符号数，默认 1。 */
  readonly minimumSymbols?: number
  /** 自定义小写字母表。 */
  readonly lowercaseAlphabet?: string
  /** 自定义大写字母表。 */
  readonly uppercaseAlphabet?: string
  /** 自定义数字字母表。 */
  readonly digitAlphabet?: string
  /** 自定义符号表。 */
  readonly symbolAlphabet?: string
  /** 是否排除视觉易混淆字符 0O1lI，默认 false。 */
  readonly excludeAmbiguous?: boolean
}

export const DEFAULT_LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
export const DEFAULT_UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
export const DEFAULT_DIGITS = '0123456789'
export const DEFAULT_SYMBOLS = '!@#$%^&*()-_=+[]{}:,.?'

const AMBIGUOUS = new Set(Array.from('0O1lI'))
const UINT32_RANGE = 0x1_0000_0000

/**
 * 使用 Web Crypto 生成满足字符类别约束的密码。
 *
 * @throws {Error} 当前环境没有 Web Crypto、配置非法或字符约束无法满足。
 */
export function generatePassword(options: PasswordGenerationOptions = {}): string {
  const resolved = resolveOptions(options)
  const characters: string[] = []

  append(characters, resolved.lowercase, resolved.minimumLowercase)
  append(characters, resolved.uppercase, resolved.minimumUppercase)
  append(characters, resolved.digits, resolved.minimumDigits)
  append(characters, resolved.symbols, resolved.minimumSymbols)

  const all = [
    ...resolved.lowercase,
    ...resolved.uppercase,
    ...resolved.digits,
    ...resolved.symbols,
  ]
  while (characters.length < resolved.length) {
    characters.push(choose(all))
  }

  for (let index = characters.length - 1; index > 0; index -= 1) {
    const replacement = secureInteger(index + 1)
    const value = characters[index]
    characters[index] = characters[replacement] as string
    characters[replacement] = value as string
  }
  return characters.join('')
}

interface ResolvedOptions {
  readonly length: number
  readonly minimumLowercase: number
  readonly minimumUppercase: number
  readonly minimumDigits: number
  readonly minimumSymbols: number
  readonly lowercase: readonly string[]
  readonly uppercase: readonly string[]
  readonly digits: readonly string[]
  readonly symbols: readonly string[]
}

function resolveOptions(options: PasswordGenerationOptions): ResolvedOptions {
  const length = integer(options.length ?? 20, 'length')
  const minimumLowercase = nonNegativeInteger(
    options.minimumLowercase ?? 1,
    'minimumLowercase',
  )
  const minimumUppercase = nonNegativeInteger(
    options.minimumUppercase ?? 1,
    'minimumUppercase',
  )
  const minimumDigits = nonNegativeInteger(options.minimumDigits ?? 1, 'minimumDigits')
  const minimumSymbols = nonNegativeInteger(
    options.minimumSymbols ?? 1,
    'minimumSymbols',
  )
  if (length < 4) throw new Error('length must be at least 4')
  if (
    minimumLowercase + minimumUppercase + minimumDigits + minimumSymbols >
    length
  ) {
    throw new Error('length is smaller than required character counts')
  }

  const filter = options.excludeAmbiguous === true
  return {
    length,
    minimumLowercase,
    minimumUppercase,
    minimumDigits,
    minimumSymbols,
    lowercase: alphabet(options.lowercaseAlphabet ?? DEFAULT_LOWERCASE, filter),
    uppercase: alphabet(options.uppercaseAlphabet ?? DEFAULT_UPPERCASE, filter),
    digits: alphabet(options.digitAlphabet ?? DEFAULT_DIGITS, filter),
    symbols: alphabet(options.symbolAlphabet ?? DEFAULT_SYMBOLS, filter),
  }
}

function alphabet(value: string, filterAmbiguous: boolean): readonly string[] {
  const characters = Array.from(value).filter(
    (character) => !filterAmbiguous || !AMBIGUOUS.has(character),
  )
  if (characters.length === 0) throw new Error('password alphabet must not be empty')
  return characters
}

function append(target: string[], alphabet: readonly string[], count: number): void {
  for (let index = 0; index < count; index += 1) {
    target.push(choose(alphabet))
  }
}

function choose(alphabet: readonly string[]): string {
  return alphabet[secureInteger(alphabet.length)] as string
}

function secureInteger(bound: number): number {
  const cryptoProvider = globalThis.crypto
  if (cryptoProvider === undefined) {
    throw new Error('Web Crypto getRandomValues is required')
  }
  const limit = Math.floor(UINT32_RANGE / bound) * bound
  const value = new Uint32Array(1)
  do {
    cryptoProvider.getRandomValues(value)
  } while ((value[0] as number) >= limit)
  return (value[0] as number) % bound
}

function integer(value: number, name: string): number {
  if (!Number.isSafeInteger(value)) throw new Error(`${name} must be a safe integer`)
  return value
}

function nonNegativeInteger(value: number, name: string): number {
  const checked = integer(value, name)
  if (checked < 0) throw new Error(`${name} must not be negative`)
  return checked
}
