import { contextComparisonKey } from './normalize.js'
import type { PasswordContext } from './types.js'

const COMMON_SUFFIXES = [
  '', '1', '01', '12', '123', '1234', '12345', '123456',
  '!', '!1', '!123', '@123', '#123', '_123', '-123',
] as const

function extractTokens(value: string): string[] {
  const normalized = contextComparisonKey(value)
  const tokens = new Set<string>()
  if (normalized.length >= 3) tokens.add(normalized)

  const emailLocal = normalized.includes('@') ? normalized.slice(0, normalized.indexOf('@')) : ''
  if (emailLocal.length >= 3) tokens.add(emailLocal)

  for (const token of normalized.split(/[^\p{L}\p{N}]+/u)) {
    if (token.length >= 3) tokens.add(token)
  }
  return [...tokens]
}

function addTokenVariants(target: Set<string>, token: string): void {
  for (const suffix of COMMON_SUFFIXES) target.add(`${token}${suffix}`)
  target.add(`${token}${token}`)
  target.add(`123${token}`)

  const year = new Date().getUTCFullYear()
  for (let offset = -1; offset <= 2; offset += 1) {
    target.add(`${token}${year + offset}`)
    target.add(`${token}@${year + offset}`)
  }
}

function candidatesFrom(values: Iterable<string | undefined>): Set<string> {
  const candidates = new Set<string>()
  for (const value of values) {
    if (!value) continue
    for (const token of extractTokens(value)) addTokenVariants(candidates, token)
  }
  return candidates
}

/**
 * 识别用户名、邮箱、显示名、产品名和组织词的常见整串变体。
 */
export class ContextPasswordChecker {
  readonly #globalCandidates: ReadonlySet<string>

  /**
   * @param globalWords 产品名、企业名等所有用户共享的上下文词
   */
  constructor(globalWords: readonly string[] = []) {
    // Global product/organization variants never change, so compute them only
    // once instead of rebuilding the same Set for every password assessment.
    this.#globalCandidates = candidatesFrom(globalWords)
  }

  /**
   * @param password 待检查密码
   * @param context 当前用户与业务上下文
   * @returns 是否应按上下文密码拒绝
   */
  isBlocked(password: string, context: PasswordContext = {}): boolean {
    const key = contextComparisonKey(password)
    if (key.length === 0) return false
    if (this.#globalCandidates.has(key)) return true
    if (!context.username
      && !context.email
      && !context.displayName
      && !context.serviceName
      && (context.organizationWords?.length ?? 0) === 0) {
      return false
    }

    const candidates = candidatesFrom([
      context.username,
      context.email,
      context.displayName,
      context.serviceName,
      ...(context.organizationWords ?? []),
    ])

    // Whole-value comparison only. No substring rejection.
    return candidates.has(key)
  }
}
