import { ContextPasswordChecker } from './context.js'
import { PasswordBlocklist } from './local-blocklist.js'
import { countUnicodeCodePoints, normalizePassword } from './normalize.js'
import type {
  PasswordAssessment,
  PasswordContext,
  PasswordViolation,
  PwnedPasswordChecker,
  StrengthEstimator,
} from './types.js'

export type HibpFailureMode = 'ALLOW_WITH_LOCAL_CHECKS' | 'REJECT'

export interface PasswordPolicyConfig {
  readonly minLengthSingleFactor: number
  readonly minLengthWithMfa: number
  readonly maxLength: number
  readonly minimumStrengthScore: number
  readonly rejectPwnedCountAtLeast: number
  readonly hibpFailureMode: HibpFailureMode
  readonly skipRemoteCheckWhenAlreadyRejected: boolean
}

export interface PasswordPolicyDependencies {
  readonly blocklist: PasswordBlocklist
  readonly contextChecker?: ContextPasswordChecker
  readonly strengthEstimator?: StrengthEstimator
  readonly pwnedChecker?: PwnedPasswordChecker
  readonly config?: Partial<PasswordPolicyConfig>
}

export interface AssessOptions {
  readonly mfaProtected: boolean
  readonly context?: PasswordContext
  readonly signal?: AbortSignal
}

export const DEFAULT_PASSWORD_POLICY: PasswordPolicyConfig = {
  minLengthSingleFactor: 15,
  minLengthWithMfa: 8,
  maxLength: 128,
  minimumStrengthScore: 3,
  rejectPwnedCountAtLeast: 1,
  hibpFailureMode: 'ALLOW_WITH_LOCAL_CHECKS',
  skipRemoteCheckWhenAlreadyRejected: true,
}

const MESSAGES = {
  empty: '密码不能为空。',
  tooShort: '密码长度不足，请使用更长且不易猜到的密码。',
  tooLong: '密码超过系统允许的最大长度。',
  common: '该密码过于常见，请更换。',
  context: '密码不能使用用户名、邮箱、产品名或企业名的常见变体。',
  weak: '该密码仍然容易被猜中，请增加长度并避免常见词、重复和序列。',
  pwned: '该密码已出现在泄露数据中，请更换。',
  pwnedUnavailable: '暂时无法完成泄露密码校验，请稍后重试。',
} as const

function add(violations: PasswordViolation[], code: PasswordViolation['code'], message: string): void {
  if (!violations.some((item) => item.code === code)) violations.push({ code, message })
}

function contextUserInputs(context: PasswordContext): string[] {
  return [
    context.username,
    context.email,
    context.displayName,
    context.serviceName,
    ...(context.organizationWords ?? []),
  ].filter((value): value is string => Boolean(value))
}

export class PasswordPolicy {
  readonly #blocklist: PasswordBlocklist
  readonly #contextChecker: ContextPasswordChecker
  readonly #strengthEstimator: StrengthEstimator | undefined
  readonly #pwnedChecker: PwnedPasswordChecker | undefined
  readonly #config: PasswordPolicyConfig

  constructor(dependencies: PasswordPolicyDependencies) {
    this.#blocklist = dependencies.blocklist
    this.#contextChecker = dependencies.contextChecker ?? new ContextPasswordChecker()
    this.#strengthEstimator = dependencies.strengthEstimator
    this.#pwnedChecker = dependencies.pwnedChecker
    this.#config = { ...DEFAULT_PASSWORD_POLICY, ...dependencies.config }
    if (this.#config.minLengthSingleFactor < 1 || this.#config.minLengthWithMfa < 1) {
      throw new Error('minimum lengths must be positive')
    }
    if (this.#config.maxLength < 64) throw new Error('maxLength must be at least 64')
    if (this.#config.maxLength < Math.max(
      this.#config.minLengthSingleFactor,
      this.#config.minLengthWithMfa,
    )) {
      throw new Error('maxLength must not be smaller than a minimum length')
    }
    if (this.#config.minimumStrengthScore < 0 || this.#config.minimumStrengthScore > 4) {
      throw new Error('minimumStrengthScore must be 0..4')
    }
    if (!Number.isFinite(this.#config.rejectPwnedCountAtLeast)
      || this.#config.rejectPwnedCountAtLeast < 1) {
      throw new Error('rejectPwnedCountAtLeast must be positive')
    }
  }

  async assess(password: string, options: AssessOptions): Promise<PasswordAssessment> {
    const normalized = normalizePassword(password)
    const length = countUnicodeCodePoints(normalized)
    const context = options.context ?? {}
    const violations: PasswordViolation[] = []

    if (length === 0) add(violations, 'EMPTY', MESSAGES.empty)
    const minimum = options.mfaProtected
      ? this.#config.minLengthWithMfa
      : this.#config.minLengthSingleFactor
    if (length > 0 && length < minimum) add(violations, 'TOO_SHORT', MESSAGES.tooShort)
    if (length > this.#config.maxLength) add(violations, 'TOO_LONG', MESSAGES.tooLong)
    if (this.#blocklist.contains(normalized)) add(violations, 'COMMON_PASSWORD', MESSAGES.common)
    if (this.#contextChecker.isBlocked(normalized, context)) {
      add(violations, 'CONTEXT_PASSWORD', MESSAGES.context)
    }

    let strengthScore: number | null = null
    if (this.#strengthEstimator && length > 0) {
      const strength = await this.#strengthEstimator.estimate(normalized, contextUserInputs(context))
      strengthScore = strength.score
      if (strength.score < this.#config.minimumStrengthScore) {
        add(violations, 'LOW_STRENGTH', MESSAGES.weak)
      }
    }

    let pwnedStatus: PasswordAssessment['pwnedStatus'] = 'skipped'
    let pwnedCount: number | null = null
    const shouldCallRemote = this.#pwnedChecker
      && !(this.#config.skipRemoteCheckWhenAlreadyRejected && violations.length > 0)
    if (shouldCallRemote) {
      const result = await this.#pwnedChecker!.check(normalized, options.signal)
      pwnedStatus = result.status
      pwnedCount = result.count
      if (result.status === 'pwned' && (result.count ?? 0) >= this.#config.rejectPwnedCountAtLeast) {
        add(violations, 'PWNED_PASSWORD', MESSAGES.pwned)
      } else if (result.status === 'unavailable' && this.#config.hibpFailureMode === 'REJECT') {
        add(violations, 'PWNED_CHECK_UNAVAILABLE', MESSAGES.pwnedUnavailable)
      }
    }

    return {
      accepted: violations.length === 0,
      codePointLength: length,
      strengthScore,
      pwnedStatus,
      pwnedCount,
      violations,
    }
  }
}
