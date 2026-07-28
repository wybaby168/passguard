import { ContextPasswordChecker } from './context.js'
import { DEFAULT_FRONTEND_BLOCKLIST_TEXT } from './default-blocklist.js'
import { HibpPwnedPasswordClient } from './hibp.js'
import { PasswordBlocklist } from './local-blocklist.js'
import {
  PasswordPolicy,
  type AssessOptions,
  type PasswordPolicyConfig,
} from './password-policy.js'
import type {
  PasswordAssessment,
  PwnedPasswordChecker,
  StrengthEstimator,
} from './types.js'
import { ZxcvbnTsStrengthEstimator } from './zxcvbn-adapter.js'

export interface PassGuardOptions {
  /** 产品名、企业名等所有用户共享的上下文词。 */
  readonly contextWords?: readonly string[]
  /** 自定义本地名单；默认使用包内置的 25,000 条高频名单。 */
  readonly blocklist?: PasswordBlocklist
  /** 设为 false 可关闭强度估算；默认使用 zxcvbn-ts。 */
  readonly strengthEstimator?: StrengthEstimator | false
  /** 设为 false 可关闭 HIBP；默认仅发送 SHA-1 前 5 位做 k-anonymity 查询。 */
  readonly pwnedChecker?: PwnedPasswordChecker | false
  readonly config?: Partial<PasswordPolicyConfig>
}

export interface PassGuardCheckOptions extends Partial<AssessOptions> {
  readonly mfaProtected?: boolean
}

/**
 * PassGuard 的高级 API。实例是无状态的，可在整个应用中安全复用。
 */
export class PassGuard {
  readonly #policy: PasswordPolicy

  constructor(options: PassGuardOptions = {}) {
    const blocklist = options.blocklist
      ?? PasswordBlocklist.fromText(DEFAULT_FRONTEND_BLOCKLIST_TEXT)
    const strengthEstimator = options.strengthEstimator === false
      ? undefined
      : (options.strengthEstimator ?? new ZxcvbnTsStrengthEstimator())
    const pwnedChecker = options.pwnedChecker === false
      ? undefined
      : (options.pwnedChecker ?? new HibpPwnedPasswordClient())

    this.#policy = new PasswordPolicy({
      blocklist,
      contextChecker: new ContextPasswordChecker(options.contextWords),
      ...(strengthEstimator ? { strengthEstimator } : {}),
      ...(pwnedChecker ? { pwnedChecker } : {}),
      ...(options.config ? { config: options.config } : {}),
    })
  }

  check(password: string, options: PassGuardCheckOptions = {}): Promise<PasswordAssessment> {
    return this.#policy.assess(password, {
      mfaProtected: options.mfaProtected ?? false,
      ...(options.context ? { context: options.context } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
    })
  }
}

/** 一行创建可复用的完整密码防御实例。 */
export function createPassGuard(options: PassGuardOptions = {}): PassGuard {
  return new PassGuard(options)
}
