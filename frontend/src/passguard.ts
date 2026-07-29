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

/** 创建高级 PassGuard 实例时可替换的组件与策略。 */
export interface PassGuardOptions {
  /** 产品名、企业名等所有用户共享的上下文词。 */
  readonly contextWords?: readonly string[]
  /** 自定义本地名单；默认使用包内置的 25,000 条高频名单。 */
  readonly blocklist?: PasswordBlocklist
  /** 设为 false 可关闭强度估算；默认使用 zxcvbn-ts。 */
  readonly strengthEstimator?: StrengthEstimator | false
  /** 设为 false 可关闭 HIBP；默认仅发送 SHA-1 前 5 位做 k-anonymity 查询。 */
  readonly pwnedChecker?: PwnedPasswordChecker | false
  /** 默认策略的局部覆盖；未提供字段继续使用安全默认值。 */
  readonly config?: Partial<PasswordPolicyConfig>
}

/** 单次 PassGuard.check 调用选项。 */
export interface PassGuardCheckOptions extends Partial<AssessOptions> {
  /** 是否使用 MFA 场景最小长度；默认 false。 */
  readonly mfaProtected?: boolean
}

/**
 * PassGuard 的高级 API。实例是无状态的，可在整个应用中安全复用。
 */
export class PassGuard {
  readonly #policy: PasswordPolicy

  /**
   * 创建高级实例并加载缺省组件。
   *
   * @param options 名单、上下文词、估算器、泄露检查器和策略覆盖
   */
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

  /**
   * 完整检查密码。
   *
   * @param password 原始密码；执行 NFC 规范化但不会 trim
   * @param options MFA、上下文和取消选项
   * @returns 只读评估结果
   */
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
