/** 稳定的密码策略违规码。业务逻辑应判断 code，而不是解析 message。 */
export type PasswordViolationCode =
  | 'EMPTY'
  | 'TOO_SHORT'
  | 'TOO_LONG'
  | 'COMMON_PASSWORD'
  | 'CONTEXT_PASSWORD'
  | 'LOW_STRENGTH'
  | 'PWNED_PASSWORD'
  | 'PWNED_CHECK_UNAVAILABLE'

/** 单个密码策略违规项。 */
export interface PasswordViolation {
  /** 稳定机器码。 */
  readonly code: PasswordViolationCode
  /** 面向用户的通用中文提示。 */
  readonly message: string
}

/** 当前用户、服务和组织相关的上下文。 */
export interface PasswordContext {
  /** 用户名。 */
  readonly username?: string
  /** 邮箱；上下文检查会额外使用 @ 前的本地部分。 */
  readonly email?: string
  /** 显示名。 */
  readonly displayName?: string
  /** 服务或产品名。 */
  readonly serviceName?: string
  /** 企业、组织或租户相关词。 */
  readonly organizationWords?: readonly string[]
}

/** 泄露密码检查状态；skipped 只由策略层产生。 */
export type PwnedStatus = 'clear' | 'pwned' | 'unavailable' | 'skipped'

/** 泄露密码检查器的结果。 */
export interface PwnedCheckResult {
  /** 检查器不能返回 skipped。 */
  readonly status: Exclude<PwnedStatus, 'skipped'>
  /** 未命中时为 0，命中时为正数，不可用时为 null。 */
  readonly count: number | null
  /** 不可用原因。 */
  readonly reason?: string
}

/** 可替换的异步泄露密码检查器。 */
export interface PwnedPasswordChecker {
  /**
   * 检查已完成 NFC 规范化的密码。
   *
   * @param password 待检查密码
   * @param signal 可选取消信号
   */
  check(password: string, signal?: AbortSignal): Promise<PwnedCheckResult>
}

/** 强度估算器返回的 zxcvbn 兼容结果。 */
export interface StrengthResult {
  /** 0（最弱）到 4（最强）的分值。 */
  readonly score: number
  /** 可选警告。 */
  readonly warning?: string
  /** 可选改进建议。 */
  readonly suggestions?: readonly string[]
}

/** 可替换的同步或异步密码强度估算器。 */
export interface StrengthEstimator {
  /**
   * @param password 已完成 NFC 规范化的密码
   * @param userInputs 用户名、邮箱、产品名等上下文输入
   */
  estimate(password: string, userInputs?: readonly string[]): Promise<StrengthResult> | StrengthResult
}

/** 一次完整密码判定的只读结果。 */
export interface PasswordAssessment {
  /** 没有违规项时为 true。 */
  readonly accepted: boolean
  /** NFC 后的 Unicode 码点数。 */
  readonly codePointLength: number
  /** 0 到 4 的强度分；未估算时为 null。 */
  readonly strengthScore: number | null
  /** 泄露密码检查状态。 */
  readonly pwnedStatus: PwnedStatus
  /** 泄露出现次数；未查或不可用时通常为 null。 */
  readonly pwnedCount: number | null
  /** 按执行顺序产生的只读违规项。 */
  readonly violations: readonly PasswordViolation[]
}
