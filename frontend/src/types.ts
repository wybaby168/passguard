export type PasswordViolationCode =
  | 'EMPTY'
  | 'TOO_SHORT'
  | 'TOO_LONG'
  | 'COMMON_PASSWORD'
  | 'CONTEXT_PASSWORD'
  | 'LOW_STRENGTH'
  | 'PWNED_PASSWORD'
  | 'PWNED_CHECK_UNAVAILABLE'

export interface PasswordViolation {
  readonly code: PasswordViolationCode
  readonly message: string
}

export interface PasswordContext {
  readonly username?: string
  readonly email?: string
  readonly displayName?: string
  readonly serviceName?: string
  readonly organizationWords?: readonly string[]
}

export type PwnedStatus = 'clear' | 'pwned' | 'unavailable' | 'skipped'

export interface PwnedCheckResult {
  readonly status: Exclude<PwnedStatus, 'skipped'>
  readonly count: number | null
  readonly reason?: string
}

export interface PwnedPasswordChecker {
  check(password: string, signal?: AbortSignal): Promise<PwnedCheckResult>
}

export interface StrengthResult {
  readonly score: number
  readonly warning?: string
  readonly suggestions?: readonly string[]
}

export interface StrengthEstimator {
  estimate(password: string, userInputs?: readonly string[]): Promise<StrengthResult> | StrengthResult
}

export interface PasswordAssessment {
  readonly accepted: boolean
  readonly codePointLength: number
  readonly strengthScore: number | null
  readonly pwnedStatus: PwnedStatus
  readonly pwnedCount: number | null
  readonly violations: readonly PasswordViolation[]
}
