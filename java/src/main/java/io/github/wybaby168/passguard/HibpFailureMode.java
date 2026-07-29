package io.github.wybaby168.passguard;

/**
 * HIBP 或其他泄露密码检查器不可用时的处理方式。
 */
public enum HibpFailureMode {
    /** 保留本地名单、上下文和强度检查的结果，不额外拒绝。 */
    ALLOW_WITH_LOCAL_CHECKS,
    /** 增加 {@link PasswordViolationCode#PWNED_CHECK_UNAVAILABLE} 违规项。 */
    REJECT
}
