package io.github.wybaby168.passguard;

/**
 * 泄露密码检查状态。
 */
public enum PwnedStatus {
    /** 已查询且未命中。 */
    CLEAR,
    /** 已查询且命中。 */
    PWNED,
    /** 检查器因网络、超时、HTTP 或解析问题不可用。 */
    UNAVAILABLE,
    /** 策略未配置检查器，或因已有本地违规而跳过远程检查。 */
    SKIPPED
}
