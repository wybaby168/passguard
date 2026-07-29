package dev.flyfish.passguard;

/**
 * 稳定的密码策略违规码。业务逻辑应判断枚举值，而不是解析提示文案。
 */
public enum PasswordViolationCode {
    /** 密码为空。 */
    EMPTY,
    /** 小于当前 MFA 场景的最小长度。 */
    TOO_SHORT,
    /** 超过允许的最大长度。 */
    TOO_LONG,
    /** 命中本地弱密码名单。 */
    COMMON_PASSWORD,
    /** 命中用户、产品或组织上下文的常见变体。 */
    CONTEXT_PASSWORD,
    /** 强度估算分低于阈值。 */
    LOW_STRENGTH,
    /** 泄露出现次数达到拒绝阈值。 */
    PWNED_PASSWORD,
    /** 泄露源不可用且策略要求拒绝。 */
    PWNED_CHECK_UNAVAILABLE
}
