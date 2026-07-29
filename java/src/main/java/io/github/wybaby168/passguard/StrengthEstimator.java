package io.github.wybaby168.passguard;

/**
 * 可替换的密码强度估算器。
 */
@FunctionalInterface
public interface StrengthEstimator {
    /**
     * 返回 zxcvbn 兼容的 0（最弱）到 4（最强）分值。
     *
     * @param password 已完成 NFC 规范化的密码
     * @return 0 到 4 的强度分
     */
    int score(String password);
}
