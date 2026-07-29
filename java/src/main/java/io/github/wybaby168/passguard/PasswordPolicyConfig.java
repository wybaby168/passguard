package io.github.wybaby168.passguard;

import java.util.Objects;

/**
 * 不可变密码策略配置。
 */
public final class PasswordPolicyConfig {
    private final int minLengthSingleFactor;
    private final int minLengthWithMfa;
    private final int maxLength;
    private final int minimumStrengthScore;
    private final long rejectPwnedCountAtLeast;
    private final HibpFailureMode hibpFailureMode;
    private final boolean skipRemoteCheckWhenAlreadyRejected;

    /**
     * 创建并验证配置。
     *
     * @param minLengthSingleFactor 单因素场景最小长度，至少为 1
     * @param minLengthWithMfa MFA 场景最小长度，至少为 1
     * @param maxLength 最大长度，至少为 64 且不小于两个最小长度
     * @param minimumStrengthScore 最小强度分，范围 0 到 4
     * @param rejectPwnedCountAtLeast 泄露拒绝阈值，至少为 1
     * @param hibpFailureMode 泄露源不可用时的处理方式
     * @param skipRemoteCheckWhenAlreadyRejected 本地已拒绝时是否跳过远程检查
     * @throws IllegalArgumentException 数值约束不满足
     */
    public PasswordPolicyConfig(
            int minLengthSingleFactor,
            int minLengthWithMfa,
            int maxLength,
            int minimumStrengthScore,
            long rejectPwnedCountAtLeast,
            HibpFailureMode hibpFailureMode,
            boolean skipRemoteCheckWhenAlreadyRejected
    ) {
        if (minLengthSingleFactor < 1 || minLengthWithMfa < 1) {
            throw new IllegalArgumentException("minimum lengths must be positive");
        }
        if (maxLength < 64) throw new IllegalArgumentException("maxLength must be at least 64");
        if (maxLength < Math.max(minLengthSingleFactor, minLengthWithMfa)) {
            throw new IllegalArgumentException("maxLength must not be smaller than a minimum length");
        }
        if (minimumStrengthScore < 0 || minimumStrengthScore > 4) {
            throw new IllegalArgumentException("minimumStrengthScore must be 0..4");
        }
        if (rejectPwnedCountAtLeast < 1) {
            throw new IllegalArgumentException("rejectPwnedCountAtLeast must be positive");
        }
        this.minLengthSingleFactor = minLengthSingleFactor;
        this.minLengthWithMfa = minLengthWithMfa;
        this.maxLength = maxLength;
        this.minimumStrengthScore = minimumStrengthScore;
        this.rejectPwnedCountAtLeast = rejectPwnedCountAtLeast;
        this.hibpFailureMode = Objects.requireNonNull(hibpFailureMode, "hibpFailureMode");
        this.skipRemoteCheckWhenAlreadyRejected = skipRemoteCheckWhenAlreadyRejected;
    }

    /** @return 单因素场景最小长度 */
    public int minLengthSingleFactor() {
        return minLengthSingleFactor;
    }

    /** @return MFA 场景最小长度 */
    public int minLengthWithMfa() {
        return minLengthWithMfa;
    }

    /** @return 最大允许长度 */
    public int maxLength() {
        return maxLength;
    }

    /** @return 最小强度分，范围 0 到 4 */
    public int minimumStrengthScore() {
        return minimumStrengthScore;
    }

    /** @return 泄露出现次数拒绝阈值 */
    public long rejectPwnedCountAtLeast() {
        return rejectPwnedCountAtLeast;
    }

    /** @return 泄露源不可用时的处理方式 */
    public HibpFailureMode hibpFailureMode() {
        return hibpFailureMode;
    }

    /** @return 本地已拒绝时是否跳过远程检查 */
    public boolean skipRemoteCheckWhenAlreadyRejected() {
        return skipRemoteCheckWhenAlreadyRejected;
    }

    /**
     * 返回推荐默认值：单因素 15、MFA 8、最大 128、强度 3、泄露阈值 1，
     * HIBP 不可用时依赖本地规则，并在本地已拒绝时跳过远程调用。
     *
     * @return 安全默认配置
     */
    public static PasswordPolicyConfig secureDefaults() {
        return new PasswordPolicyConfig(15, 8, 128, 3, 1,
                HibpFailureMode.ALLOW_WITH_LOCAL_CHECKS, true);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof PasswordPolicyConfig)) return false;
        PasswordPolicyConfig that = (PasswordPolicyConfig) other;
        return minLengthSingleFactor == that.minLengthSingleFactor
                && minLengthWithMfa == that.minLengthWithMfa
                && maxLength == that.maxLength
                && minimumStrengthScore == that.minimumStrengthScore
                && rejectPwnedCountAtLeast == that.rejectPwnedCountAtLeast
                && skipRemoteCheckWhenAlreadyRejected == that.skipRemoteCheckWhenAlreadyRejected
                && hibpFailureMode == that.hibpFailureMode;
    }

    @Override
    public int hashCode() {
        return Objects.hash(minLengthSingleFactor, minLengthWithMfa, maxLength,
                minimumStrengthScore, rejectPwnedCountAtLeast, hibpFailureMode,
                skipRemoteCheckWhenAlreadyRejected);
    }

    @Override
    public String toString() {
        return "PasswordPolicyConfig[minLengthSingleFactor=" + minLengthSingleFactor
                + ", minLengthWithMfa=" + minLengthWithMfa
                + ", maxLength=" + maxLength
                + ", minimumStrengthScore=" + minimumStrengthScore
                + ", rejectPwnedCountAtLeast=" + rejectPwnedCountAtLeast
                + ", hibpFailureMode=" + hibpFailureMode
                + ", skipRemoteCheckWhenAlreadyRejected="
                + skipRemoteCheckWhenAlreadyRejected + "]";
    }
}
