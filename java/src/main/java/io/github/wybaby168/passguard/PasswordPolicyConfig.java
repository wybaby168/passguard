package io.github.wybaby168.passguard;

import java.util.Objects;

public final class PasswordPolicyConfig {
    private final int minLengthSingleFactor;
    private final int minLengthWithMfa;
    private final int maxLength;
    private final int minimumStrengthScore;
    private final long rejectPwnedCountAtLeast;
    private final HibpFailureMode hibpFailureMode;
    private final boolean skipRemoteCheckWhenAlreadyRejected;

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

    public int minLengthSingleFactor() {
        return minLengthSingleFactor;
    }

    public int minLengthWithMfa() {
        return minLengthWithMfa;
    }

    public int maxLength() {
        return maxLength;
    }

    public int minimumStrengthScore() {
        return minimumStrengthScore;
    }

    public long rejectPwnedCountAtLeast() {
        return rejectPwnedCountAtLeast;
    }

    public HibpFailureMode hibpFailureMode() {
        return hibpFailureMode;
    }

    public boolean skipRemoteCheckWhenAlreadyRejected() {
        return skipRemoteCheckWhenAlreadyRejected;
    }

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
