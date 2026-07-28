package io.github.wybaby168.passguard;

import java.util.Objects;

public record PasswordPolicyConfig(
        int minLengthSingleFactor,
        int minLengthWithMfa,
        int maxLength,
        int minimumStrengthScore,
        long rejectPwnedCountAtLeast,
        HibpFailureMode hibpFailureMode,
        boolean skipRemoteCheckWhenAlreadyRejected
) {
    public PasswordPolicyConfig {
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
        Objects.requireNonNull(hibpFailureMode, "hibpFailureMode");
    }

    public static PasswordPolicyConfig secureDefaults() {
        return new PasswordPolicyConfig(15, 8, 128, 3, 1,
                HibpFailureMode.ALLOW_WITH_LOCAL_CHECKS, true);
    }
}
