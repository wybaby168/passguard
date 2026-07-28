package io.github.wybaby168.passguard;

import java.util.Objects;

public record PwnedCheckResult(PwnedStatus status, Long count, String reason) {
    public PwnedCheckResult {
        Objects.requireNonNull(status, "status");
        if (status == PwnedStatus.SKIPPED) {
            throw new IllegalArgumentException("checker result cannot be SKIPPED");
        }
        if (status == PwnedStatus.PWNED && (count == null || count < 1)) {
            throw new IllegalArgumentException("pwned count must be positive");
        }
        if (status == PwnedStatus.CLEAR && (count == null || count != 0)) {
            throw new IllegalArgumentException("clear count must be zero");
        }
    }

    public static PwnedCheckResult clear() {
        return new PwnedCheckResult(PwnedStatus.CLEAR, 0L, null);
    }

    public static PwnedCheckResult pwned(long count) {
        return new PwnedCheckResult(PwnedStatus.PWNED, count, null);
    }

    public static PwnedCheckResult unavailable(String reason) {
        return new PwnedCheckResult(PwnedStatus.UNAVAILABLE, null, reason);
    }
}
