package io.github.wybaby168.passguard;

import java.util.Objects;

public final class PwnedCheckResult {
    private final PwnedStatus status;
    private final Long count;
    private final String reason;

    public PwnedCheckResult(PwnedStatus status, Long count, String reason) {
        this.status = Objects.requireNonNull(status, "status");
        if (status == PwnedStatus.SKIPPED) {
            throw new IllegalArgumentException("checker result cannot be SKIPPED");
        }
        if (status == PwnedStatus.PWNED && (count == null || count < 1)) {
            throw new IllegalArgumentException("pwned count must be positive");
        }
        if (status == PwnedStatus.CLEAR && (count == null || count != 0)) {
            throw new IllegalArgumentException("clear count must be zero");
        }
        this.count = count;
        this.reason = reason;
    }

    public PwnedStatus status() {
        return status;
    }

    public Long count() {
        return count;
    }

    public String reason() {
        return reason;
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

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof PwnedCheckResult)) return false;
        PwnedCheckResult that = (PwnedCheckResult) other;
        return status == that.status
                && Objects.equals(count, that.count)
                && Objects.equals(reason, that.reason);
    }

    @Override
    public int hashCode() {
        return Objects.hash(status, count, reason);
    }

    @Override
    public String toString() {
        return "PwnedCheckResult[status=" + status
                + ", count=" + count + ", reason=" + reason + "]";
    }
}
