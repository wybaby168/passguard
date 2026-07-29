package dev.flyfish.passguard;

import java.util.Objects;

/**
 * 泄露密码检查器返回的不可变结果。
 */
public final class PwnedCheckResult {
    private final PwnedStatus status;
    private final Long count;
    private final String reason;

    /**
     * 创建结果并验证状态、计数不变量。
     *
     * @param status {@code CLEAR}、{@code PWNED} 或 {@code UNAVAILABLE}
     * @param count CLEAR 时为 0，PWNED 时为正数，UNAVAILABLE 时可为 {@code null}
     * @param reason 不可用原因，可为 {@code null}
     * @throws IllegalArgumentException 状态与计数组合不合法
     */
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

    /** @return 检查状态 */
    public PwnedStatus status() {
        return status;
    }

    /** @return 泄露次数；不可用时通常为 {@code null} */
    public Long count() {
        return count;
    }

    /** @return 不可用原因；没有时为 {@code null} */
    public String reason() {
        return reason;
    }

    /** @return 未命中的结果，计数为 0 */
    public static PwnedCheckResult clear() {
        return new PwnedCheckResult(PwnedStatus.CLEAR, 0L, null);
    }

    /**
     * @param count 正的泄露次数
     * @return 命中结果
     */
    public static PwnedCheckResult pwned(long count) {
        return new PwnedCheckResult(PwnedStatus.PWNED, count, null);
    }

    /**
     * @param reason 不可用原因
     * @return 不可用结果
     */
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
