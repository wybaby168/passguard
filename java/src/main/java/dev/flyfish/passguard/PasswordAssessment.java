package dev.flyfish.passguard;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * 一次完整密码判定的不可变结果。
 */
public final class PasswordAssessment {
    private final boolean accepted;
    private final int codePointLength;
    private final Integer strengthScore;
    private final PwnedStatus pwnedStatus;
    private final Long pwnedCount;
    private final List<PasswordViolation> violations;

    /**
     * 创建结果值。正常业务代码应从 {@link PassGuard#check(String)} 或
     * {@link PasswordPolicy#assess(String, boolean, PasswordContext)} 获取实例。
     *
     * @param accepted 是否通过全部已启用规则
     * @param codePointLength NFC 后的 Unicode 码点数
     * @param strengthScore 0 到 4 的强度分；未估算时为 {@code null}
     * @param pwnedStatus 泄露检查状态
     * @param pwnedCount 泄露出现次数；未查或不可用时可为 {@code null}
     * @param violations 违规项；构造器会创建不可变副本
     */
    public PasswordAssessment(
            boolean accepted,
            int codePointLength,
            Integer strengthScore,
            PwnedStatus pwnedStatus,
            Long pwnedCount,
            List<PasswordViolation> violations
    ) {
        this.accepted = accepted;
        this.codePointLength = codePointLength;
        this.strengthScore = strengthScore;
        this.pwnedStatus = Objects.requireNonNull(pwnedStatus, "pwnedStatus");
        Objects.requireNonNull(violations, "violations");
        this.pwnedCount = pwnedCount;
        ArrayList<PasswordViolation> copy =
                new ArrayList<PasswordViolation>(violations.size());
        for (PasswordViolation violation : violations) {
            copy.add(Objects.requireNonNull(
                    violation, "violations contains null"));
        }
        this.violations = Collections.unmodifiableList(copy);
    }

    /** @return 没有违规项时为 {@code true} */
    public boolean accepted() {
        return accepted;
    }

    /** @return NFC 后的 Unicode 码点数 */
    public int codePointLength() {
        return codePointLength;
    }

    /** @return 0 到 4 的强度分；未估算时为 {@code null} */
    public Integer strengthScore() {
        return strengthScore;
    }

    /** @return 泄露检查状态 */
    public PwnedStatus pwnedStatus() {
        return pwnedStatus;
    }

    /** @return 泄露出现次数；未查或不可用时可为 {@code null} */
    public Long pwnedCount() {
        return pwnedCount;
    }

    /** @return 不可变违规列表 */
    public List<PasswordViolation> violations() {
        return violations;
    }

    /** @return 第一项违规；通过时为空 */
    public Optional<PasswordViolation> firstViolation() {
        return violations.isEmpty()
                ? Optional.<PasswordViolation>empty()
                : Optional.of(violations.get(0));
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof PasswordAssessment)) return false;
        PasswordAssessment that = (PasswordAssessment) other;
        return accepted == that.accepted
                && codePointLength == that.codePointLength
                && Objects.equals(strengthScore, that.strengthScore)
                && pwnedStatus == that.pwnedStatus
                && Objects.equals(pwnedCount, that.pwnedCount)
                && violations.equals(that.violations);
    }

    @Override
    public int hashCode() {
        return Objects.hash(accepted, codePointLength, strengthScore,
                pwnedStatus, pwnedCount, violations);
    }

    @Override
    public String toString() {
        return "PasswordAssessment[accepted=" + accepted
                + ", codePointLength=" + codePointLength
                + ", strengthScore=" + strengthScore
                + ", pwnedStatus=" + pwnedStatus
                + ", pwnedCount=" + pwnedCount
                + ", violations=" + violations + "]";
    }
}
