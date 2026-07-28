package io.github.wybaby168.passguard;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public final class PasswordAssessment {
    private final boolean accepted;
    private final int codePointLength;
    private final Integer strengthScore;
    private final PwnedStatus pwnedStatus;
    private final Long pwnedCount;
    private final List<PasswordViolation> violations;

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

    public boolean accepted() {
        return accepted;
    }

    public int codePointLength() {
        return codePointLength;
    }

    public Integer strengthScore() {
        return strengthScore;
    }

    public PwnedStatus pwnedStatus() {
        return pwnedStatus;
    }

    public Long pwnedCount() {
        return pwnedCount;
    }

    public List<PasswordViolation> violations() {
        return violations;
    }

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
