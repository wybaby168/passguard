package io.github.wybaby168.passguard;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record PasswordAssessment(
        boolean accepted,
        int codePointLength,
        Integer strengthScore,
        PwnedStatus pwnedStatus,
        Long pwnedCount,
        List<PasswordViolation> violations
) {
    public PasswordAssessment {
        Objects.requireNonNull(pwnedStatus, "pwnedStatus");
        Objects.requireNonNull(violations, "violations");
        violations = List.copyOf(violations);
    }

    public Optional<PasswordViolation> firstViolation() {
        return violations.stream().findFirst();
    }
}
