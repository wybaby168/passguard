package io.github.wybaby168.passguard;

import java.util.Objects;

public record PasswordViolation(PasswordViolationCode code, String message) {
    public PasswordViolation {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(message, "message");
    }
}
