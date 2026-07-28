package io.github.wybaby168.passguard;

import java.util.Objects;

public final class PasswordViolation {
    private final PasswordViolationCode code;
    private final String message;

    public PasswordViolation(PasswordViolationCode code, String message) {
        this.code = Objects.requireNonNull(code, "code");
        this.message = Objects.requireNonNull(message, "message");
    }

    public PasswordViolationCode code() {
        return code;
    }

    public String message() {
        return message;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof PasswordViolation)) return false;
        PasswordViolation that = (PasswordViolation) other;
        return code == that.code && message.equals(that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, message);
    }

    @Override
    public String toString() {
        return "PasswordViolation[code=" + code + ", message=" + message + "]";
    }
}
