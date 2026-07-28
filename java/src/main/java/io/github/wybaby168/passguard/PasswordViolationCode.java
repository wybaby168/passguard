package io.github.wybaby168.passguard;

public enum PasswordViolationCode {
    EMPTY,
    TOO_SHORT,
    TOO_LONG,
    COMMON_PASSWORD,
    CONTEXT_PASSWORD,
    LOW_STRENGTH,
    PWNED_PASSWORD,
    PWNED_CHECK_UNAVAILABLE
}
