package io.github.wybaby168.passguard;

@FunctionalInterface
public interface PwnedPasswordChecker {
    PwnedCheckResult check(String password);
}
