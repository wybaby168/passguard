package io.github.wybaby168.passguard;

@FunctionalInterface
public interface StrengthEstimator {
    /** Returns a zxcvbn-compatible score from 0 (weakest) to 4 (strongest). */
    int score(String password);
}
