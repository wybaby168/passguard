package io.github.wybaby168.passguard;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTimeout;

class PerformanceTest {
    @Test
    void performsFiftyThousandLocalAssessmentsWithinBudget() {
        PassGuard guard = PassGuard.builder()
                .blocklist(new LocalBlocklist(List.of("123456", "password")))
                .contextWords("PassGuard", "Example Corp")
                .strengthEstimator(password -> 4)
                .disablePwnedCheck()
                .build();

        assertTimeout(Duration.ofSeconds(5), () -> {
            for (int index = 0; index < 50_000; index++) {
                guard.check("a genuinely long candidate " + index + "!");
            }
        });
    }
}
