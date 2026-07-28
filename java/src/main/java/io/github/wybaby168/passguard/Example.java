package io.github.wybaby168.passguard;

import java.util.Collections;

public final class Example {
    private Example() {}

    public static void main(String[] args) throws Exception {
        PassGuard guard = PassGuard.builder()
                .contextWords("examplecorp", "example-product")
                .disablePwnedCheck()
                .build();

        // Never accept a real password from command-line arguments in production;
        // shell history and process listings can expose it. This is a fixed demo value.
        PasswordAssessment result = guard.check(
                "a-demo-password-that-must-be-replaced",
                false,
                new PasswordContext("demo-user", "demo@example.test", null,
                        "example-product", Collections.<String>emptyList())
        );
        System.out.println("accepted=" + result.accepted());
        System.out.println("violations=" + result.violations());
    }
}
