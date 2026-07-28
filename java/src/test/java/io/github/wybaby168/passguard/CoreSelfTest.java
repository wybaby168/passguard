package io.github.wybaby168.passguard;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Year;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collections;

public final class CoreSelfTest {
    private static final int EXPECTED_BACKEND_ENTRIES = 125_691;

    public static void main(String[] args) throws Exception {
        Path fullListPath = args.length > 0
                ? Paths.get(args[0])
                : Paths.get("src/main/resources/weak-passwords/backend-blocklist.txt");
        LocalBlocklist fullList = LocalBlocklist.fromPath(fullListPath);
        check(fullList.size() == EXPECTED_BACKEND_ENTRIES,
                "unexpected backend blocklist size: " + fullList.size());
        check(fullList.contains("123456"), "full backend blocklist did not contain known common password");
        expectIllegalArgument(() -> new PasswordPolicyConfig(
                15, 8, 63, 3, 1, HibpFailureMode.ALLOW_WITH_LOCAL_CHECKS, true));

        LocalBlocklist list = new LocalBlocklist(
                Arrays.asList(" password", "éxample", "123456"));
        check(list.contains(" password"), "leading space must be preserved");
        check(!list.contains("password"), "passwords must not be trimmed");
        check(list.contains("éxample"), "NFC exact match failed");

        PasswordPolicy commonPolicy = new PasswordPolicy(
                PasswordPolicyConfig.secureDefaults(), list,
                new ContextPasswordChecker(
                        Collections.singletonList("flyfish")),
                password -> 4,
                password -> PwnedCheckResult.clear());
        PasswordAssessment common = commonPolicy.assess("123456", true, PasswordContext.empty());
        check(common.violations().stream().anyMatch(v -> v.code() == PasswordViolationCode.COMMON_PASSWORD),
                "common password was not rejected");

        PasswordAssessment context = commonPolicy.assess(
                "flyfish@" + Year.now(ZoneOffset.UTC).getValue(), false, PasswordContext.empty());
        check(context.violations().stream().anyMatch(v -> v.code() == PasswordViolationCode.CONTEXT_PASSWORD),
                "context password was not rejected");

        PasswordPolicy pwnedPolicy = new PasswordPolicy(
                PasswordPolicyConfig.secureDefaults(),
                new LocalBlocklist(Collections.<String>emptyList()),
                new ContextPasswordChecker(Collections.<String>emptyList()),
                password -> 4,
                password -> PwnedCheckResult.pwned(99));
        PasswordAssessment pwned = pwnedPolicy.assess(
                "a genuinely long candidate 2026!", false, PasswordContext.empty());
        check(pwned.pwnedStatus() == PwnedStatus.PWNED, "pwned status mismatch");
        check(!pwned.accepted(), "pwned password was accepted");
        System.out.println("CoreSelfTest: PASS (backend entries=" + fullList.size() + ")");
    }

    private static void expectIllegalArgument(Runnable action) {
        try {
            action.run();
            throw new AssertionError("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
