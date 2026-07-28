package io.github.wybaby168.passguard;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class PasswordPolicyTest {
    private static final StrengthEstimator STRONG = password -> 4;

    @Test
    void preservesSpacesAndNfc() {
        LocalBlocklist list = new LocalBlocklist(List.of(" password", "éxample"));
        assertTrue(list.contains(" password"));
        assertFalse(list.contains("password"));
        assertTrue(list.contains("éxample"));
    }

    @Test
    void rejectsCommonAndContextPasswords() {
        PasswordPolicy policy = new PasswordPolicy(
                PasswordPolicyConfig.secureDefaults(),
                new LocalBlocklist(List.of("correct horse battery staple")),
                new ContextPasswordChecker(List.of("flyfish")),
                STRONG,
                password -> PwnedCheckResult.clear()
        );
        PasswordAssessment common = policy.assess(
                "correct horse battery staple", false, PasswordContext.empty());
        assertTrue(common.violations().stream()
                .anyMatch(v -> v.code() == PasswordViolationCode.COMMON_PASSWORD));

        PasswordAssessment context = policy.assess(
                "flyfish@" + java.time.Year.now(java.time.ZoneOffset.UTC).getValue(), false, PasswordContext.empty());
        assertTrue(context.violations().stream()
                .anyMatch(v -> v.code() == PasswordViolationCode.CONTEXT_PASSWORD));
    }

    @Test
    void rejectsPwnedAfterLocalChecksPass() {
        PasswordPolicy policy = new PasswordPolicy(
                PasswordPolicyConfig.secureDefaults(),
                new LocalBlocklist(List.of()),
                new ContextPasswordChecker(List.of()),
                STRONG,
                password -> PwnedCheckResult.pwned(42)
        );
        PasswordAssessment result = policy.assess(
                "a genuinely long candidate 2026!", false, PasswordContext.empty());
        assertEquals(PwnedStatus.PWNED, result.pwnedStatus());
        assertEquals(42L, result.pwnedCount());
        assertTrue(result.violations().stream()
                .anyMatch(v -> v.code() == PasswordViolationCode.PWNED_PASSWORD));
    }

    @Test
    void createsPassGuardWithOneCallAndLoadsBundledBlocklist() {
        PassGuard guard = PassGuard.builder()
                .disableStrengthEstimator()
                .disablePwnedCheck()
                .contextWords("Flyfish")
                .build();

        PasswordAssessment common = guard.check("123456", true);
        assertFalse(common.accepted());
        assertEquals(PasswordViolationCode.TOO_SHORT,
                common.firstViolation().orElseThrow().code());
        assertTrue(common.violations().stream()
                .anyMatch(v -> v.code() == PasswordViolationCode.COMMON_PASSWORD));

        String contextual = "flyfish@" + java.time.Year.now(java.time.ZoneOffset.UTC).getValue();
        assertTrue(guard.check(contextual).violations().stream()
                .anyMatch(v -> v.code() == PasswordViolationCode.CONTEXT_PASSWORD));
    }

    @Test
    void appliesConfiguredHibpFailureMode() {
        PasswordPolicyConfig strict = new PasswordPolicyConfig(
                15, 8, 128, 3, 1, HibpFailureMode.REJECT, true);
        PassGuard guard = PassGuard.builder()
                .blocklist(new LocalBlocklist(List.of()))
                .strengthEstimator(STRONG)
                .pwnedChecker(password -> PwnedCheckResult.unavailable("test"))
                .config(strict)
                .build();

        PasswordAssessment result = guard.check("a genuinely long candidate 2026!");
        assertTrue(result.violations().stream()
                .anyMatch(v -> v.code() == PasswordViolationCode.PWNED_CHECK_UNAVAILABLE));
    }

    @Test
    void hibpClientUsesKAnonymityPrefixAndPadding() throws Exception {
        AtomicReference<String> requestedPath = new AtomicReference<>();
        AtomicReference<String> padding = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/range/", exchange -> {
            requestedPath.set(exchange.getRequestURI().getPath());
            padding.set(exchange.getRequestHeaders().getFirst("Add-Padding"));
            byte[] response = (
                    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n"
                    + "00000000000000000000000000000000000:0\n"
            ).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        try {
            URI endpoint = URI.create(
                    "http://127.0.0.1:" + server.getAddress().getPort() + "/range/");
            HibpPwnedPasswordClient client = new HibpPwnedPasswordClient(
                    HttpClient.newHttpClient(), endpoint, Duration.ofSeconds(2));
            PwnedCheckResult result = client.check("password");
            assertEquals(PwnedStatus.PWNED, result.status());
            assertEquals(42L, result.count());
            assertEquals("/range/5BAA6", requestedPath.get());
            assertEquals("true", padding.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void validatesResultAndPolicyInvariants() {
        assertThrows(IllegalArgumentException.class,
                () -> PwnedCheckResult.pwned(0));
        assertThrows(IllegalArgumentException.class,
                () -> new PwnedCheckResult(PwnedStatus.SKIPPED, null, null));
        assertThrows(IllegalArgumentException.class,
                () -> new PasswordPolicyConfig(
                        15, 8, 63, 3, 1,
                        HibpFailureMode.ALLOW_WITH_LOCAL_CHECKS, true));
        assertThrows(IllegalArgumentException.class,
                () -> new PasswordPolicyConfig(
                        15, 8, 128, 5, 1,
                        HibpFailureMode.ALLOW_WITH_LOCAL_CHECKS, true));
    }
}
