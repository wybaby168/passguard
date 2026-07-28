package io.github.wybaby168.passguard;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Objects;

public final class HibpPwnedPasswordClient implements PwnedPasswordChecker {
    private static final URI DEFAULT_ENDPOINT = URI.create("https://api.pwnedpasswords.com/range/");

    private final HttpClient client;
    private final URI endpoint;
    private final Duration timeout;

    public HibpPwnedPasswordClient() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build(),
                DEFAULT_ENDPOINT, Duration.ofSeconds(5));
    }

    public HibpPwnedPasswordClient(HttpClient client, URI endpoint, Duration timeout) {
        this.client = Objects.requireNonNull(client, "client");
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
    }

    @Override
    public PwnedCheckResult check(String password) {
        try {
            String digest = sha1UpperHex(PasswordNormalizer.normalizePassword(password));
            String prefix = digest.substring(0, 5);
            String suffix = digest.substring(5);
            HttpRequest request = HttpRequest.newBuilder(endpoint.resolve(prefix))
                    .timeout(timeout)
                    .header("Accept", "text/plain")
                    .header("Add-Padding", "true")
                    .header("User-Agent", "passguard-java/1.0.1")
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                return PwnedCheckResult.unavailable("HTTP " + response.statusCode());
            }

            for (String line : response.body().split("\\R")) {
                int colon = line.indexOf(':');
                if (colon < 1) continue;
                if (line.substring(0, colon).equalsIgnoreCase(suffix)) {
                    long count = Long.parseLong(line.substring(colon + 1).trim());
                    if (count > 0) return PwnedCheckResult.pwned(count);
                }
            }
            return PwnedCheckResult.clear();
        } catch (IOException exception) {
            return PwnedCheckResult.unavailable(exception.getClass().getSimpleName());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return PwnedCheckResult.unavailable("interrupted");
        } catch (RuntimeException exception) {
            return PwnedCheckResult.unavailable(exception.getClass().getSimpleName());
        }
    }

    private static String sha1UpperHex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            // SHA-1 is required only because HIBP indexes this corpus by SHA-1.
            // Never use this method for password storage.
            return HexFormat.of().withUpperCase().formatHex(
                    digest.digest(value.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-1 is unavailable", impossible);
        }
    }
}
