package io.github.wybaby168.passguard;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Objects;

public final class HibpPwnedPasswordClient implements PwnedPasswordChecker {
    private static final URI DEFAULT_ENDPOINT = URI.create("https://api.pwnedpasswords.com/range/");
    private static final char[] UPPER_HEX = "0123456789ABCDEF".toCharArray();

    private final URI endpoint;
    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;

    public HibpPwnedPasswordClient() {
        this(DEFAULT_ENDPOINT, Duration.ofSeconds(3), Duration.ofSeconds(5));
    }

    public HibpPwnedPasswordClient(URI endpoint, Duration timeout) {
        this(endpoint, timeout, timeout);
    }

    public HibpPwnedPasswordClient(
            URI endpoint,
            Duration connectTimeout,
            Duration readTimeout
    ) {
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint");
        this.connectTimeoutMillis = timeoutMillis(connectTimeout, "connectTimeout");
        this.readTimeoutMillis = timeoutMillis(readTimeout, "readTimeout");
    }

    @Override
    public PwnedCheckResult check(String password) {
        HttpURLConnection connection = null;
        try {
            String digest = sha1UpperHex(PasswordNormalizer.normalizePassword(password));
            String prefix = digest.substring(0, 5);
            String suffix = digest.substring(5);
            connection = (HttpURLConnection) endpoint.resolve(prefix)
                    .toURL().openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(connectTimeoutMillis);
            connection.setReadTimeout(readTimeoutMillis);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestProperty("Accept", "text/plain");
            connection.setRequestProperty("Add-Padding", "true");
            connection.setRequestProperty("User-Agent", "passguard-java/1.0.2");

            int statusCode = connection.getResponseCode();
            if (statusCode != HttpURLConnection.HTTP_OK) {
                return PwnedCheckResult.unavailable("HTTP " + statusCode);
            }

            try (InputStream input = connection.getInputStream();
                 BufferedReader reader = new BufferedReader(
                         new InputStreamReader(input, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    int colon = line.indexOf(':');
                    if (colon < 1) continue;
                    if (line.substring(0, colon).equalsIgnoreCase(suffix)) {
                        long count = Long.parseLong(
                                line.substring(colon + 1).trim());
                        if (count > 0) return PwnedCheckResult.pwned(count);
                    }
                }
            }
            return PwnedCheckResult.clear();
        } catch (IOException exception) {
            return PwnedCheckResult.unavailable(exception.getClass().getSimpleName());
        } catch (RuntimeException exception) {
            return PwnedCheckResult.unavailable(exception.getClass().getSimpleName());
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private static String sha1UpperHex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            // SHA-1 is required only because HIBP indexes this corpus by SHA-1.
            // Never use this method for password storage.
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            char[] encoded = new char[bytes.length * 2];
            for (int index = 0; index < bytes.length; index++) {
                int current = bytes[index] & 0xff;
                encoded[index * 2] = UPPER_HEX[current >>> 4];
                encoded[index * 2 + 1] = UPPER_HEX[current & 0x0f];
            }
            return new String(encoded);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-1 is unavailable", impossible);
        }
    }

    private static int timeoutMillis(Duration timeout, String name) {
        Objects.requireNonNull(timeout, name);
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        long millis;
        try {
            millis = timeout.toMillis();
        } catch (ArithmeticException overflow) {
            return Integer.MAX_VALUE;
        }
        if (millis < 1) return 1;
        return millis > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) millis;
    }
}
