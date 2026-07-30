package dev.flyfish.passguard;

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

/**
 * HIBP Pwned Passwords range API 客户端。
 *
 * <p>客户端对 NFC 后密码计算 SHA-1，只发送前 5 个十六进制字符，并在本地
 * 比较返回后缀。SHA-1 仅用于 HIBP 索引兼容，不能用于密码存储。</p>
 *
 * <p>该 Java 8 实现使用同步 {@link HttpURLConnection}。</p>
 */
public final class HibpPwnedPasswordClient implements PwnedPasswordChecker {
    private static final URI DEFAULT_ENDPOINT = URI.create("https://api.pwnedpasswords.com/range/");
    private static final char[] UPPER_HEX = "0123456789ABCDEF".toCharArray();

    private final URI endpoint;
    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;

    /**
     * 使用官方端点、3 秒连接超时和 5 秒读取超时。
     */
    public HibpPwnedPasswordClient() {
        this(DEFAULT_ENDPOINT, Duration.ofSeconds(3), Duration.ofSeconds(5));
    }

    /**
     * 为连接和读取使用相同超时。
     *
     * @param endpoint range API 基础地址
     * @param timeout 正的连接与读取超时
     */
    public HibpPwnedPasswordClient(URI endpoint, Duration timeout) {
        this(endpoint, timeout, timeout);
    }

    /**
     * 使用自定义端点及独立超时。
     *
     * @param endpoint range API 基础地址
     * @param connectTimeout 正的连接超时
     * @param readTimeout 正的读取超时
     */
    public HibpPwnedPasswordClient(
            URI endpoint,
            Duration connectTimeout,
            Duration readTimeout
    ) {
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint");
        this.connectTimeoutMillis = timeoutMillis(connectTimeout, "connectTimeout");
        this.readTimeoutMillis = timeoutMillis(readTimeout, "readTimeout");
    }

    /**
     * 查询泄露状态。网络、非 200 HTTP 和解析异常会转换为
     * {@link PwnedStatus#UNAVAILABLE}。
     *
     * @param password 待检查密码
     * @return clear、pwned 或 unavailable 结果
     */
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
            connection.setRequestProperty("User-Agent", "passguard-java/2.1.0");

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
