package dev.flyfish.passguard.crypto.key;

import dev.flyfish.passguard.crypto.CryptoException;

import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * 从环境变量加载密钥。
 *
 * <p>对于别名 {@code data} 和版本 {@code 2026_01}，读取
 * {@code PASSGUARD_KEY_DATA_ACTIVE=2026_01} 和
 * {@code PASSGUARD_KEY_DATA_2026_01=&lt;base64-32-bytes&gt;}。</p>
 */
public final class EnvironmentKeyProvider implements KeyProvider {
    private final Map<String, String> environment;
    private final String prefix;

    /** 使用 {@link System#getenv()} 和默认前缀 {@code PASSGUARD_KEY_}。 */
    public EnvironmentKeyProvider() {
        this(System.getenv(), "PASSGUARD_KEY_");
    }

    /** @param environment 环境变量快照；@param prefix 环境变量前缀 */
    public EnvironmentKeyProvider(Map<String, String> environment, String prefix) {
        this.environment = Objects.requireNonNull(environment, "environment");
        if (prefix == null || prefix.isEmpty()) {
            throw new IllegalArgumentException("prefix must not be empty");
        }
        this.prefix = prefix;
    }

    @Override
    public KeyDescriptor activeKey(String alias) {
        String normalized = variable(alias);
        String id = environment.get(prefix + normalized + "_ACTIVE");
        if (id == null || id.trim().isEmpty()) {
            throw new CryptoException("active environment key id is missing for alias " + alias);
        }
        return key(alias, id.trim());
    }

    @Override
    public KeyDescriptor key(String alias, String keyId) {
        String encoded = environment.get(prefix + variable(alias) + "_" + variable(keyId));
        if (encoded == null || encoded.trim().isEmpty()) {
            throw new CryptoException("environment key material is missing for alias " + alias);
        }
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(encoded.trim());
        } catch (IllegalArgumentException invalid) {
            throw new CryptoException("environment key is not valid Base64", invalid);
        }
        try {
            return new KeyDescriptor(keyId, new SecretKeySpec(bytes, "AES"));
        } finally {
            java.util.Arrays.fill(bytes, (byte) 0);
        }
    }

    private static String variable(String value) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{1,64}")) {
            throw new IllegalArgumentException("invalid key alias or id");
        }
        return value.replace('-', '_').toUpperCase(Locale.ROOT);
    }
}
