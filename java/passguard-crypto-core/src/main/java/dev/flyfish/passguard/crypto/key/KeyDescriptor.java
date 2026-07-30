package dev.flyfish.passguard.crypto.key;

import javax.crypto.SecretKey;
import java.util.Objects;

/**
 * 一个可用于加密或解密的带版本密钥。
 */
public final class KeyDescriptor {
    private final String id;
    private final SecretKey secretKey;

    /**
     * @param id 密钥版本标识，只允许字母、数字、下划线和短横线
     * @param secretKey 256 位 AES/HMAC 密钥
     */
    public KeyDescriptor(String id, SecretKey secretKey) {
        if (id == null || !id.matches("[A-Za-z0-9_-]{1,64}")) {
            throw new IllegalArgumentException("invalid key id");
        }
        this.id = id;
        this.secretKey = Objects.requireNonNull(secretKey, "secretKey");
        byte[] encoded = secretKey.getEncoded();
        try {
            if (encoded == null || encoded.length != 32) {
                throw new IllegalArgumentException("key must contain exactly 256 bits");
            }
        } finally {
            if (encoded != null) java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    /** @return 密钥版本标识 */
    public String id() { return id; }

    /**
     * 返回 JCE 密钥对象。调用方不得记录、序列化或长期缓存其编码。
     *
     * @return 密钥对象
     */
    public SecretKey secretKey() { return secretKey; }

    @Override
    public String toString() {
        return "KeyDescriptor[id=" + id + ", secretKey=<redacted>]";
    }
}
