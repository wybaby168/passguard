package dev.flyfish.passguard.crypto;

import dev.flyfish.passguard.crypto.key.KeyDescriptor;
import dev.flyfish.passguard.crypto.key.KeyProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;
import java.util.Arrays;

/**
 * 使用 HMAC-SHA256 生成精确匹配盲索引。
 */
public final class BlindIndexService {
    private final KeyProvider keyProvider;

    /** @param keyProvider 索引密钥来源 */
    public BlindIndexService(KeyProvider keyProvider) {
        this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider");
    }

    /**
     * @param plaintext 原始明文，不做 trim 或大小写折叠
     * @param keyAlias 与数据密钥分离的索引别名
     * @param context 稳定索引上下文
     * @return {@code BI1.keyId.digest} 格式索引
     */
    public String compute(String plaintext, String keyAlias, String context) {
        Objects.requireNonNull(plaintext, "plaintext");
        String alias = required(keyAlias, "keyAlias");
        String indexContext = required(context, "context");
        KeyDescriptor key = keyProvider.activeKey(alias);
        byte[] material = key.secretKey().getEncoded();
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(material, "HmacSHA256"));
            mac.update(("passguard:blind-index:v1:" + alias + ":" + indexContext + "\0")
                    .getBytes(StandardCharsets.UTF_8));
            byte[] digest = mac.doFinal(plaintextBytes);
            return "BI1." + key.id() + "."
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (GeneralSecurityException failure) {
            throw new CryptoException("blind index generation failed", failure);
        } finally {
            Arrays.fill(material, (byte) 0);
            Arrays.fill(plaintextBytes, (byte) 0);
        }
    }

    private static String required(String value, String name) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }
}
