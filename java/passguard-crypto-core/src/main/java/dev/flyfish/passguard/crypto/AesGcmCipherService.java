package dev.flyfish.passguard.crypto;

import dev.flyfish.passguard.crypto.key.KeyDescriptor;
import dev.flyfish.passguard.crypto.key.KeyProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.Arrays;

/**
 * AES-256-GCM 密文实现。
 *
 * <p>每次加密使用新的 96 位 nonce；上下文写入 AAD，密文不能被复制到其他字段使用。</p>
 */
public final class AesGcmCipherService implements CipherService {
    /** 密文版本前缀。 */
    public static final String PREFIX = "PG1.";
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private final KeyProvider keyProvider;
    private final SecureRandom random;

    /** @param keyProvider 密钥来源 */
    public AesGcmCipherService(KeyProvider keyProvider) {
        this(keyProvider, new SecureRandom());
    }

    /** @param keyProvider 密钥来源；@param random nonce 随机源 */
    public AesGcmCipherService(KeyProvider keyProvider, SecureRandom random) {
        this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider");
        this.random = Objects.requireNonNull(random, "random");
    }

    @Override
    public String encrypt(String plaintext, String keyAlias, String context) {
        Objects.requireNonNull(plaintext, "plaintext");
        String alias = required(keyAlias, "keyAlias");
        String aadContext = required(context, "context");
        KeyDescriptor key = keyProvider.activeKey(alias);
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key.secretKey(),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(alias, aadContext));
            byte[] ciphertext = cipher.doFinal(plaintextBytes);
            return PREFIX + key.id() + "." + encode(nonce) + "." + encode(ciphertext);
        } catch (GeneralSecurityException failure) {
            throw new CryptoException("AES-GCM encryption failed", failure);
        } finally {
            Arrays.fill(plaintextBytes, (byte) 0);
        }
    }

    @Override
    public String decrypt(String ciphertext, String keyAlias, String context) {
        Objects.requireNonNull(ciphertext, "ciphertext");
        String alias = required(keyAlias, "keyAlias");
        String aadContext = required(context, "context");
        String[] parts = ciphertext.split("\\.", -1);
        if (parts.length != 4 || !"PG1".equals(parts[0])
                || !parts[1].matches("[A-Za-z0-9_-]{1,64}")) {
            throw new CryptoException("unsupported or malformed ciphertext");
        }
        byte[] nonce;
        byte[] encrypted;
        try {
            nonce = decode(parts[2]);
            encrypted = decode(parts[3]);
        } catch (IllegalArgumentException invalid) {
            throw new CryptoException("malformed ciphertext encoding", invalid);
        }
        if (nonce.length != NONCE_LENGTH || encrypted.length < 16) {
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(encrypted, (byte) 0);
            throw new CryptoException("malformed ciphertext length");
        }
        KeyDescriptor key = keyProvider.key(alias, parts[1]);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key.secretKey(),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(alias, aadContext));
            byte[] plaintext = cipher.doFinal(encrypted);
            try {
                return new String(plaintext, StandardCharsets.UTF_8);
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        } catch (GeneralSecurityException failure) {
            throw new CryptoException("ciphertext authentication failed", failure);
        } finally {
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(encrypted, (byte) 0);
        }
    }

    private static byte[] aad(String alias, String context) {
        return ("passguard:v1:" + alias + ":" + context).getBytes(StandardCharsets.UTF_8);
    }

    private static String encode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] decode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    private static String required(String value, String name) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }
}
