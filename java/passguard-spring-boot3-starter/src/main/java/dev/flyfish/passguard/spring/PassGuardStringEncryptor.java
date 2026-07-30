package dev.flyfish.passguard.spring;

import dev.flyfish.passguard.crypto.CipherService;
import org.jasypt.encryption.StringEncryptor;

import java.util.Objects;

/** 把 jasypt-spring-boot PropertySource 解密连接到 PassGuard 密文协议。 */
public final class PassGuardStringEncryptor implements StringEncryptor {
    private static final String CONTEXT = "spring-config";
    private final CipherService cipherService;
    private final String keyAlias;

    public PassGuardStringEncryptor(CipherService cipherService, String keyAlias) {
        this.cipherService = Objects.requireNonNull(cipherService, "cipherService");
        if (keyAlias == null || keyAlias.isBlank()) {
            throw new IllegalArgumentException("keyAlias must not be blank");
        }
        this.keyAlias = keyAlias.trim();
    }

    @Override
    public String encrypt(String message) {
        return cipherService.encrypt(message, keyAlias, CONTEXT);
    }

    @Override
    public String decrypt(String encryptedMessage) {
        return cipherService.decrypt(encryptedMessage, keyAlias, CONTEXT);
    }
}
