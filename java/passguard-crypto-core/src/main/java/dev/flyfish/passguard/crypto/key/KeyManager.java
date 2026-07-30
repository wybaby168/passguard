package dev.flyfish.passguard.crypto.key;

import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * 生成和轮换 256 位对称密钥。
 */
public final class KeyManager {
    private final MutableKeyProvider provider;
    private final SecureRandom random;

    /** @param provider 可写密钥来源 */
    public KeyManager(MutableKeyProvider provider) {
        this(provider, new SecureRandom());
    }

    /** @param provider 可写密钥来源；@param random 密钥随机源 */
    public KeyManager(MutableKeyProvider provider, SecureRandom random) {
        this.provider = Objects.requireNonNull(provider, "provider");
        this.random = Objects.requireNonNull(random, "random");
    }

    /**
     * 生成新密钥并立即设为 active；旧版本仍可解密。
     *
     * @param alias 逻辑别名
     * @param keyId 新版本标识
     * @return 不泄露材料的描述对象
     */
    public KeyDescriptor generateAndActivate(String alias, String keyId) {
        byte[] material = new byte[32];
        random.nextBytes(material);
        try {
            KeyDescriptor descriptor =
                    new KeyDescriptor(keyId, new SecretKeySpec(material, "AES"));
            provider.putAndActivate(alias, descriptor);
            return descriptor;
        } finally {
            java.util.Arrays.fill(material, (byte) 0);
        }
    }

    /** @param alias 逻辑别名；@param keyId 已有版本 */
    public void activate(String alias, String keyId) {
        provider.activate(alias, keyId);
    }

    /**
     * 停止指定别名的新加密写入，保留全部历史版本用于解密。
     *
     * @param alias 逻辑别名
     */
    public void deactivate(String alias) {
        provider.deactivate(alias);
    }
}
