package dev.flyfish.passguard.crypto;

/**
 * 带密钥版本与上下文认证的文本加解密服务。
 */
public interface CipherService {
    /**
     * @param plaintext 明文；不能为 {@code null}
     * @param keyAlias 密钥逻辑别名
     * @param context 稳定的使用场景或字段上下文
     * @return 带版本和 key id 的认证密文
     */
    String encrypt(String plaintext, String keyAlias, String context);

    /**
     * @param ciphertext {@code PG1} 格式密文
     * @param keyAlias 密钥逻辑别名
     * @param context 必须与加密时完全一致
     * @return 明文
     * @throws CryptoException 格式、密钥或认证校验失败
     */
    String decrypt(String ciphertext, String keyAlias, String context);
}
