package dev.flyfish.passguard.crypto;

/**
 * 加密、解密、密钥加载或密文验证失败。
 *
 * <p>异常消息永不包含密钥、明文或完整密文。</p>
 */
public class CryptoException extends RuntimeException {
    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
