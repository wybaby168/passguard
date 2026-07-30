package dev.flyfish.passguard.crypto.key;

/**
 * 密钥来源策略接口。
 *
 * <p>实现必须线程安全。加密只使用 active key；解密按密文携带的 key id 查找历史密钥。</p>
 */
public interface KeyProvider {
    /** @param alias 逻辑别名；@return 当前写入密钥 */
    KeyDescriptor activeKey(String alias);

    /** @param alias 逻辑别名；@param keyId 历史版本；@return 对应解密密钥 */
    KeyDescriptor key(String alias, String keyId);
}
