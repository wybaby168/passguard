package dev.flyfish.passguard.crypto.key;

/** 支持安全轮换的可变密钥来源。 */
public interface MutableKeyProvider extends KeyProvider {
    /**
     * 保存密钥并将其设为 active。旧密钥仍保留用于解密。
     *
     * @param alias 逻辑别名
     * @param descriptor 新密钥
     */
    void putAndActivate(String alias, KeyDescriptor descriptor);

    /**
     * 将指定已有版本设为 active。
     *
     * @param alias 逻辑别名
     * @param keyId 已存在版本
     */
    void activate(String alias, String keyId);

    /**
     * 清除 active 状态以阻止新写入；历史密钥仍可用于解密。
     *
     * @param alias 逻辑别名
     */
    void deactivate(String alias);
}
