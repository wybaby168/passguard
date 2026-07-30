package dev.flyfish.passguard.crypto;

import dev.flyfish.passguard.crypto.key.KeyProvider;

import java.util.Objects;

/**
 * 识别旧密钥密文并幂等地重加密到 active key。
 *
 * <p>服务不删除或停用历史密钥。调用方应在确认全部数据已迁移且备份可恢复后，
 * 再通过外部密钥系统执行生命周期策略。</p>
 */
public final class ReEncryptionService {
    private final CipherService cipherService;
    private final KeyProvider keyProvider;

    /**
     * @param cipherService 密文服务
     * @param keyProvider 用于识别 active key 的密钥来源
     */
    public ReEncryptionService(CipherService cipherService, KeyProvider keyProvider) {
        this.cipherService = Objects.requireNonNull(cipherService, "cipherService");
        this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider");
    }

    /**
     * @param ciphertext {@code PG1} 密文
     * @param keyAlias 逻辑密钥别名
     * @return 密文使用的 key id 与 active key 不同时为 {@code true}
     */
    public boolean needsReEncryption(String ciphertext, String keyAlias) {
        return !keyId(ciphertext).equals(keyProvider.activeKey(keyAlias).id());
    }

    /**
     * 先认证并解密，再按 active key 写回；已使用 active key 时原样返回。
     *
     * @param ciphertext 原密文
     * @param keyAlias 逻辑密钥别名
     * @param context AAD 字段上下文
     * @return 原密文或使用 active key 的新密文
     */
    public String reEncrypt(String ciphertext, String keyAlias, String context) {
        String plaintext = cipherService.decrypt(ciphertext, keyAlias, context);
        if (!needsReEncryption(ciphertext, keyAlias)) return ciphertext;
        return cipherService.encrypt(plaintext, keyAlias, context);
    }

    /**
     * 对一个调用方提供的分页批次执行幂等重加密。
     *
     * @param records 记录批次
     * @param accessor 密文字段读写策略
     * @param keyAlias 逻辑密钥别名
     * @param context AAD 字段上下文
     * @param dryRun 是否只统计
     * @param <T> 记录类型
     * @return 本批次统计
     */
    public <T> MigrationReport migrate(
            Iterable<T> records,
            CiphertextAccessor<T> accessor,
            String keyAlias,
            String context,
            boolean dryRun) {
        Objects.requireNonNull(records, "records");
        Objects.requireNonNull(accessor, "accessor");
        long examined = 0;
        long changed = 0;
        for (T record : records) {
            examined++;
            String ciphertext = accessor.read(record);
            if (ciphertext != null && needsReEncryption(ciphertext, keyAlias)) {
                changed++;
                if (!dryRun) {
                    accessor.write(record, reEncrypt(ciphertext, keyAlias, context));
                }
            }
        }
        return new MigrationReport(examined, changed, dryRun);
    }

    private static String keyId(String ciphertext) {
        if (ciphertext == null) throw new IllegalArgumentException("ciphertext must not be null");
        String[] parts = ciphertext.split("\\.", -1);
        if (parts.length != 4 || !"PG1".equals(parts[0])
                || !parts[1].matches("[A-Za-z0-9_-]{1,64}")) {
            throw new CryptoException("unsupported or malformed ciphertext");
        }
        return parts[1];
    }

    /** 提供记录中单个密文字段的读取和更新，不得记录字段值。 */
    public interface CiphertextAccessor<T> {
        /** @param record 记录；@return 可为 {@code null} 的密文 */
        String read(T record);

        /** @param record 记录；@param ciphertext 使用 active key 的新密文 */
        void write(T record, String ciphertext);
    }
}
