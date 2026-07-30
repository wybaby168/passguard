package dev.flyfish.passguard.crypto;

/** 数据库读取到非 PassGuard 密文时的处理策略。 */
public enum ReadPolicy {
    /** 立即失败，防止把意外明文当作已受保护数据。 */
    STRICT,
    /** 迁移窗口内保留旧明文；所有后续写入仍会加密。 */
    MIGRATION
}
