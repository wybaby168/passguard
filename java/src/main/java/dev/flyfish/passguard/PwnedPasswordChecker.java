package dev.flyfish.passguard;

/**
 * 可替换的泄露密码检查器。
 *
 * <p>实现可以连接 HIBP、企业内部代理、离线哈希库或缓存层，但不应把明文密码
 * 发送到未经审计的远程服务。</p>
 */
@FunctionalInterface
public interface PwnedPasswordChecker {
    /**
     * 检查密码是否出现在泄露数据中。
     *
     * @param password 已完成 NFC 规范化的密码
     * @return 检查结果；不能返回 {@link PwnedStatus#SKIPPED}
     */
    PwnedCheckResult check(String password);
}
