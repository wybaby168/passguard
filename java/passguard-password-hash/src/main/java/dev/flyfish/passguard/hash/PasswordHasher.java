package dev.flyfish.passguard.hash;

/**
 * 登录密码的单向哈希策略。
 *
 * <p>实现必须自动生成独立盐值并使用恒定时间比较。该接口不适用于需要恢复明文的业务秘密。</p>
 */
public interface PasswordHasher {
    /**
     * @param password 待哈希密码；调用方仍负责清空原数组
     * @return 包含算法、参数和盐值的自描述哈希
     */
    String hash(char[] password);

    /**
     * @param password 待验证密码
     * @param encodedHash 已存储的自描述哈希
     * @return 匹配时为 {@code true}；格式无效时为 {@code false}
     */
    boolean verify(char[] password, String encodedHash);

    /**
     * @param encodedHash 已存储哈希
     * @return 算法或参数不符合当前策略时为 {@code true}
     */
    boolean needsRehash(String encodedHash);
}
