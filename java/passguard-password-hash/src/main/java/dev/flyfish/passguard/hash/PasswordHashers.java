package dev.flyfish.passguard.hash;

/** 常用密码哈希策略的工厂入口。 */
public final class PasswordHashers {
    private PasswordHashers() {}

    /** @return 使用推荐参数的新 Argon2id 实例 */
    public static PasswordHasher argon2id() {
        return new Argon2idPasswordHasher();
    }

    /** @return 使用推荐参数的新 PBKDF2 实例 */
    public static PasswordHasher pbkdf2() {
        return new Pbkdf2PasswordHasher();
    }
}
