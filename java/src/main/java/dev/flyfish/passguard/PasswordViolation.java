package dev.flyfish.passguard;

import java.util.Objects;

/**
 * 单个密码策略违规项。
 */
public final class PasswordViolation {
    private final PasswordViolationCode code;
    private final String message;

    /**
     * 创建不可变违规项。
     *
     * @param code 稳定机器码
     * @param message 面向用户的通用提示
     */
    public PasswordViolation(PasswordViolationCode code, String message) {
        this.code = Objects.requireNonNull(code, "code");
        this.message = Objects.requireNonNull(message, "message");
    }

    /** @return 稳定违规码 */
    public PasswordViolationCode code() {
        return code;
    }

    /** @return 通用提示文案 */
    public String message() {
        return message;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof PasswordViolation)) return false;
        PasswordViolation that = (PasswordViolation) other;
        return code == that.code && message.equals(that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, message);
    }

    @Override
    public String toString() {
        return "PasswordViolation[code=" + code + ", message=" + message + "]";
    }
}
