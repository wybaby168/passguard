package io.github.wybaby168.passguard;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * 用户、服务与组织相关的密码上下文。
 *
 * <p>上下文只用于生成整串候选值，不会执行子串拒绝。</p>
 */
public final class PasswordContext {
    private final String username;
    private final String email;
    private final String displayName;
    private final String serviceName;
    private final List<String> organizationWords;

    /**
     * 创建不可变上下文。
     *
     * @param username 用户名，可为 {@code null}
     * @param email 邮箱，可为 {@code null}
     * @param displayName 显示名，可为 {@code null}
     * @param serviceName 服务或产品名，可为 {@code null}
     * @param organizationWords 组织相关词；{@code null} 按空列表处理
     */
    public PasswordContext(
            String username,
            String email,
            String displayName,
            String serviceName,
            List<String> organizationWords
    ) {
        this.username = username;
        this.email = email;
        this.displayName = displayName;
        this.serviceName = serviceName;
        if (organizationWords == null) {
            this.organizationWords = Collections.emptyList();
        } else {
            ArrayList<String> copy = new ArrayList<String>(organizationWords.size());
            for (String word : organizationWords) {
                copy.add(Objects.requireNonNull(
                        word, "organizationWords contains null"));
            }
            this.organizationWords = Collections.unmodifiableList(copy);
        }
    }

    /** @return 用户名，可为 {@code null} */
    public String username() {
        return username;
    }

    /** @return 邮箱，可为 {@code null} */
    public String email() {
        return email;
    }

    /** @return 显示名，可为 {@code null} */
    public String displayName() {
        return displayName;
    }

    /** @return 服务或产品名，可为 {@code null} */
    public String serviceName() {
        return serviceName;
    }

    /** @return 组织相关词的不可变副本 */
    public List<String> organizationWords() {
        return organizationWords;
    }

    /** @return 不含任何上下文值的实例 */
    public static PasswordContext empty() {
        return new PasswordContext(null, null, null, null,
                Collections.<String>emptyList());
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof PasswordContext)) return false;
        PasswordContext that = (PasswordContext) other;
        return Objects.equals(username, that.username)
                && Objects.equals(email, that.email)
                && Objects.equals(displayName, that.displayName)
                && Objects.equals(serviceName, that.serviceName)
                && organizationWords.equals(that.organizationWords);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, email, displayName, serviceName, organizationWords);
    }

    @Override
    public String toString() {
        return "PasswordContext[username=" + username
                + ", email=" + email
                + ", displayName=" + displayName
                + ", serviceName=" + serviceName
                + ", organizationWords=" + organizationWords + "]";
    }
}
