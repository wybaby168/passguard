package dev.flyfish.passguard;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * PassGuard 的高级入口。实例是无状态的，可在整个应用中安全复用。
 */
public final class PassGuard {
    /** 内置后端弱密码名单的 classpath 资源路径。 */
    public static final String DEFAULT_BLOCKLIST_RESOURCE =
            "/weak-passwords/backend-blocklist.txt";

    private final PasswordPolicy policy;

    private PassGuard(PasswordPolicy policy) {
        this.policy = policy;
    }

    /**
     * 使用内置 125,691 条名单、nbvcxz 和 HIBP 创建完整防御实例。
     */
    public static PassGuard create() {
        return builder().build();
    }

    /**
     * 创建不访问外部网络的实例，适合离线任务或低延迟本地预检。
     */
    public static PassGuard localOnly() {
        return builder().disablePwnedCheck().build();
    }

    /** @return 新的高级配置构建器 */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * 使用单因素最小长度和空上下文检查密码。
     *
     * @param password 原始密码
     * @return 评估结果
     */
    public PasswordAssessment check(String password) {
        return check(password, false, PasswordContext.empty());
    }

    /**
     * 使用空上下文检查密码。
     *
     * @param password 原始密码
     * @param mfaProtected 是否使用 MFA 场景最小长度
     * @return 评估结果
     */
    public PasswordAssessment check(String password, boolean mfaProtected) {
        return check(password, mfaProtected, PasswordContext.empty());
    }

    /**
     * 使用完整用户与业务上下文检查密码。
     *
     * @param password 原始密码
     * @param mfaProtected 是否使用 MFA 场景最小长度
     * @param context 用户与业务上下文；可为 {@code null}
     * @return 评估结果
     */
    public PasswordAssessment check(
            String password,
            boolean mfaProtected,
            PasswordContext context
    ) {
        return policy.assess(password, mfaProtected, context);
    }

    /**
     * {@link PassGuard} 的可复用组件构建器。
     */
    public static final class Builder {
        private PasswordPolicyConfig config = PasswordPolicyConfig.secureDefaults();
        private LocalBlocklist blocklist;
        private final List<String> contextWords = new ArrayList<>();
        private StrengthEstimator strengthEstimator;
        private boolean defaultStrengthEstimator = true;
        private PwnedPasswordChecker pwnedChecker;
        private boolean defaultPwnedChecker = true;

        private Builder() {}

        /**
         * @param config 完整策略配置
         * @return 当前构建器
         */
        public Builder config(PasswordPolicyConfig config) {
            this.config = Objects.requireNonNull(config, "config");
            return this;
        }

        /**
         * @param blocklist 自定义本地名单
         * @return 当前构建器
         */
        public Builder blocklist(LocalBlocklist blocklist) {
            this.blocklist = Objects.requireNonNull(blocklist, "blocklist");
            return this;
        }

        /**
         * 累积产品名、企业名等全局上下文词。
         *
         * @param words 全局词
         * @return 当前构建器
         */
        public Builder contextWords(String... words) {
            Objects.requireNonNull(words, "words");
            return contextWords(Arrays.asList(words));
        }

        /**
         * 累积产品名、企业名等全局上下文词。
         *
         * @param words 全局词集合
         * @return 当前构建器
         */
        public Builder contextWords(Collection<String> words) {
            Objects.requireNonNull(words, "words");
            for (String word : words) {
                if (!ContextPasswordChecker.isBlank(word)) contextWords.add(word);
            }
            return this;
        }

        /**
         * @param estimator 自定义强度估算器
         * @return 当前构建器
         */
        public Builder strengthEstimator(StrengthEstimator estimator) {
            this.strengthEstimator = Objects.requireNonNull(estimator, "estimator");
            this.defaultStrengthEstimator = false;
            return this;
        }

        /**
         * 关闭强度估算。
         *
         * @return 当前构建器
         */
        public Builder disableStrengthEstimator() {
            this.strengthEstimator = null;
            this.defaultStrengthEstimator = false;
            return this;
        }

        /**
         * @param checker 自定义泄露密码检查器
         * @return 当前构建器
         */
        public Builder pwnedChecker(PwnedPasswordChecker checker) {
            this.pwnedChecker = Objects.requireNonNull(checker, "checker");
            this.defaultPwnedChecker = false;
            return this;
        }

        /**
         * 关闭远程泄露检查。
         *
         * @return 当前构建器
         */
        public Builder disablePwnedCheck() {
            this.pwnedChecker = null;
            this.defaultPwnedChecker = false;
            return this;
        }

        /**
         * 加载缺省组件并创建无状态实例。
         *
         * @return 可复用的 PassGuard
         * @throws IllegalStateException 内置名单加载失败
         */
        public PassGuard build() {
            LocalBlocklist effectiveBlocklist = blocklist == null
                    ? loadDefaultBlocklist()
                    : blocklist;
            StrengthEstimator effectiveStrengthEstimator = defaultStrengthEstimator
                    ? new NbvcxzStrengthEstimator()
                    : strengthEstimator;
            PwnedPasswordChecker effectivePwnedChecker = defaultPwnedChecker
                    ? new HibpPwnedPasswordClient()
                    : pwnedChecker;
            PasswordPolicy effectivePolicy = new PasswordPolicy(
                    config,
                    effectiveBlocklist,
                    new ContextPasswordChecker(contextWords),
                    effectiveStrengthEstimator,
                    effectivePwnedChecker
            );
            return new PassGuard(effectivePolicy);
        }

        private static LocalBlocklist loadDefaultBlocklist() {
            try {
                return LocalBlocklist.fromClasspath(DEFAULT_BLOCKLIST_RESOURCE);
            } catch (IOException exception) {
                throw new IllegalStateException(
                        "PassGuard 内置弱密码名单加载失败", exception);
            }
        }
    }
}
