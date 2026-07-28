package io.github.wybaby168.passguard;

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

    public static Builder builder() {
        return new Builder();
    }

    public PasswordAssessment check(String password) {
        return check(password, false, PasswordContext.empty());
    }

    public PasswordAssessment check(String password, boolean mfaProtected) {
        return check(password, mfaProtected, PasswordContext.empty());
    }

    public PasswordAssessment check(
            String password,
            boolean mfaProtected,
            PasswordContext context
    ) {
        return policy.assess(password, mfaProtected, context);
    }

    public static final class Builder {
        private PasswordPolicyConfig config = PasswordPolicyConfig.secureDefaults();
        private LocalBlocklist blocklist;
        private final List<String> contextWords = new ArrayList<>();
        private StrengthEstimator strengthEstimator;
        private boolean defaultStrengthEstimator = true;
        private PwnedPasswordChecker pwnedChecker;
        private boolean defaultPwnedChecker = true;

        private Builder() {}

        public Builder config(PasswordPolicyConfig config) {
            this.config = Objects.requireNonNull(config, "config");
            return this;
        }

        public Builder blocklist(LocalBlocklist blocklist) {
            this.blocklist = Objects.requireNonNull(blocklist, "blocklist");
            return this;
        }

        public Builder contextWords(String... words) {
            Objects.requireNonNull(words, "words");
            return contextWords(Arrays.asList(words));
        }

        public Builder contextWords(Collection<String> words) {
            Objects.requireNonNull(words, "words");
            for (String word : words) {
                if (!ContextPasswordChecker.isBlank(word)) contextWords.add(word);
            }
            return this;
        }

        public Builder strengthEstimator(StrengthEstimator estimator) {
            this.strengthEstimator = Objects.requireNonNull(estimator, "estimator");
            this.defaultStrengthEstimator = false;
            return this;
        }

        public Builder disableStrengthEstimator() {
            this.strengthEstimator = null;
            this.defaultStrengthEstimator = false;
            return this;
        }

        public Builder pwnedChecker(PwnedPasswordChecker checker) {
            this.pwnedChecker = Objects.requireNonNull(checker, "checker");
            this.defaultPwnedChecker = false;
            return this;
        }

        public Builder disablePwnedCheck() {
            this.pwnedChecker = null;
            this.defaultPwnedChecker = false;
            return this;
        }

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
