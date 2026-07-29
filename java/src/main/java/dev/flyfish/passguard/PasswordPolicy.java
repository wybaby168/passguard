package dev.flyfish.passguard;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * 底层密码策略编排器。通常应优先使用 {@link PassGuard}。
 */
public final class PasswordPolicy {
    private final PasswordPolicyConfig config;
    private final LocalBlocklist blocklist;
    private final ContextPasswordChecker contextChecker;
    private final StrengthEstimator strengthEstimator;
    private final PwnedPasswordChecker pwnedChecker;

    /**
     * 创建策略。
     *
     * @param config 策略配置
     * @param blocklist 本地名单
     * @param contextChecker 上下文检查器；{@code null} 表示空全局上下文
     * @param strengthEstimator 强度估算器；{@code null} 表示关闭
     * @param pwnedChecker 泄露密码检查器；{@code null} 表示关闭
     */
    public PasswordPolicy(
            PasswordPolicyConfig config,
            LocalBlocklist blocklist,
            ContextPasswordChecker contextChecker,
            StrengthEstimator strengthEstimator,
            PwnedPasswordChecker pwnedChecker
    ) {
        this.config = Objects.requireNonNull(config, "config");
        this.blocklist = Objects.requireNonNull(blocklist, "blocklist");
        this.contextChecker = contextChecker == null
                ? new ContextPasswordChecker(Collections.<String>emptyList())
                : contextChecker;
        this.strengthEstimator = strengthEstimator;
        this.pwnedChecker = pwnedChecker;
    }

    /**
     * 按长度、名单、上下文、强度和泄露状态依次评估密码。
     *
     * @param password 原始密码，不能为 {@code null}
     * @param mfaProtected 是否使用 MFA 场景最小长度
     * @param context 当前上下文；{@code null} 按空上下文处理
     * @return 不可变评估结果
     */
    public PasswordAssessment assess(String password, boolean mfaProtected, PasswordContext context) {
        Objects.requireNonNull(password, "password");
        String normalized = PasswordNormalizer.normalizePassword(password);
        int length = PasswordNormalizer.codePointLength(normalized);
        PasswordContext safeContext = context == null ? PasswordContext.empty() : context;
        List<PasswordViolation> violations = new ArrayList<>();

        if (length == 0) add(violations, PasswordViolationCode.EMPTY, "密码不能为空。");
        int minimum = mfaProtected ? config.minLengthWithMfa() : config.minLengthSingleFactor();
        if (length > 0 && length < minimum) {
            add(violations, PasswordViolationCode.TOO_SHORT, "密码长度不足，请使用更长且不易猜到的密码。");
        }
        if (length > config.maxLength()) {
            add(violations, PasswordViolationCode.TOO_LONG, "密码超过系统允许的最大长度。");
        }
        if (blocklist.contains(normalized)) {
            add(violations, PasswordViolationCode.COMMON_PASSWORD, "该密码过于常见，请更换。");
        }
        if (contextChecker.isBlocked(normalized, safeContext)) {
            add(violations, PasswordViolationCode.CONTEXT_PASSWORD,
                    "密码不能使用用户名、邮箱、产品名或企业名的常见变体。");
        }

        Integer strengthScore = null;
        if (strengthEstimator != null && length > 0) {
            strengthScore = strengthEstimator.score(normalized);
            if (strengthScore < config.minimumStrengthScore()) {
                add(violations, PasswordViolationCode.LOW_STRENGTH,
                        "该密码仍然容易被猜中，请增加长度并避免常见词、重复和序列。");
            }
        }

        PwnedStatus pwnedStatus = PwnedStatus.SKIPPED;
        Long pwnedCount = null;
        boolean callRemote = pwnedChecker != null
                && !(config.skipRemoteCheckWhenAlreadyRejected() && !violations.isEmpty());
        if (callRemote) {
            PwnedCheckResult result = pwnedChecker.check(normalized);
            pwnedStatus = result.status();
            pwnedCount = result.count();
            if (result.status() == PwnedStatus.PWNED
                    && result.count() != null
                    && result.count() >= config.rejectPwnedCountAtLeast()) {
                add(violations, PasswordViolationCode.PWNED_PASSWORD,
                        "该密码已出现在泄露数据中，请更换。");
            } else if (result.status() == PwnedStatus.UNAVAILABLE
                    && config.hibpFailureMode() == HibpFailureMode.REJECT) {
                add(violations, PasswordViolationCode.PWNED_CHECK_UNAVAILABLE,
                        "暂时无法完成泄露密码校验，请稍后重试。");
            }
        }

        return new PasswordAssessment(violations.isEmpty(), length, strengthScore,
                pwnedStatus, pwnedCount, violations);
    }

    private static void add(List<PasswordViolation> target, PasswordViolationCode code, String message) {
        boolean exists = target.stream().anyMatch(item -> item.code() == code);
        if (!exists) target.add(new PasswordViolation(code, message));
    }
}
