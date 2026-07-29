package dev.flyfish.passguard;

import java.util.Collections;

/**
 * 使用固定演示值的独立启动示例，主要用于发行产物验证。
 *
 * <p>业务集成应使用 {@link PassGuard}，不应依赖本类。</p>
 */
public final class Example {
    private Example() {}

    /**
     * 运行固定的本地检查示例。
     *
     * @param args 未使用
     * @throws Exception 初始化或检查失败
     */
    public static void main(String[] args) throws Exception {
        PassGuard guard = PassGuard.builder()
                .contextWords("examplecorp", "example-product")
                .disablePwnedCheck()
                .build();

        // Never accept a real password from command-line arguments in production;
        // shell history and process listings can expose it. This is a fixed demo value.
        PasswordAssessment result = guard.check(
                "a-demo-password-that-must-be-replaced",
                false,
                new PasswordContext("demo-user", "demo@example.test", null,
                        "example-product", Collections.<String>emptyList())
        );
        System.out.println("accepted=" + result.accepted());
        System.out.println("violations=" + result.violations());
    }
}
