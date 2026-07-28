# Spring Boot 接入示例

```java
import io.github.wybaby168.passguard.PassGuard;

@Configuration
class PasswordSecurityConfiguration {
    @Bean
    PassGuard passGuard() {
        return PassGuard.builder()
            .contextWords("your-company", "your-product")
            .build();
    }
}
```

在领域服务而不是仅在 Controller/Bean Validation 中执行：

```java
@Service
class RegistrationService {
    private final PassGuard passGuard;
    private final PasswordHasher passwordHasher; // 你的 Argon2id 封装

    RegistrationService(PassGuard passGuard, PasswordHasher passwordHasher) {
        this.passGuard = passGuard;
        this.passwordHasher = passwordHasher;
    }

    public User register(RegisterCommand command) {
        PasswordAssessment assessment = passGuard.check(
            command.password(),
            false,
            new PasswordContext(
                command.username(), command.email(), command.displayName(),
                "your-product", List.of("your-company")
            )
        );
        if (!assessment.accepted()) {
            throw new PasswordPolicyException(assessment.violations());
        }
        String encoded = passwordHasher.argon2id(command.password());
        return saveUser(command, encoded);
    }
}
```

默认 HIBP 客户端使用同步 `HttpClient`。可放在 Java 21 虚拟线程或受控 I/O 线程池中，并配合 Resilience4j 等做缓存、超时、熔断和指标。指标只能记录状态与延迟，不能记录密码、完整哈希或响应内容。
