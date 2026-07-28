# PassGuard Java

Java 17+ 的弱密码防御库，内置 125,691 条高频名单、nbvcxz 强度估算、上下文变体和 HIBP k-anonymity 查询。

## 安装

```xml
<dependency>
  <groupId>io.github.wybaby168</groupId>
  <artifactId>passguard</artifactId>
  <version>1.0.0</version>
</dependency>
```

## 最快接入

```java
import io.github.wybaby168.passguard.PassGuard;
import io.github.wybaby168.passguard.PasswordAssessment;
import io.github.wybaby168.passguard.PasswordContext;

PassGuard guard = PassGuard.builder()
    .contextWords("your-company", "your-product")
    .build();

PasswordAssessment result = guard.check(
    rawPassword,
    userHasMfa,
    new PasswordContext(
        username, email, displayName, "your-product", java.util.List.of()
    )
);

if (!result.accepted()) {
    throw new PasswordRejectedException(result.violations());
}
```

也可以直接使用：

```java
PassGuard complete = PassGuard.create();    // 本地名单 + nbvcxz + HIBP
PassGuard local = PassGuard.localOnly();    // 无网络
```

实例无状态且可复用。Spring Boot 中应注册为单例 Bean，不要在每次请求时重新解析名单。

## 自定义

```java
PassGuard guard = PassGuard.builder()
    .config(new PasswordPolicyConfig(
        15, 8, 256, 3, 1,
        HibpFailureMode.REJECT, true
    ))
    .contextWords("your-company", "your-product")
    .pwnedChecker(customChecker)
    .build();
```

底层的 `PasswordPolicy`、`LocalBlocklist`、`ContextPasswordChecker`、`StrengthEstimator` 和 `PwnedPasswordChecker` 都是公开 API，可替换名单、缓存或远程客户端。

## HIBP 与线程

默认客户端只发送 SHA-1 前 5 位，启用 `Add-Padding`，连接超时 3 秒、请求超时 5 秒。它使用同步 Java `HttpClient`；高并发服务应在受控 I/O 线程或虚拟线程中调用，并按业务需要增加前缀缓存、熔断和指标。

默认 `ALLOW_WITH_LOCAL_CHECKS` 会在 HIBP 不可用时依靠本地规则继续；高保证业务可改为 `REJECT`。

## 构建

```bash
mvn clean test
mvn -Prelease clean verify
```

发布 profile 会生成 sources、Javadoc 和 GPG 签名，满足 Maven Central Portal 的发布要求。
