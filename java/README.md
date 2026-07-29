# PassGuard Java

Java 8+ 的弱密码防御库，内置 125,691 条高频名单、nbvcxz 强度估算、上下文变体和 HIBP k-anonymity 查询。

- [完整 Java API 参考](API.md)
- [在线 Javadoc](https://javadoc.io/doc/dev.flyfish/passguard/latest/index.html)
- [Spring Boot 接入示例](SPRING_BOOT_EXAMPLE.md)

## 安装

```xml
<dependency>
  <groupId>dev.flyfish</groupId>
  <artifactId>passguard</artifactId>
  <version>1.0.3</version>
</dependency>
```

从 `1.0.2` 开始，主 JAR 以 Java 8 字节码（class major version 52）发布，并在真实 JDK 8 上完成编译、测试和独立启动验证；同一产物也持续在 Java 11、17、21 和 25 上测试。

## 最快接入

```java
import io.github.wybaby168.passguard.PassGuard;
import io.github.wybaby168.passguard.PasswordAssessment;
import io.github.wybaby168.passguard.PasswordContext;

import java.util.Collections;

PassGuard guard = PassGuard.builder()
    .contextWords("your-company", "your-product")
    .build();

PasswordAssessment result = guard.check(
    rawPassword,
    userHasMfa,
    new PasswordContext(
        username, email, displayName, "your-product",
        Collections.emptyList()
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

所有公开类、方法、默认值、参数约束、返回字段、枚举和失败语义见
[完整 Java API 参考](API.md)。Maven Central 同步发布 sources 和 Javadoc JAR。

## HIBP 与线程

默认客户端只发送 SHA-1 前 5 位，启用 `Add-Padding`，连接超时 3 秒、读取超时 5 秒。它使用 Java 8 自带的同步 `HttpURLConnection`；高并发服务应在受控 I/O 线程中调用，并按业务需要增加前缀缓存、熔断和指标。

默认 `ALLOW_WITH_LOCAL_CHECKS` 会在 HIBP 不可用时依靠本地规则继续；高保证业务可改为 `REJECT`。

## 构建

```bash
mvn clean test
mvn -Prelease clean verify
```

发布 profile 会生成 sources、Javadoc 和 GPG 签名，满足 Maven Central Portal 的发布要求。
