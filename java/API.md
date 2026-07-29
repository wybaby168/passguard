# PassGuard Java API 参考

适用于 `dev.flyfish:passguard:2.0.0`，运行环境为 Java 8 及以上版本。

- [返回项目主页](../README.md)
- [Java 快速接入](README.md)
- [Spring Boot 示例](SPRING_BOOT_EXAMPLE.md)
- [在线 Javadoc](https://javadoc.io/doc/dev.flyfish/passguard/latest/index.html)

## 如何选择 API

| 需求 | 推荐入口 | 是否访问网络 |
|---|---|---:|
| 使用全部默认防御能力 | `PassGuard.create()` | 是 |
| 离线校验或低延迟预检 | `PassGuard.localOnly()` | 否 |
| 修改阈值、企业词或替换组件 | `PassGuard.builder()` | 可选 |
| 直接组合底层组件 | `PasswordPolicy` | 可选 |
| 仅管理自定义弱密码名单 | `LocalBlocklist` | 否 |
| 仅调用 HIBP k-anonymity | `HibpPwnedPasswordClient` | 是 |

通常应从 `PassGuard` 开始。只有需要替换名单、强度算法、远程泄露源或编排顺序时，才直接使用底层类型。

## 安装与导入

```xml
<dependency>
  <groupId>dev.flyfish</groupId>
  <artifactId>passguard</artifactId>
  <version>2.0.0</version>
</dependency>
```

```java
import dev.flyfish.passguard.PassGuard;
import dev.flyfish.passguard.PasswordAssessment;
import dev.flyfish.passguard.PasswordContext;
```

公共 Java 包名为 `dev.flyfish.passguard`。

从 `1.x` 升级到 `2.0.0` 时，将 import 前缀由
`io.github.wybaby168.passguard` 替换为 `dev.flyfish.passguard`。
Maven 坐标和公开类型名称不变。

## `PassGuard`

高级入口，封装本地名单、上下文检查、强度估算和泄露密码检查。实例无状态，可作为应用级单例复用。

### 工厂方法

| 方法 | 行为 |
|---|---|
| `PassGuard.create()` | 内置 125,691 条名单 + nbvcxz + HIBP |
| `PassGuard.localOnly()` | 内置名单 + nbvcxz，不访问 HIBP |
| `PassGuard.builder()` | 按需替换或关闭组件 |

内置名单资源路径由 `PassGuard.DEFAULT_BLOCKLIST_RESOURCE` 提供。

### `check` 重载

```java
PasswordAssessment check(String password)
PasswordAssessment check(String password, boolean mfaProtected)
PasswordAssessment check(
    String password,
    boolean mfaProtected,
    PasswordContext context
)
```

- `password`：原始密码；不能为 `null`。实现会执行 NFC 规范化，但不会 `trim()`、转小写或删除空白。
- `mfaProtected`：`true` 时使用 MFA 场景最小长度，默认配置为 8；否则使用单因素最小长度 15。
- `context`：用户和业务上下文；传 `null` 等同于 `PasswordContext.empty()`。
- 返回值：不可变的 `PasswordAssessment`。

推荐在注册、修改密码和重置密码的服务端事务中调用：

```java
PasswordAssessment result = guard.check(password, hasMfa, context);
if (!result.accepted()) {
    PasswordViolation first = result.firstViolation().get();
    throw new IllegalArgumentException(first.message());
}
```

不要记录 `password`。如果上下文包含用户名或邮箱，也不要直接记录完整 `PasswordContext`。

## `PassGuard.Builder`

```java
PassGuard guard = PassGuard.builder()
    .config(PasswordPolicyConfig.secureDefaults())
    .contextWords("example-company", "example-product")
    .build();
```

| 方法 | 说明 |
|---|---|
| `config(PasswordPolicyConfig)` | 替换全部策略配置 |
| `blocklist(LocalBlocklist)` | 替换默认本地名单 |
| `contextWords(String...)` | 添加所有用户共享的产品名、企业名等上下文词 |
| `contextWords(Collection<String>)` | 集合形式添加全局上下文词 |
| `strengthEstimator(StrengthEstimator)` | 替换 nbvcxz 强度估算器 |
| `disableStrengthEstimator()` | 关闭强度估算；`strengthScore()` 返回 `null` |
| `pwnedChecker(PwnedPasswordChecker)` | 替换默认 HIBP 客户端 |
| `disablePwnedCheck()` | 关闭远程泄露检查 |
| `build()` | 构造可复用实例 |

重复调用 `contextWords` 会累积有效词条。空值参数会抛出 `NullPointerException`；空白上下文词会被忽略。

## `PasswordPolicyConfig`

不可变策略配置。

```java
PasswordPolicyConfig config = new PasswordPolicyConfig(
    15,  // minLengthSingleFactor
    8,   // minLengthWithMfa
    128, // maxLength
    3,   // minimumStrengthScore
    1,   // rejectPwnedCountAtLeast
    HibpFailureMode.ALLOW_WITH_LOCAL_CHECKS,
    true // skipRemoteCheckWhenAlreadyRejected
);
```

| 访问器 | 默认值 | 约束与含义 |
|---|---:|---|
| `minLengthSingleFactor()` | 15 | 至少为 1 |
| `minLengthWithMfa()` | 8 | 至少为 1 |
| `maxLength()` | 128 | 至少为 64，且不能小于两个最小长度 |
| `minimumStrengthScore()` | 3 | 0–4；仅在启用强度估算时生效 |
| `rejectPwnedCountAtLeast()` | 1 | 至少为 1 |
| `hibpFailureMode()` | `ALLOW_WITH_LOCAL_CHECKS` | HIBP 不可用时继续或拒绝 |
| `skipRemoteCheckWhenAlreadyRejected()` | `true` | 本地已拒绝时跳过远程请求 |

`PasswordPolicyConfig.secureDefaults()` 返回上表配置。构造参数不合法时抛出 `IllegalArgumentException`。

## `PasswordContext`

用于阻止与当前用户、服务或组织高度相关的密码。

```java
PasswordContext context = new PasswordContext(
    username,
    email,
    displayName,
    "example-product",
    Collections.singletonList("example-company")
);
```

| 访问器 | 内容 |
|---|---|
| `username()` | 用户名，可为 `null` |
| `email()` | 邮箱；会提取本地部分作为候选词 |
| `displayName()` | 显示名 |
| `serviceName()` | 服务或产品名 |
| `organizationWords()` | 组织相关词的不可变副本 |
| `PasswordContext.empty()` | 无上下文的共享语义值 |

构造器接受 `organizationWords == null`，按空列表处理；列表内不能包含 `null`。

上下文匹配会使用 NFKC 和不区分大小写的比较键，生成常见数字、符号和相邻年份变体，最终只做整串匹配，不做子串拒绝。

## `PasswordAssessment`

一次完整判定的不可变结果。

| 访问器 | 类型 | 说明 |
|---|---|---|
| `accepted()` | `boolean` | 没有任何违规项时为 `true` |
| `codePointLength()` | `int` | NFC 后的 Unicode 码点数，不是 UTF-16 长度 |
| `strengthScore()` | `Integer` | 0–4；未启用或空密码时为 `null` |
| `pwnedStatus()` | `PwnedStatus` | 泄露检查状态 |
| `pwnedCount()` | `Long` | HIBP 出现次数；未查询或不可用时通常为 `null` |
| `violations()` | `List<PasswordViolation>` | 不可变违规列表 |
| `firstViolation()` | `Optional<PasswordViolation>` | 第一项违规；通过时为空 |

公共构造器主要用于适配器、序列化和测试。正常业务代码应使用 `PassGuard.check()` 或 `PasswordPolicy.assess()` 获取结果。

## 违规项

### `PasswordViolation`

不可变值对象：

- `code()`：稳定机器码，适合业务分支、指标和国际化映射。
- `message()`：面向用户的通用中文提示。

不要依赖 `message()` 做程序判断；应使用 `code()`。

### `PasswordViolationCode`

| 枚举值 | 触发条件 |
|---|---|
| `EMPTY` | 密码为空 |
| `TOO_SHORT` | 小于当前 MFA 场景的最小长度 |
| `TOO_LONG` | 超过最大长度 |
| `COMMON_PASSWORD` | 命中本地弱密码名单 |
| `CONTEXT_PASSWORD` | 命中用户、产品或企业上下文变体 |
| `LOW_STRENGTH` | 强度分低于阈值 |
| `PWNED_PASSWORD` | 泄露次数达到拒绝阈值 |
| `PWNED_CHECK_UNAVAILABLE` | HIBP 不可用且策略为拒绝 |

## `PwnedStatus`

| 枚举值 | 含义 |
|---|---|
| `CLEAR` | 已查询且未命中 |
| `PWNED` | 已查询且命中 |
| `UNAVAILABLE` | 超时、网络、HTTP 或解析失败 |
| `SKIPPED` | 未配置检查器，或本地已拒绝后跳过 |

## 本地名单 API

### `LocalBlocklist`

```java
LocalBlocklist list = new LocalBlocklist(entries);
LocalBlocklist classpathList = LocalBlocklist.fromClasspath("/passwords.txt");
LocalBlocklist fileList = LocalBlocklist.fromPath(path);
LocalBlocklist streamList = LocalBlocklist.fromInputStream(input);
```

| 方法 | 说明 |
|---|---|
| `contains(String)` | NFC 后整串查询 |
| `size()` | 去重后的词条数 |
| `fromClasspath(String)` | UTF-8 classpath 资源；找不到时抛出 `IOException` |
| `fromPath(Path)` | UTF-8 文件 |
| `fromInputStream(InputStream)` | 读取 UTF-8 流并关闭该流 |

每行是一条完整密码。读取时只去掉行终止符，不会去掉密码两端空格。空行和空字符串词条被忽略。

## 上下文检查 API

### `ContextPasswordChecker`

```java
ContextPasswordChecker checker =
    new ContextPasswordChecker(Arrays.asList("example-company"));

boolean blocked = checker.isBlocked(password, context);
```

- 构造器会预计算全局词变体，实例可复用。
- `isBlocked` 接受 `null` 上下文。
- 长度小于 3 的上下文 token 不参与候选生成。
- 只做整串匹配。

## 强度估算 API

### `StrengthEstimator`

函数式扩展接口：

```java
@FunctionalInterface
public interface StrengthEstimator {
    int score(String password);
}
```

返回值应使用 zxcvbn 兼容的 0–4 分值。自定义实现应无状态或线程安全，因为 `PassGuard` 通常作为单例复用。

### `NbvcxzStrengthEstimator`

| 构造器 | 说明 |
|---|---|
| `new NbvcxzStrengthEstimator()` | 使用默认 `Nbvcxz` |
| `new NbvcxzStrengthEstimator(Nbvcxz)` | 注入已配置的 nbvcxz 实例 |

`score(String)` 返回 `Nbvcxz#getBasicScore()`。

## 泄露密码 API

### `PwnedPasswordChecker`

函数式扩展接口：

```java
@FunctionalInterface
public interface PwnedPasswordChecker {
    PwnedCheckResult check(String password);
}
```

自定义实现可以接入内部离线哈希库、缓存代理或其他经授权的泄露源。不要发送明文密码到远端服务。

### `PwnedCheckResult`

| 工厂方法 | 结果 |
|---|---|
| `clear()` | `CLEAR`，计数为 0 |
| `pwned(long count)` | `PWNED`，计数必须大于 0 |
| `unavailable(String reason)` | `UNAVAILABLE`，计数为 `null` |

访问器为 `status()`、`count()` 和 `reason()`。检查器结果不能使用 `SKIPPED`；该状态由策略层产生。

公共构造器会验证状态与计数不变量，不合法时抛出 `IllegalArgumentException`。

### `HibpPwnedPasswordClient`

```java
new HibpPwnedPasswordClient()
new HibpPwnedPasswordClient(endpoint, timeout)
new HibpPwnedPasswordClient(endpoint, connectTimeout, readTimeout)
```

默认设置：

- 端点：`https://api.pwnedpasswords.com/range/`
- 连接超时：3 秒
- 读取超时：5 秒
- `Add-Padding: true`
- 不自动跟随重定向，不使用 HTTP 缓存

`check(String)` 会对 NFC 后的密码计算 SHA-1，仅发送前 5 个十六进制字符，并在本地比较后缀。SHA-1 仅用于 HIBP 索引兼容，不能用于密码存储。

客户端把网络、非 200 HTTP 和解析异常转换为 `PwnedCheckResult.unavailable(...)`，而不是向业务层抛出。超时必须为正数；亚毫秒正数按 1 ms 处理，超大值会限制为 `Integer.MAX_VALUE` ms。

Java 8 实现基于同步 `HttpURLConnection`。高并发服务应在受控 I/O 线程中调用，并按需要在 `PwnedPasswordChecker` 外层增加缓存、熔断和指标。

## 直接使用 `PasswordPolicy`

只有需要完全控制组件组合时才使用：

```java
PasswordPolicy policy = new PasswordPolicy(
    config,
    blocklist,
    contextChecker,
    strengthEstimator, // 可为 null
    pwnedChecker       // 可为 null
);

PasswordAssessment result =
    policy.assess(password, mfaProtected, context);
```

构造参数 `config` 和 `blocklist` 不能为空；`contextChecker == null` 时使用空全局上下文；强度估算器或泄露检查器为 `null` 表示关闭对应能力。

## 失败、并发与日志

- `PassGuard`、配置和结果对象均可安全复用或跨线程读取。
- 自定义 `StrengthEstimator`、`PwnedPasswordChecker` 的并发安全由实现者负责。
- 本地规则是同步 CPU/内存操作；默认 HIBP 客户端是同步网络 I/O。
- 不要记录密码、完整 SHA-1、HIBP 响应体或含个人信息的上下文对象。
- 可安全记录违规 `code`、HIBP 状态、耗时和匿名化计数。

## `Example`

`dev.flyfish.passguard.Example` 是固定演示值的独立启动示例，用于发行验证；业务集成不应依赖该类。
