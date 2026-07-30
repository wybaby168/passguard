# PassGuard Java API 参考

适用于 PassGuard `2.1.0`。核心、生成、哈希、加密、MyBatis、JPA 2.2 与
Boot 2 模块支持 Java 8；Jakarta、Hibernate 6 与 Boot 3 模块使用 Java 17。

- [返回项目主页](../README.md)
- [Java 快速接入](README.md)
- [Spring Boot 示例](SPRING_BOOT_EXAMPLE.md)
- [在线 Javadoc](https://javadoc.io/doc/dev.flyfish/passguard/latest/index.html)

## 模块选择

| artifactId | 公开入口 | 说明 |
|---|---|---|
| `passguard` | `PassGuard` | 原有弱密码策略，API 向后兼容 |
| `passguard-generator` | `SecurePasswordGenerator` | 安全密码生成 |
| `passguard-password-hash` | `PasswordHasher`、`PasswordHashers` | Argon2id/PBKDF2 |
| `passguard-crypto-core` | `CipherService`、`KeyProvider`、`@Encrypted` | 加密与密钥核心 |
| `passguard-crypto-jackson` | `PassGuardJacksonModule` | 响应字段排除 |
| `passguard-crypto-mybatis` | `PassGuardMyBatisPlugin` | MyBatis 透明适配 |
| `passguard-crypto-jpa-javax` | `PassGuardHibernate5Integrator` | Hibernate 5 事件系统 |
| `passguard-crypto-jpa-jakarta` | `PassGuardHibernate6Integrator` | Hibernate 6 事件系统 |
| `passguard-crypto-r2dbc-boot2/3` | `PassGuardR2dbcCallbacks` | R2DBC 回调 |
| `passguard-spring-boot2/3-starter` | `PassGuardCryptoProperties` | Jasypt 与自动装配 |

自动配置类 `PassGuardCryptoAutoConfiguration`、`PassGuardJacksonAutoConfiguration`、
`PassGuardMyBatisAutoConfiguration`、`PassGuardHibernate5Configuration`、
`PassGuardHibernate6AutoConfiguration`、`PassGuardR2dbcConfiguration` 和
`PassGuardR2dbcAutoConfiguration` 通常不需要直接调用。所有模块都可由
`passguard-bom` 管理版本。

## 密码生成 API

### `SecurePasswordGenerator`

| 入口 | 行为 |
|---|---|
| `new SecurePasswordGenerator()` | 使用新的 `SecureRandom` |
| `new SecurePasswordGenerator(SecureRandom)` | 注入调用方统一管理的密码学安全随机源 |
| `generate()` | 使用长度 20、每类至少 1 个字符的默认配置 |
| `generate(PasswordGenerationOptions)` | 使用自定义不可变配置 |

`PasswordGenerationOptions.secureDefaults()` 返回默认值，`builder()` 返回
`PasswordGenerationOptions.Builder`。Builder 提供：

- `length`、`minimumLowercase`、`minimumUppercase`、`minimumDigits`、
  `minimumSymbols`；
- `lowercaseAlphabet`、`uppercaseAlphabet`、`digitAlphabet`、`symbolAlphabet`；
- `excludeAmbiguous` 和最终的 `build`。

对应只读访问器为 `length()`、`minimumLowercase()`、`minimumUppercase()`、
`minimumDigits()`、`minimumSymbols()`、`lowercaseAlphabet()`、
`uppercaseAlphabet()`、`digitAlphabet()`、`symbolAlphabet()` 和
`excludeAmbiguous()`。默认字符表常量为 `DEFAULT_LOWERCASE`、
`DEFAULT_UPPERCASE`、`DEFAULT_DIGITS`、`DEFAULT_SYMBOLS`。

```java
import dev.flyfish.passguard.generator.PasswordGenerationOptions;
import dev.flyfish.passguard.generator.SecurePasswordGenerator;

PasswordGenerationOptions options = PasswordGenerationOptions.builder()
    .length(24)
    .minimumSymbols(2)
    .excludeAmbiguous(true)
    .build();

String password = new SecurePasswordGenerator().generate(options);
```

生成器使用 Fisher-Yates 洗牌和无偏 `nextInt(bound)`。长度小于 4、负数最小值、
总最小数量超过长度或过滤后字符表为空时抛出 `IllegalArgumentException`。

## 登录密码哈希 API

### `PasswordHasher`

```java
interface PasswordHasher {
    String hash(char[] password);
    boolean verify(char[] password, String encodedHash);
    boolean needsRehash(String encodedHash);
}
```

- `Argon2idPasswordHasher` 默认参数：
  `DEFAULT_MEMORY_KIB=19456`、`DEFAULT_ITERATIONS=2`、
  `DEFAULT_PARALLELISM=1`，输出标准 PHC 字符串。
- `Pbkdf2PasswordHasher` 默认 `DEFAULT_ITERATIONS=600000`，
  使用 PBKDF2-HMAC-SHA256 和 256 位输出。
- `PasswordHashers.argon2id()`、`PasswordHashers.pbkdf2()` 是推荐工厂。

自定义构造器接受安全参数和 `SecureRandom`。`verify` 对无效格式返回 `false`；
`needsRehash` 对无效格式或旧参数返回 `true`。调用方必须在使用后清空原始
`char[]`。快速 SHA-256、SHA-1、MD5 不属于此 API。

## 加密与密钥 API

### `CipherService` 与 `AesGcmCipherService`

```java
import dev.flyfish.passguard.crypto.AesGcmCipherService;
import dev.flyfish.passguard.crypto.CipherService;
import dev.flyfish.passguard.crypto.key.EnvironmentKeyProvider;

CipherService cipher = new AesGcmCipherService(new EnvironmentKeyProvider());
String encrypted = cipher.encrypt(plaintext, "data", "credential.password");
String decrypted = cipher.decrypt(encrypted, "data", "credential.password");
```

密文格式为 `PG1.keyId.nonce.ciphertextAndTag`。每次加密使用新的 96 位 nonce、
128 位认证标签和 `passguard:v1:<alias>:<context>` AAD。格式错误、未知 key id、错误
上下文或篡改会抛出 `CryptoException`，不会返回原值。
`AesGcmCipherService.PREFIX` 是公开的 `PG1.` 检测常量。

### 密钥接口

| 类型 | API |
|---|---|
| `KeyProvider` | `activeKey(alias)`、`key(alias, keyId)` |
| `MutableKeyProvider` | `putAndActivate`、`activate`、`deactivate` |
| `KeyDescriptor` | `id()`、`secretKey()`；`toString()` 永远脱敏 |
| `KeyManager` | `generateAndActivate`、`activate`、`deactivate` |
| `EnvironmentKeyProvider` | 默认读取 `PASSGUARD_KEY_*` |
| `KeyStoreKeyProvider` | PKCS12/JCEKS 的 `alias.keyId` 条目 |
| `CompositeKeyProvider` | 依次查询多个 Provider |
| `InMemoryKeyProvider` | 测试、CLI 或外部 KMS 适配缓存 |

`KeyDescriptor` 只接受 256 位材料和安全 key id。`deactivate(alias)` 只停止该
别名的新加密，不删除历史材料，已有密文仍可解密。`KeyManager` 不提供无保护删除。

### 盲索引与迁移

`BlindIndexService.compute(plaintext, keyAlias, context)` 返回
`BI1.keyId.digest`。它只做大小写敏感的原文等值匹配，不 trim、不规范化、不支持
LIKE、范围或排序。

`SecretMigrationService<T>` 使用 `Detector<T>` 与 `Writer<T>` 编排迁移，
`migrate(records, dryRun)` 返回 `MigrationReport`；报告访问器为 `examined()`、
`changed()`、`dryRun()`。默认 `ReadPolicy.STRICT` 拒绝旧明文；
`ReadPolicy.MIGRATION` 仅用于有时间边界的迁移窗口。

`ReEncryptionService` 用于密钥轮换：

| API | 行为 |
|---|---|
| `needsReEncryption(ciphertext, keyAlias)` | 判断密文是否仍使用非 active key |
| `reEncrypt(ciphertext, keyAlias, context)` | 先认证解密，再按 active key 重加密；已最新时返回原字符串 |
| `migrate(records, CiphertextAccessor, keyAlias, context, dryRun)` | 对调用方提供的分页批次执行幂等迁移 |

`ReEncryptionService.CiphertextAccessor<T>` 只定义 `read` 和 `write`，让应用自行控制
事务、分页和持久化。轮换服务不会停用或删除旧密钥。

`AnnotatedFieldProcessor` 是适配器共用底层，公开 `supports`、
`encryptForWrite`、`restoreAfterWrite`、`decryptAfterRead`、
`encryptStateForWrite`、`encryptedState`、`decryptStateAfterRead` 和
`prepareForWrite`。`prepareForWrite` 返回 `PreparedWrite`，应在
try-with-resources 中使用；其 `close` 会精确恢复原明文和调用方原有盲索引值，
重复关闭无副作用，`toString()` 永不包含字段值。普通业务代码通常无需直接使用。

## 注解与数据库适配

```java
import dev.flyfish.passguard.crypto.annotation.BlindIndex;
import dev.flyfish.passguard.crypto.annotation.Encrypted;

class Credential {
    @Encrypted(keyAlias = "data", context = "credential.password")
    private String password;

    @BlindIndex(
        source = "password",
        keyAlias = "index",
        context = "credential.password_index"
    )
    private String passwordIndex;
}
```

- `@Encrypted.keyAlias()` 为空时使用 Starter 的默认别名；
  `context()` 为空时由实体类和属性名推导。
- `@BlindIndex.source()` 指定当前对象中的明文字段；`keyAlias()` 默认 `index`。
- 两个注解只支持 `String` 字段，不匹配的类型在元数据初始化时失败。
- `PassGuardMyBatisPlugin` 实现 `intercept`、`plugin`、`setProperties`；
  Spring Boot 自动配置会创建插件。
- `PassGuardHibernate5Integrator` / `PassGuardHibernate6Integrator` 注册
  `onPreLoad`、`onPreInsert`、`onPreUpdate` 事件处理，只转换 Hibernate JDBC
  state，不污染实体或脏检查快照。`integrate`/`disintegrate` 由 Hibernate 调用。
- `PassGuardR2dbcCallbacks` 的 `onBeforeSave` 转换 `OutboundRow`，
  `onAfterConvert` 解密实体。
- `PassGuardJacksonModule.setupModule` 注册
  `EncryptedAnnotationIntrospector.findPropertyAccess`，使属性 write-only。

## Spring Boot / Jasypt API

`PassGuardCryptoProperties` 对应 `passguard.crypto`：

| 配置 | 默认值 | 说明 |
|---|---|---|
| `enabled` | `true` | 是否启用自动配置 |
| `default-key-alias` | `data` | 数据库字段默认别名 |
| `config-key-alias` | `config` | `ENC(...)` 配置别名 |
| `read-policy` | `STRICT` | 旧明文读取策略 |
| `provider` | `ENVIRONMENT` | `ENVIRONMENT` 或 `KEYSTORE` |
| `environment-prefix` | `PASSGUARD_KEY_` | 环境变量前缀 |
| `key-store.location` | 无 | PKCS12/JCEKS 路径 |
| `key-store.type` | `PKCS12` | KeyStore 类型 |
| `key-store.password-environment` | `PASSGUARD_KEYSTORE_PASSWORD` | 密码环境变量名 |
| `key-store.password-system-property` | 无 | 可选的 KeyStore 密码 JVM 系统属性名 |
| `key-store.active-ids` | `{}` | 别名到 active id 的映射 |

对应访问器为 `getDefaultKeyAlias`/`setDefaultKeyAlias`、
`getConfigKeyAlias`/`setConfigKeyAlias`、`getReadPolicy`/`setReadPolicy`、
`getProvider`/`setProvider`、`getEnvironmentPrefix`/`setEnvironmentPrefix`、
`getKeyStore`，以及嵌套 KeyStore 的 `getLocation`/`setLocation`、
`getType`/`setType`、`getPasswordEnvironment`/`setPasswordEnvironment`、
`getPasswordSystemProperty`/`setPasswordSystemProperty` 和
`getActiveIds`/`setActiveIds`。

`PassGuardStringEncryptor.encrypt`/`decrypt` 由 Starter 注册为
`jasyptStringEncryptor`。`ConfigCryptoCli` 只从 stdin 读取明文并向 stdout 输出
`ENC(PG1...)`，避免命令行历史泄漏。完整接入见
[Spring Boot 示例](SPRING_BOOT_EXAMPLE.md)。

自动配置公开的 Bean 工厂方法为 `passGuardKeyProvider`、
`passGuardCipherService`、`passGuardBlindIndexService`、
`passGuardAnnotatedFieldProcessor`、`passGuardJacksonModule`、
`passGuardMyBatisPlugin`、`passGuardR2dbcCallbacks`、
`passGuardHibernate5Customizer`、`passGuardHibernate6Customizer` 和
`jasyptStringEncryptor`。Hibernate 定制器通过 `getIntegrators` 提供事件集成器，
`customize` 不会把密钥材料写入 Hibernate 属性。一般应用只覆盖相同类型的 Bean，无需直接调用
这些工厂方法。

若 classpath 存在 Actuator，`PassGuardActuatorSanitizationConfiguration` 自动注册
`passGuardSanitizingFunction`：敏感键名以及 `PG1`、`BI1`、`ENC(PG1...)` 值统一
显示为脱敏占位符，避免 `/env`、配置属性端点或诊断输出泄漏秘密。

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
  <version>2.1.0</version>
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

`Example` 是固定演示值的独立启动示例，用于发行验证；业务集成不应依赖该类。
