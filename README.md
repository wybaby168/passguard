# PassGuard

[![CI](https://github.com/wybaby168/passguard/actions/workflows/ci.yml/badge.svg)](https://github.com/wybaby168/passguard/actions/workflows/ci.yml)
[![Maven Central](https://img.shields.io/maven-central/v/dev.flyfish/passguard)](https://central.sonatype.com/artifact/dev.flyfish/passguard)
[![npm](https://img.shields.io/npm/v/passguard-kit)](https://www.npmjs.com/package/passguard-kit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

PassGuard 是模块化密码安全工具包。它同时覆盖弱密码防御、安全密码生成、登录密码哈希、密钥轮换、配置文件解密，以及 MyBatis、JPA/Hibernate、R2DBC 数据库字段透明加解密。核心模块支持 Java 8，JavaScript 生成器支持现代浏览器和 Node.js 20+。

> 登录密码必须使用 Argon2id/PBKDF2 等不可逆哈希；AES-GCM 可逆加密只用于必须恢复明文的数据库连接口令、第三方凭据和 API 密钥。

## 核心能力

- **开箱即用**：Java `PassGuard.create()`；JavaScript `createPassGuard()`。
- **安全生成与哈希**：Java/JS 使用密码学安全随机源生成密码；Java 提供 Argon2id 和 PBKDF2。
- **认证加密与轮换**：AES-256-GCM、版本化 key id、环境变量、PKCS12/JCEKS 与 `KeyProvider` SPI。
- **透明数据库保护**：一个 `@Encrypted` 完成写入加密、查询解密；可选 HMAC 盲索引支持等值查询。
- **配置文件解密**：Spring Boot 2/3 Starter 通过 jasypt-spring-boot 处理 `ENC(...)`，注入值保持明文。
- **前端响应排除**：Jackson 自动把 `@Encrypted` 属性设为 write-only，不返回掩码或密文。
- **本地高频拦截**：浏览器内置 25,000 条、Java 内置 125,691 条，使用 `Set` 做平均 O(1) 整串查询。
- **上下文拦截**：识别用户名、邮箱前缀、显示名、产品名、企业名及常见年份/数字变体。
- **强度估算**：Java 使用 nbvcxz，JavaScript 使用 zxcvbn-ts；不是机械要求大小写和特殊字符。
- **泄露密码检测**：接入 HIBP Pwned Passwords k-anonymity API，只发送 SHA-1 前 5 位，并启用 `Add-Padding`。
- **Unicode 正确性**：密码按 NFC 规范化，以 Unicode 码点计数，不调用 `trim()`，不擅自修改大小写。
- **可控故障策略**：HIBP 不可用时可选择继续本地判断或拒绝请求。
- **服务端/前端一致**：两端使用相同的判定模型；最终裁决必须在服务端重复执行。

## API 文档与选型

| 开发场景 | Java | JavaScript / TypeScript |
|---|---|---|
| 完整默认能力 | `PassGuard.create()` | `createPassGuard()` |
| 无网络本地预检 | `PassGuard.localOnly()` | `createPassGuard({ pwnedChecker: false })` |
| 修改阈值或替换组件 | `PassGuard.builder()` | `new PassGuard(options)` |
| 完全控制底层组合 | `new PasswordPolicy(...)` | `new PasswordPolicy(dependencies)` |

- [Java 完整 API 参考](java/API.md)：所有公开类、构建器、配置、结果、扩展接口和异常语义。
- [JavaScript / TypeScript 完整 API 参考](frontend/API.md)：所有导出函数、类、接口、选项、取消与运行环境。
- [在线 Java Javadoc](https://javadoc.io/doc/dev.flyfish/passguard/latest/index.html)。
- npm 包内同时发布 TypeScript 声明和 `API.md`，IDE 可直接显示 TSDoc。

## 30 秒接入

### JavaScript / TypeScript

```bash
npm install passguard-kit
```

```ts
import { createPassGuard } from 'passguard-kit'

// 应在应用启动时创建一次并复用。
const guard = createPassGuard({
  contextWords: ['你的公司名', '你的产品名'],
})

const result = await guard.check(password, {
  mfaProtected: userHasMfa,
  context: {
    username,
    email,
    displayName,
    serviceName: '你的产品名',
  },
})

if (!result.accepted) {
  // 只记录 code，绝不要记录 password。
  throw new Error(result.violations[0]?.message ?? '密码不符合安全要求')
}
```

默认实例包含 25,000 条本地名单、zxcvbn-ts 和 HIBP 查询，不需要额外下载名单。只做无网络的本地预检：

```ts
const localGuard = createPassGuard({ pwnedChecker: false })
```

支持现代浏览器和 Node.js 20+，发布包为原生 ESM。

### Java

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

import java.util.Collections;

PassGuard guard = PassGuard.builder()
    .contextWords("你的公司名", "你的产品名")
    .build();

PasswordAssessment result = guard.check(
    password,
    userHasMfa,
    new PasswordContext(
        username, email, displayName, "你的产品名",
        Collections.emptyList()
    )
);

if (!result.accepted()) {
    throw new IllegalArgumentException(result.violations().get(0).message());
}
```

最短写法：

```java
PassGuard guard = PassGuard.create();       // 本地名单 + nbvcxz + HIBP
PassGuard local = PassGuard.localOnly();    // 不访问外部网络
```

`PassGuard` 实例无状态且可复用。Java 服务中应把它注册为单例 Bean，不能每个请求重复加载名单。

Java 包从 `1.0.2` 开始以 Java 8 字节码（class major version 52）发布，并在真实 JDK 8 上执行完整测试；同一 JAR 可直接用于 Java 8、11、17、21、25。

> `2.0.0` 将 Java 包统一为 `dev.flyfish.passguard`，与 Maven 坐标
> `dev.flyfish:passguard` 保持一致。由 `1.x` 升级时只需更新 import，
> 策略 API 和 Maven 坐标不变。

## 按需选择 Java 模块

| 需求 | Maven artifactId | Java |
|---|---|---:|
| 弱密码检测 | `passguard` | 8+ |
| 安全密码生成 | `passguard-generator` | 8+ |
| Argon2id / PBKDF2 | `passguard-password-hash` | 8+ |
| AES-GCM、密钥和注解 | `passguard-crypto-core` | 8+ |
| JSON 响应排除 | `passguard-crypto-jackson` | 8+ |
| MyBatis | `passguard-crypto-mybatis` | 8+ |
| JPA 2.2 / Hibernate 5 | `passguard-crypto-jpa-javax` | 8+ |
| Jakarta / Hibernate 6 | `passguard-crypto-jpa-jakarta` | 17+ |
| R2DBC | `passguard-crypto-r2dbc-boot2` / `passguard-crypto-r2dbc-boot3` | 8 / 17 |
| 配置文件解密 | `passguard-spring-boot2-starter` / `passguard-spring-boot3-starter` | 8 / 17 |

推荐先导入 BOM，再只声明需要的模块：

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>dev.flyfish</groupId>
      <artifactId>passguard-bom</artifactId>
      <version>2.1.0</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

## 密码生成与登录密码哈希

```java
import dev.flyfish.passguard.generator.SecurePasswordGenerator;
import dev.flyfish.passguard.hash.PasswordHasher;
import dev.flyfish.passguard.hash.PasswordHashers;

String generated = new SecurePasswordGenerator().generate();

PasswordHasher hasher = PasswordHashers.argon2id();
String storedHash = hasher.hash(userPassword);
boolean matches = hasher.verify(loginPassword, storedHash);
```

JavaScript 可以只加载生成器子路径：

```ts
import { generatePassword } from 'passguard-kit/generator'

const password = generatePassword({ length: 24, excludeAmbiguous: true })
```

## 数据库字段透明加解密

```java
import dev.flyfish.passguard.crypto.annotation.BlindIndex;
import dev.flyfish.passguard.crypto.annotation.Encrypted;

class ExternalCredential {
    @Encrypted(keyAlias = "data", context = "external_credential.password")
    private String password;

    @BlindIndex(
        source = "password",
        keyAlias = "index",
        context = "external_credential.password_index"
    )
    private String passwordIndex;
}
```

再引入当前项目使用的 MyBatis、JPA 或 R2DBC 适配模块即可。Spring Boot 会自动注册适配器；数据库保存 `PG1...` 密文，业务实体读取到明文，Jackson 响应不包含 `password`。

环境变量密钥约定：

```text
PASSGUARD_KEY_DATA_ACTIVE=v1
PASSGUARD_KEY_DATA_V1=<32 字节随机密钥的 Base64>
PASSGUARD_KEY_INDEX_ACTIVE=v1
PASSGUARD_KEY_INDEX_V1=<另一把 32 字节随机密钥的 Base64>
PASSGUARD_KEY_CONFIG_ACTIVE=v1
PASSGUARD_KEY_CONFIG_V1=<另一把 32 字节随机密钥的 Base64>
```

配置文件写入 `ENC(PG1...)`，Spring 的 `Environment`、`@Value` 和 `@ConfigurationProperties` 获得明文。密钥不能写回 `application.yml`。

## 判定结果

两端都会返回这些核心字段：

| 字段 | 含义 |
|---|---|
| `accepted` | 是否通过全部已启用规则 |
| `codePointLength` | NFC 后的 Unicode 码点长度 |
| `strengthScore` | 0–4 的强度评分；未启用时为 `null` |
| `pwnedStatus` | `clear` / `pwned` / `unavailable` / `skipped` |
| `pwnedCount` | HIBP 记录的出现次数 |
| `violations` | 稳定错误码和中文通用提示列表 |

错误码包括：`EMPTY`、`TOO_SHORT`、`TOO_LONG`、`COMMON_PASSWORD`、`CONTEXT_PASSWORD`、`LOW_STRENGTH`、`PWNED_PASSWORD`、`PWNED_CHECK_UNAVAILABLE`。

## 默认安全策略

| 项目 | 默认值 |
|---|---:|
| 无 MFA 最短长度 | 15 个 Unicode 码点 |
| 有 MFA 最短长度 | 8 个 Unicode 码点 |
| 最大长度 | 128 个 Unicode 码点 |
| 最低强度分 | 3 / 4 |
| HIBP 拒绝阈值 | 出现至少 1 次 |
| 已被本地拒绝时 | 跳过 HIBP，减少网络请求 |
| HIBP 不可用时 | 依靠本地检查继续；高保证业务可改为拒绝 |

需要自定义时，Java 使用 `PasswordPolicyConfig`，JavaScript 使用 `config`：

```ts
const guard = createPassGuard({
  config: {
    hibpFailureMode: 'REJECT',
    maxLength: 256,
  },
})
```

## 性能

本地名单在实例初始化时只解析一次，后续为哈希集合查询；全局产品/企业词的常见变体也只预计算一次。

在 Apple Silicon、Node.js 26 的一次本地基准中：

- 25,000 条名单初始化约 **8.8 ms**；
- 纯名单查询约 **2,450 万次/秒**；
- 关闭 zxcvbn/HIBP 的完整本地策略约 **110 万次/秒**。

Java 测试在 5 秒预算内执行 50,000 次完整本地策略校验，当前机器实测约 48 ms。以上数据用于回归对比，不代表所有硬件上的绝对承诺；真实总延迟通常由 zxcvbn/nbvcxz 计算和 HIBP 网络往返主导。运行自己的基准：

发布 CI 还使用 JMH 覆盖 32/128/1024 字节 AES-GCM、注解元数据缓存和安全密码生成；
CI 固定 Ubuntu 24.04、Temurin 17.0.19 和预热/测量参数，结果与已提交基线比较，
吞吐下降超过 15% 会阻止合并，并始终保留原始 JSON 供审计。Argon2id 是故意的慢操作，
单独验证默认参数的交互延迟，不与快速加密吞吐混为一谈。

```bash
cd frontend && npm run benchmark
cd ../java && mvn test
mvn -pl passguard-benchmarks -am package
java -jar passguard-benchmarks/target/passguard-benchmarks.jar
```

## 正确部署

推荐链路：

1. 浏览器本地快速提示；
2. 用户提交时执行 HIBP 查询；
3. 服务端使用 Java 或服务端 JavaScript 版本重复最终校验；
4. 通过后使用专用密码 KDF 保存。

重要边界：

- 不要把密码、完整 SHA-1、HIBP 响应写入日志、异常、埋点或 APM。
- HIBP 只应在提交/失焦后查询，不能每次按键都查询。
- 浏览器逻辑可被绕过，不能作为安全边界。
- SHA-1 仅用于 HIBP 索引格式，绝不能用于密码存储。
- 本地名单、上下文词均做整串匹配；不要因为密码包含一个短词就拒绝。

详见 [SECURITY.md](SECURITY.md)、[Java API](java/API.md) 与
[JavaScript / TypeScript API](frontend/API.md)。

## 开发与验证

```bash
# JavaScript：严格类型检查 + 全部测试
cd frontend
npm ci
npm test

# Java：Java 8/17 分层编译 + 全部模块测试
cd ../java
mvn clean test

# 数据与脚本
cd ..
python3 -m py_compile scripts/update_lists.py
bash -n scripts/download_hibp.sh
python3 scripts/update_lists.py --input-dir data/source --ref 2026.1
```

CI 会在 Java 8、11、17、21、25 上运行完整测试，并覆盖多个 Node.js 版本。发布前还会验证 Java 8 字节码、npm tarball、Maven sources/Javadoc/GPG 产物和独立消费者安装。

## 数据来源与授权

代码采用 [MIT License](LICENSE)。默认静态名单来自固定到 `2026.1` 的 SecLists 数据；zxcvbn-ts、nbvcxz、HIBP 及可选数据仍遵守各自上游条款。完整来源、固定版本、哈希与取舍见 [SOURCES.md](SOURCES.md) 和 [NOTICE.md](NOTICE.md)。

可选的 Probable Wordlists 带 CC BY-SA 4.0，**没有合并进默认发布名单**。
