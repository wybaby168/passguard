# PassGuard

[![CI](https://github.com/wybaby168/passguard/actions/workflows/ci.yml/badge.svg)](https://github.com/wybaby168/passguard/actions/workflows/ci.yml)
[![Maven Central](https://img.shields.io/maven-central/v/dev.flyfish/passguard)](https://central.sonatype.com/artifact/dev.flyfish/passguard)
[![npm](https://img.shields.io/npm/v/passguard-kit)](https://www.npmjs.com/package/passguard-kit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

PassGuard 是面向注册、改密和密码重置场景的弱密码防御库。它把本地高频弱密码名单、用户/企业上下文、可猜测性评分和 HIBP 泄露密码查询组合成一个易用 API，并同时提供 Java 17+ 与 TypeScript/JavaScript 版本。

> 这是防御工具，不是密码生成器，也不是密码存储库。校验通过后仍须使用 Argon2id、scrypt 或合规参数的 PBKDF2 保存密码。

## 核心能力

- **开箱即用**：Java `PassGuard.create()`；JavaScript `createPassGuard()`。
- **本地高频拦截**：浏览器内置 25,000 条、Java 内置 125,691 条，使用 `Set` 做平均 O(1) 整串查询。
- **上下文拦截**：识别用户名、邮箱前缀、显示名、产品名、企业名及常见年份/数字变体。
- **强度估算**：Java 使用 nbvcxz，JavaScript 使用 zxcvbn-ts；不是机械要求大小写和特殊字符。
- **泄露密码检测**：接入 HIBP Pwned Passwords k-anonymity API，只发送 SHA-1 前 5 位，并启用 `Add-Padding`。
- **Unicode 正确性**：密码按 NFC 规范化，以 Unicode 码点计数，不调用 `trim()`，不擅自修改大小写。
- **可控故障策略**：HIBP 不可用时可选择继续本地判断或拒绝请求。
- **服务端/前端一致**：两端使用相同的判定模型；最终裁决必须在服务端重复执行。

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
  <version>1.0.1</version>
</dependency>
```

```java
import io.github.wybaby168.passguard.PassGuard;
import io.github.wybaby168.passguard.PasswordAssessment;
import io.github.wybaby168.passguard.PasswordContext;

PassGuard guard = PassGuard.builder()
    .contextWords("你的公司名", "你的产品名")
    .build();

PasswordAssessment result = guard.check(
    password,
    userHasMfa,
    new PasswordContext(
        username, email, displayName, "你的产品名", java.util.List.of()
    )
);

if (!result.accepted()) {
    throw new IllegalArgumentException(
        result.firstViolation().orElseThrow().message()
    );
}
```

最短写法：

```java
PassGuard guard = PassGuard.create();       // 本地名单 + nbvcxz + HIBP
PassGuard local = PassGuard.localOnly();    // 不访问外部网络
```

`PassGuard` 实例无状态且可复用。Java 服务中应把它注册为单例 Bean，不能每个请求重复加载名单。

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

```bash
cd frontend && npm run benchmark
cd ../java && mvn test
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

详见 [SECURITY.md](SECURITY.md)、[Java 接入说明](java/README.md) 与 [npm 接入说明](frontend/README.md)。

## 开发与验证

```bash
# JavaScript：严格类型检查 + 10 项测试
cd frontend
npm ci
npm test

# Java：Java 17 编译 + 8 项测试
cd ../java
mvn clean test

# 数据与脚本
cd ..
python3 -m py_compile scripts/update_lists.py
bash -n scripts/download_hibp.sh
python3 scripts/update_lists.py --input-dir data/source --ref 2026.1
```

CI 会覆盖多个 Node.js 与 Java LTS/当前版本。发布前还会验证 npm tarball、Maven sources/Javadoc/GPG 产物和独立消费者安装。

## 数据来源与授权

代码采用 [MIT License](LICENSE)。默认静态名单来自固定到 `2026.1` 的 SecLists 数据；zxcvbn-ts、nbvcxz、HIBP 及可选数据仍遵守各自上游条款。完整来源、固定版本、哈希与取舍见 [SOURCES.md](SOURCES.md) 和 [NOTICE.md](NOTICE.md)。

可选的 Probable Wordlists 带 CC BY-SA 4.0，**没有合并进默认发布名单**。
