# PassGuard 1.0.2 验证记录

验证日期：2026-07-28（Asia/Shanghai）。

## 源包与数据

- 原始 ZIP 内 61 个受校验文件全部通过 SHA-256。
- 使用固定 SecLists `2026.1` 和本地源离线重建。
- 默认前端名单：25,000 条；与发布资源逐字节一致。
- 默认 Java 名单：125,691 条；与发布资源逐字节一致。
- 启用可选 Probable Wordlists 后：125,812 条，增量 121 条。
- `scripts/update_lists.py` 通过 Python 语法检查。
- `scripts/download_hibp.sh` 通过 Bash 语法检查。

## JavaScript / TypeScript

- TypeScript strict 编译通过。
- 10 项 Node.js 测试全部通过，覆盖：
  - NFC 与不 `trim()`；
  - 本地名单、上下文变体、长度与 MFA 策略；
  - HIBP 五位前缀、`Add-Padding`、失败策略与取消信号；
  - 配置不变量；
  - 一行创建的 `createPassGuard()` 高级 API。
- `npm audit --omit=dev --registry=https://registry.npmjs.org`：0 漏洞。
- `npm pack` 产物：34 个文件，约 122.2 KiB 压缩、268.7 KiB 解压。
- 在全新临时项目中从 tarball 安装，ESM 导入和实际弱密码拦截通过。

## Java / Maven

- Java 8 目标编译通过，并使用真实 JDK 8 运行全部测试。
- Maven Compiler 3.15.0、Surefire 3.5.6、JAR 3.5.1、Source 3.4.0
  已在真实 JDK 8 上完成构建，并在 JDK 21 上完成发布产物验证。
- 9 项 JUnit 测试全部通过，覆盖：
  - 完整内置名单加载；
  - Unicode、上下文、长度、强度和泄露策略；
  - 本地 HTTP 服务器验证 HIBP k-anonymity 请求；
  - `PassGuard` 高级 API；
  - Java 8 值对象不可变性与超时参数；
  - 50,000 次本地策略性能预算。
- `mvn -Prelease,ossrh clean verify` 成功生成：
  - 主 JAR；
  - sources JAR；
  - Javadoc JAR；
  - POM；
  - 上述四项的 GPG 签名。
- 签名密钥指纹：`C4B132940C188FE1C013B3A3DF2CC947BCDF2931`。
- JAR 包含 `META-INF/LICENSE`、`META-INF/NOTICE.md`、自动模块名和 125,691 条默认名单。
- 从构建 JAR 独立启动 `io.github.wybaby168.passguard.Example` 通过。

## 依赖更新稳定策略

- Dependabot 将 npm、Maven 插件和 GitHub Actions 的 minor/patch 更新分别分组，减少相互冲突的 PR。
- JUnit 6 要求 Java 17，当前 Java 8 兼容线继续使用 JUnit 5，并忽略其 semver-major 自动更新。
- TypeScript 7 是新的原生编译器主版本；当前发布线继续使用已验证的 TypeScript 5，并忽略其 semver-major 自动更新。
- 全仓 SHA-256 清单仍作为人工审核门禁保留，不因 Bot PR 而跳过。

## 性能基线

测试环境：Apple Silicon、Node.js v26.0.0、当前本机 JDK/Maven。

- JavaScript 25,000 条名单初始化：约 8.8 ms。
- JavaScript 纯名单查询：约 24,500,000 次/秒。
- JavaScript 完整本地策略（关闭 zxcvbn/HIBP）：约 1,100,000 次/秒。
- Java 50,000 次完整本地策略：约 45–55 ms，低于 5 秒回归预算。

性能数字用于版本回归，不代表所有硬件上的绝对值；启用强度估算和 HIBP 后，总延迟主要由估算器及网络决定。
