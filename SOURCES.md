# 数据源与组件清单

## 1. SecLists（默认静态基线）

- 仓库：<https://github.com/danielmiessler/SecLists>
- 固定版本：`2026.1`（本包不使用浮动 `master`）
- Release：<https://github.com/danielmiessler/SecLists/releases/tag/2026.1>
- 授权：仓库 MIT License；副本见 `data/source/SecLists-LICENSE`

默认并集按以下优先级构建：

1. `2025-199_most_used_passwords.txt`：最近年度高频项，优先进入前端子集。
2. `10k-most-common.txt`：经典高频基础名单。
3. `Pwdb_top-100000.txt`：更大规模的频次排序来源。
4. `100k-most-used-passwords-NCSC.txt`：NCSC 常见密码名单，经 SecLists 整理。

原始路径均位于 SecLists 的 `Passwords/Common-Credentials/`。更新脚本记录下载 URL、条数和 SHA-256，条数异常会失败，不会静默发布空文件。

## 2. HIBP Pwned Passwords（动态泄露基线）

- 官方说明：<https://haveibeenpwned.com/Passwords>
- API：<https://haveibeenpwned.com/API/v3#PwnedPasswords>
- 官方下载器：<https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader>

它是本方案的“持续更新层”。API 只发送 SHA-1 哈希的前 5 个十六进制字符，并在本地比对返回后缀；建议请求头 `Add-Padding: true`。SHA-1 在这里仅为与 HIBP 索引兼容，密码存储仍应使用 Argon2id/scrypt/PBKDF2 等专用 KDF。

完整离线 HIBP 数据可能非常大，默认不塞进源码仓库。使用 `scripts/download_hibp.sh` 下载或增量更新，并将文件存放在受控数据卷或对象存储中。

## 3. Probable Wordlists v2（可选历史源）

- 仓库：<https://github.com/berzerk0/Probable-Wordlists>
- 授权：CC BY-SA 4.0
- 本包文件：`data/optional/probable-v2_top-12000.txt`
- 许可证副本：`data/optional/Probable-Wordlists-LICENSE.txt`

该来源已多年未形成新的主版本，且在当前四源生产并集上只增加 121 个唯一项。为了避免陈旧数据和独立 ShareAlike 条款无意进入商业构建，本包默认不合并，只保留作回归评估和来源对照。

## 4. zxcvbn-ts（浏览器强度估算）

- 官网文档：<https://zxcvbn-ts.github.io/zxcvbn/>
- 仓库：<https://github.com/zxcvbn-ts/zxcvbn>
- npm：`@zxcvbn-ts/core`、`@zxcvbn-ts/language-common`、`@zxcvbn-ts/language-en`
- 授权：MIT

本包使用 v4 的 `ZxcvbnFactory` API，并固定依赖版本。它用于识别字典词、重复、序列、键盘路径等可猜测模式；不能替代泄露密码黑名单。

## 5. nbvcxz（Java 强度估算）

- 仓库：<https://github.com/GoSimpleLLC/nbvcxz>
- Maven：`me.gosimple:nbvcxz:1.5.1`
- 授权：MIT

它是 Java 侧与 zxcvbn 类似的估算器，支持中文反馈、字典和上下文排除。1.5.1 是当前上游最新发布，但发布时间较早，因此应固定版本、做依赖扫描，并把它视为补充信号，而不是唯一安全判据。

## 6. 规范依据

- NIST SP 800-63B：密码应与常见、预期、已泄露值的 blocklist 做整串比较；不建议机械组成规则；单因素最少 15、MFA 场景最少 8、最大长度至少 64；接受 Unicode 时应使用 NFC。
- OWASP Authentication Cheat Sheet：使用常见/泄露密码阻止名单和强度估算器。
- OWASP Password Storage Cheat Sheet：优先 Argon2id；SHA-1 不得用于密码存储。

## 未打包的超大语料

RockYou、各类 combo list、带邮箱/用户名的泄露集合以及来源不明的“几十 GB 密码字典”没有被打包。原因包括：

- 常含个人账号标识，不符合最小化收集原则；
- 授权与来源难以审计；
- 大量内容是攻击型变体，不等同于高价值注册 blocklist；
- 静态越大并不等于在线注册防御越有效，反而增加浏览器体积、内存和误报。

需要全量离线泄露校验时，应优先用 HIBP 官方哈希下载链路，而不是下载来源不明的明文组合库。
