# passguard-kit JavaScript / TypeScript API 参考

适用于 `passguard-kit@2.0.0`，原生 ESM，支持现代浏览器和 Node.js 20 及以上版本。

- [返回项目主页](https://github.com/wybaby168/passguard)
- [JavaScript 快速接入](README.md)
- [Java API](https://github.com/wybaby168/passguard/blob/main/java/API.md)

## 如何选择 API

| 需求 | 推荐入口 | 是否访问网络 |
|---|---|---:|
| 使用全部默认防御能力 | `createPassGuard()` | 是 |
| 只做本地预检 | `createPassGuard({ pwnedChecker: false })` | 否 |
| 修改阈值或替换组件 | `new PassGuard(options)` | 可选 |
| 完全控制底层组合 | `new PasswordPolicy(dependencies)` | 可选 |
| 仅管理自定义弱密码名单 | `PasswordBlocklist` | 否 |
| 仅查询 HIBP | `HibpPwnedPasswordClient` | 是 |

多数应用只需要 `createPassGuard()` 和 `guard.check()`。底层导出用于自定义名单、企业内部泄露源、强度算法或测试替身。

## 安装与导入

```bash
npm install passguard-kit
```

```ts
import {
  createPassGuard,
  type PasswordAssessment,
  type PasswordContext,
} from 'passguard-kit'
```

包只提供 ESM 入口。TypeScript 声明随 npm 包发布。

## `createPassGuard`

```ts
function createPassGuard(options?: PassGuardOptions): PassGuard
```

一行创建可复用的高级实例：

```ts
const guard = createPassGuard({
  contextWords: ['example-company', 'example-product'],
})
```

默认包含：

- 25,000 条浏览器侧高频弱密码名单；
- `ZxcvbnTsStrengthEstimator`；
- `HibpPwnedPasswordClient`；
- `DEFAULT_PASSWORD_POLICY`。

## `PassGuard`

```ts
class PassGuard {
  constructor(options?: PassGuardOptions)
  check(
    password: string,
    options?: PassGuardCheckOptions,
  ): Promise<PasswordAssessment>
}
```

实例没有请求级可变状态，应在模块初始化或应用启动时创建一次并复用。

```ts
const result = await guard.check(password, {
  mfaProtected: userHasMfa,
  context: {
    username,
    email,
    displayName,
    serviceName: 'example-product',
    organizationWords: ['example-company'],
  },
  signal: abortController.signal,
})
```

`password` 会执行 NFC 规范化，但不会 `trim()`、转小写或删除空白。远程检查、异步强度估算器和取消信号使 `check()` 始终返回 Promise。

## `PassGuardOptions`

| 属性 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `contextWords` | `readonly string[]` | `[]` | 所有用户共享的产品名、企业名等 |
| `blocklist` | `PasswordBlocklist` | 内置 25,000 条名单 | 替换本地名单 |
| `strengthEstimator` | `StrengthEstimator \| false` | zxcvbn-ts | 自定义或关闭强度估算 |
| `pwnedChecker` | `PwnedPasswordChecker \| false` | HIBP | 自定义或关闭泄露检查 |
| `config` | `Partial<PasswordPolicyConfig>` | 默认策略 | 覆盖指定策略项 |

关闭所有可选慢路径：

```ts
const localGuard = createPassGuard({
  strengthEstimator: false,
  pwnedChecker: false,
})
```

这仍会执行长度、本地名单和上下文检查。

## `PassGuardCheckOptions`

继承 `Partial<AssessOptions>`。

| 属性 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `mfaProtected` | `boolean` | `false` | 是否使用 MFA 场景最小长度 |
| `context` | `PasswordContext` | `{}` | 当前用户和业务上下文 |
| `signal` | `AbortSignal` | 无 | 取消 HIBP 或自定义异步实现 |

## `PasswordContext`

```ts
interface PasswordContext {
  readonly username?: string
  readonly email?: string
  readonly displayName?: string
  readonly serviceName?: string
  readonly organizationWords?: readonly string[]
}
```

上下文词会生成常见数字、符号和相邻年份变体，最终只做整串匹配，不做子串拒绝。邮箱会额外提取 `@` 前的本地部分。

不要把含用户名或邮箱的完整上下文写入日志。

## `PasswordAssessment`

```ts
interface PasswordAssessment {
  readonly accepted: boolean
  readonly codePointLength: number
  readonly strengthScore: number | null
  readonly pwnedStatus: PwnedStatus
  readonly pwnedCount: number | null
  readonly violations: readonly PasswordViolation[]
}
```

| 属性 | 说明 |
|---|---|
| `accepted` | 没有任何违规项时为 `true` |
| `codePointLength` | NFC 后的 Unicode 码点数 |
| `strengthScore` | 0–4；未启用或空密码时为 `null` |
| `pwnedStatus` | `clear`、`pwned`、`unavailable` 或 `skipped` |
| `pwnedCount` | 泄露出现次数；未查或不可用时通常为 `null` |
| `violations` | 稳定机器码与通用中文消息列表 |

## 违规类型

```ts
interface PasswordViolation {
  readonly code: PasswordViolationCode
  readonly message: string
}
```

`PasswordViolationCode` 包含：

| 值 | 触发条件 |
|---|---|
| `EMPTY` | 密码为空 |
| `TOO_SHORT` | 小于当前 MFA 场景最小长度 |
| `TOO_LONG` | 超过最大长度 |
| `COMMON_PASSWORD` | 命中本地名单 |
| `CONTEXT_PASSWORD` | 命中用户、产品或组织上下文变体 |
| `LOW_STRENGTH` | 强度分低于阈值 |
| `PWNED_PASSWORD` | 泄露次数达到拒绝阈值 |
| `PWNED_CHECK_UNAVAILABLE` | 泄露源不可用且策略为拒绝 |

业务逻辑应判断 `code`，不要依赖 `message` 文案。

## 策略配置

### `PasswordPolicyConfig`

| 属性 | 默认值 | 约束与含义 |
|---|---:|---|
| `minLengthSingleFactor` | 15 | 至少为 1 |
| `minLengthWithMfa` | 8 | 至少为 1 |
| `maxLength` | 128 | 至少为 64，且不小于两个最小长度 |
| `minimumStrengthScore` | 3 | 0–4 |
| `rejectPwnedCountAtLeast` | 1 | 有限数且至少为 1 |
| `hibpFailureMode` | `ALLOW_WITH_LOCAL_CHECKS` | HIBP 不可用时继续或拒绝 |
| `skipRemoteCheckWhenAlreadyRejected` | `true` | 本地已拒绝时跳过远程调用 |

完整默认值由只读常量 `DEFAULT_PASSWORD_POLICY` 导出。

```ts
const guard = createPassGuard({
  config: {
    maxLength: 256,
    minimumStrengthScore: 2,
    hibpFailureMode: 'REJECT',
  },
})
```

配置不满足约束时，`PassGuard` 或 `PasswordPolicy` 构造器抛出 `Error`。

### `HibpFailureMode`

```ts
type HibpFailureMode = 'ALLOW_WITH_LOCAL_CHECKS' | 'REJECT'
```

- `ALLOW_WITH_LOCAL_CHECKS`：远程不可用时依赖已执行的本地规则。
- `REJECT`：增加 `PWNED_CHECK_UNAVAILABLE` 违规项。

## `PasswordPolicy`

低层策略编排器：

```ts
class PasswordPolicy {
  constructor(dependencies: PasswordPolicyDependencies)
  assess(
    password: string,
    options: AssessOptions,
  ): Promise<PasswordAssessment>
}
```

### `PasswordPolicyDependencies`

| 属性 | 必需 | 说明 |
|---|---:|---|
| `blocklist` | 是 | 本地名单 |
| `contextChecker` | 否 | 默认使用空全局词的检查器 |
| `strengthEstimator` | 否 | 缺省表示关闭 |
| `pwnedChecker` | 否 | 缺省表示关闭 |
| `config` | 否 | 默认策略的局部覆盖 |

### `AssessOptions`

| 属性 | 必需 | 说明 |
|---|---:|---|
| `mfaProtected` | 是 | 决定使用哪个最小长度 |
| `context` | 否 | 当前上下文 |
| `signal` | 否 | 传给泄露检查器 |

```ts
const policy = new PasswordPolicy({
  blocklist,
  contextChecker,
  strengthEstimator,
  pwnedChecker,
  config: { hibpFailureMode: 'REJECT' },
})

const result = await policy.assess(password, {
  mfaProtected: false,
  context,
})
```

执行顺序为：规范化与长度、本地名单、上下文、强度、远程泄露检查。默认在已有本地违规时跳过远程请求。

## 本地名单 API

### `PasswordBlocklist`

```ts
class PasswordBlocklist {
  constructor(entries: Iterable<string>)
  static fromText(text: string): PasswordBlocklist
  static fromUrl(
    url: string,
    signal?: AbortSignal,
  ): Promise<PasswordBlocklist>
  contains(password: string): boolean
  readonly size: number
}
```

- 构造器会 NFC 规范化、去重并忽略空字符串。
- `fromText` 按行解析，只移除 `LF` 或 `CRLF` 行终止符，不会 `trim()`。
- `fromUrl` 使用 `force-cache`、`same-origin` 和可选取消信号；非 2xx 响应抛出 `Error`。
- `contains` 做 NFC 后整串查询。

## 上下文 API

### `ContextPasswordChecker`

```ts
class ContextPasswordChecker {
  constructor(globalWords?: readonly string[])
  isBlocked(
    password: string,
    context?: PasswordContext,
  ): boolean
}
```

构造器会预计算全局词变体，实例应复用。长度小于 3 的 token 不参与候选生成。

## 强度估算 API

### `StrengthResult`

```ts
interface StrengthResult {
  readonly score: number
  readonly warning?: string
  readonly suggestions?: readonly string[]
}
```

### `StrengthEstimator`

```ts
interface StrengthEstimator {
  estimate(
    password: string,
    userInputs?: readonly string[],
  ): Promise<StrengthResult> | StrengthResult
}
```

自定义实现可以同步或异步。`score` 应使用 0–4 的 zxcvbn 兼容范围。

### `ZxcvbnTsStrengthEstimator`

```ts
class ZxcvbnTsStrengthEstimator implements StrengthEstimator {
  estimate(
    password: string,
    userInputs?: readonly string[],
  ): StrengthResult
}
```

使用 `@zxcvbn-ts/core`、通用词典和英文词典，并返回分值、可选警告及建议。

## 泄露密码 API

### `PwnedStatus`

```ts
type PwnedStatus = 'clear' | 'pwned' | 'unavailable' | 'skipped'
```

- `skipped` 只由策略层产生。
- 检查器的 `PwnedCheckResult.status` 排除 `skipped`。

### `PwnedCheckResult`

```ts
interface PwnedCheckResult {
  readonly status: 'clear' | 'pwned' | 'unavailable'
  readonly count: number | null
  readonly reason?: string
}
```

### `PwnedPasswordChecker`

```ts
interface PwnedPasswordChecker {
  check(
    password: string,
    signal?: AbortSignal,
  ): Promise<PwnedCheckResult>
}
```

可用于接入企业内部代理、离线哈希库、缓存层或测试替身。不要把明文密码发送到未经审计的服务。

### `HibpClientOptions`

| 属性 | 默认值 | 说明 |
|---|---|---|
| `endpoint` | `https://api.pwnedpasswords.com/range/` | range API 基础地址 |
| `timeoutMs` | 5000 | 正有限毫秒数 |
| `fetchImpl` | `globalThis.fetch` | 自定义 fetch、代理或测试替身 |

### `HibpPwnedPasswordClient`

```ts
class HibpPwnedPasswordClient implements PwnedPasswordChecker {
  constructor(options?: HibpClientOptions)
  check(
    password: string,
    signal?: AbortSignal,
  ): Promise<PwnedCheckResult>
}
```

实现行为：

- 对 NFC 后密码计算 SHA-1；
- 仅发送前 5 个十六进制字符；
- 设置 `Add-Padding: true`；
- 在本地比较返回的哈希后缀；
- 超时、取消、缺少 Web Crypto、网络和 HTTP 错误统一返回 `unavailable`。

SHA-1 仅用于 HIBP 索引兼容，不能用于密码存储。

## 规范化工具

### `normalizePassword`

```ts
function normalizePassword(password: string): string
```

返回 Unicode NFC；不修改大小写或空白。

### `countUnicodeCodePoints`

```ts
function countUnicodeCodePoints(value: string): number
```

按 Unicode 码点计数，避免直接使用 UTF-16 `string.length`。

### `contextComparisonKey`

```ts
function contextComparisonKey(value: string): string
```

返回 NFKC 后的小写上下文比较键。仅用于上下文匹配，不应用于本地泄露名单或密码存储。

## 取消、异常与运行环境

- `PassGuard.check` 本身把 HIBP 失败表达为结果状态，不会因网络失败拒绝 Promise。
- `PasswordBlocklist.fromUrl` 的 HTTP 失败会抛出 `Error`。
- 构造器配置不合法会同步抛出 `Error`。
- 自定义 `StrengthEstimator` 或 `PwnedPasswordChecker` 抛出的异常不会被策略层自动吞掉。
- HIBP 需要 `fetch`、`AbortController`、`TextEncoder` 和 Web Crypto `subtle.digest`。
- 浏览器直连 HIBP 时 CSP 至少允许 `connect-src https://api.pwnedpasswords.com`。

## 日志与安全边界

- 不要记录密码、完整 SHA-1、HIBP 响应体或带个人信息的上下文。
- 可记录违规 `code`、`pwnedStatus`、耗时和匿名化统计。
- 浏览器结果只用于用户体验；最终裁决必须在可信服务端重复执行。
- 校验通过后仍需使用 Argon2id、scrypt 或合规参数的 PBKDF2 存储密码。
