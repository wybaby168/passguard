# passguard-kit

PassGuard 的 TypeScript/JavaScript 包，面向现代浏览器与 Node.js 20+。提供 Web Crypto 安全密码生成器，并内置 25,000 条高频弱密码名单、zxcvbn-ts 强度估算、上下文变体和 HIBP k-anonymity 查询。

- [完整 JavaScript / TypeScript API 参考](API.md)
- npm 包包含 TypeScript 声明，IDE 可直接显示参数和 TSDoc

## 安装

```bash
npm install passguard-kit
```

只需要密码生成器：

```ts
import { generatePassword } from 'passguard-kit/generator'

const generated = generatePassword({
  length: 24,
  excludeAmbiguous: true,
})
```

```ts
import { createPassGuard } from 'passguard-kit'

const guard = createPassGuard({
  contextWords: ['你的公司名', '你的产品名'],
})

const result = await guard.check(password, {
  mfaProtected: false,
  context: { username, email, serviceName: '你的产品名' },
})

if (!result.accepted) {
  console.log(result.violations)
}
```

实例应在应用启动时创建一次并复用。默认会在本地规则通过后查询 HIBP；关闭外部网络访问：

```ts
const localGuard = createPassGuard({ pwnedChecker: false })
```

## 高级组合

```ts
import {
  ContextPasswordChecker,
  HibpPwnedPasswordClient,
  PasswordBlocklist,
  PasswordPolicy,
  ZxcvbnTsStrengthEstimator,
} from 'passguard-kit'

const policy = new PasswordPolicy({
  blocklist: PasswordBlocklist.fromText('123456\npassword\n'),
  contextChecker: new ContextPasswordChecker(['你的产品名']),
  strengthEstimator: new ZxcvbnTsStrengthEstimator(),
  pwnedChecker: new HibpPwnedPasswordClient({ timeoutMs: 3000 }),
  config: { hibpFailureMode: 'REJECT' },
})
```

`PasswordBlocklist.fromUrl()` 可加载自定义名单。读取时仅移除换行符，不会 `trim()` 密码。

所有导出函数、类、接口、配置默认值、返回字段、违规码、取消和失败语义见
[完整 API 参考](API.md)。

## 浏览器部署

HIBP 直连需要 CSP：

```text
connect-src 'self' https://api.pwnedpasswords.com
```

建议只在提交或输入框失焦后调用，不要逐键调用。前端结果只用于用户体验，服务端必须重复校验。

## 构建与验证

```bash
npm ci
npm test
npm run benchmark
npm pack --dry-run
```

完整中文文档、安全边界和 Java 版本见 [GitHub 仓库](https://github.com/wybaby168/passguard)。
