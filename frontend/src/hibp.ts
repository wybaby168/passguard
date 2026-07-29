import { normalizePassword } from './normalize.js'
import type { PwnedCheckResult, PwnedPasswordChecker } from './types.js'

function bytesToUpperHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase()
}

async function sha1UpperHex(value: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto API is unavailable')
  }
  const bytes = new TextEncoder().encode(value)
  return bytesToUpperHex(await globalThis.crypto.subtle.digest('SHA-1', bytes))
}

/** HIBP Pwned Passwords range API 客户端选项。 */
export interface HibpClientOptions {
  /** range API 基础地址。 */
  readonly endpoint?: string
  /** 正的有限超时毫秒数，默认 5000。 */
  readonly timeoutMs?: number
  /** 自定义 fetch、代理或测试替身。 */
  readonly fetchImpl?: typeof fetch
}

/**
 * HIBP Pwned Passwords k-anonymity 客户端。
 *
 * 仅发送 NFC 后密码 SHA-1 的前 5 个十六进制字符，并在本地比较后缀。
 * SHA-1 不能用于密码存储。
 */
export class HibpPwnedPasswordClient implements PwnedPasswordChecker {
  readonly #endpoint: string
  readonly #timeoutMs: number
  readonly #fetch: typeof fetch

  /**
   * @param options 端点、超时和 fetch 实现
   * @throws timeoutMs 不是正有限数时抛出 Error
   */
  constructor(options: HibpClientOptions = {}) {
    this.#endpoint = options.endpoint ?? 'https://api.pwnedpasswords.com/range/'
    this.#timeoutMs = options.timeoutMs ?? 5_000
    if (!Number.isFinite(this.#timeoutMs) || this.#timeoutMs <= 0) {
      throw new Error('timeoutMs must be positive')
    }
    this.#fetch = options.fetchImpl ?? globalThis.fetch.bind(globalThis)
  }

  /**
   * 查询泄露状态。超时、取消、Web Crypto、网络、HTTP 和解析问题会返回
   * unavailable，而不是拒绝 Promise。
   *
   * @param password 待检查密码
   * @param signal 可选调用方取消信号
   */
  async check(password: string, signal?: AbortSignal): Promise<PwnedCheckResult> {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(new Error('HIBP request timeout')), this.#timeoutMs)
    const abortFromCaller = () => controller.abort(signal?.reason)
    if (signal?.aborted) {
      abortFromCaller()
    } else {
      signal?.addEventListener('abort', abortFromCaller, { once: true })
    }

    try {
      const digest = await sha1UpperHex(normalizePassword(password))
      const prefix = digest.slice(0, 5)
      const suffix = digest.slice(5)
      const response = await this.#fetch(`${this.#endpoint}${prefix}`, {
        headers: {
          Accept: 'text/plain',
          'Add-Padding': 'true',
        },
        signal: controller.signal,
      })

      if (!response.ok) {
        return { status: 'unavailable', count: null, reason: `HTTP ${response.status}` }
      }

      for (const line of (await response.text()).split(/\r?\n/)) {
        const separator = line.indexOf(':')
        if (separator < 1) continue
        if (line.slice(0, separator).toUpperCase() === suffix) {
          const count = Number.parseInt(line.slice(separator + 1), 10)
          if (Number.isFinite(count) && count > 0) return { status: 'pwned', count }
        }
      }
      return { status: 'clear', count: 0 }
    } catch (error: unknown) {
      const reason = error instanceof Error ? error.message : 'unknown HIBP error'
      return { status: 'unavailable', count: null, reason }
    } finally {
      clearTimeout(timeout)
      signal?.removeEventListener('abort', abortFromCaller)
    }
  }
}
