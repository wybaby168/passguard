import { normalizePassword } from './normalize.js'

function linesWithoutTerminators(text: string): string[] {
  return text.split('\n').map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line))
}

/**
 * NFC 规范化、去重的弱密码整串名单。
 */
export class PasswordBlocklist {
  readonly #entries: ReadonlySet<string>

  /**
   * @param entries 每个元素是一条完整密码；空字符串会被忽略
   */
  constructor(entries: Iterable<string>) {
    const normalized = new Set<string>()
    for (const entry of entries) {
      if (entry.length > 0) {
        normalized.add(normalizePassword(entry))
      }
    }
    this.#entries = normalized
  }

  /**
   * 从换行分隔的 UTF-8 文本语义值创建名单。
   *
   * 只移除行终止符，不会 trim 每一行。
   */
  static fromText(text: string): PasswordBlocklist {
    return new PasswordBlocklist(linesWithoutTerminators(text).filter((line) => line.length > 0))
  }

  /**
   * 使用 fetch 加载文本名单。
   *
   * @param url 名单 URL
   * @param signal 可选取消信号
   * @throws 非 2xx HTTP 响应时抛出 Error
   */
  static async fromUrl(url: string, signal?: AbortSignal): Promise<PasswordBlocklist> {
    const requestInit: RequestInit = {
      cache: 'force-cache',
      credentials: 'same-origin',
      ...(signal ? { signal } : {}),
    }
    const response = await fetch(url, requestInit)
    if (!response.ok) {
      throw new Error(`Password blocklist request failed with HTTP ${response.status}`)
    }
    return PasswordBlocklist.fromText(await response.text())
  }

  /** @returns NFC 后的整串密码是否命中 */
  contains(password: string): boolean {
    return this.#entries.has(normalizePassword(password))
  }

  /** 去重后的词条数。 */
  get size(): number {
    return this.#entries.size
  }
}
