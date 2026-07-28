import { normalizePassword } from './normalize.js'

function linesWithoutTerminators(text: string): string[] {
  return text.split('\n').map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line))
}

export class PasswordBlocklist {
  readonly #entries: ReadonlySet<string>

  constructor(entries: Iterable<string>) {
    const normalized = new Set<string>()
    for (const entry of entries) {
      if (entry.length > 0) {
        normalized.add(normalizePassword(entry))
      }
    }
    this.#entries = normalized
  }

  static fromText(text: string): PasswordBlocklist {
    return new PasswordBlocklist(linesWithoutTerminators(text).filter((line) => line.length > 0))
  }

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

  contains(password: string): boolean {
    return this.#entries.has(normalizePassword(password))
  }

  get size(): number {
    return this.#entries.size
  }
}
