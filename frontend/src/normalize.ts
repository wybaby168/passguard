/**
 * 返回密码的 Unicode NFC 形式；不会 trim、转小写或删除空白。
 */
export function normalizePassword(password: string): string {
  // Deliberately do not trim, lowercase, or remove whitespace.
  return password.normalize('NFC')
}

/** 按 Unicode 码点而不是 UTF-16 code unit 计数。 */
export function countUnicodeCodePoints(value: string): number {
  let count = 0
  for (const _codePoint of value) count += 1
  return count
}

/**
 * 返回 NFKC 后的小写上下文比较键。
 *
 * 仅用于上下文匹配，不应用于泄露名单或密码存储。
 */
export function contextComparisonKey(value: string): string {
  return value.normalize('NFKC').toLowerCase()
}
