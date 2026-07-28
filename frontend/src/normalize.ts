export function normalizePassword(password: string): string {
  // Deliberately do not trim, lowercase, or remove whitespace.
  return password.normalize('NFC')
}

export function countUnicodeCodePoints(value: string): number {
  let count = 0
  for (const _codePoint of value) count += 1
  return count
}

export function contextComparisonKey(value: string): string {
  return value.normalize('NFKC').toLowerCase()
}
