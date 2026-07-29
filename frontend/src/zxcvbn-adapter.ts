import { ZxcvbnFactory } from '@zxcvbn-ts/core'
import * as languageCommon from '@zxcvbn-ts/language-common'
import * as languageEn from '@zxcvbn-ts/language-en'
import type { StrengthEstimator, StrengthResult } from './types.js'

const factory = new ZxcvbnFactory({
  translations: languageEn.translations,
  graphs: languageCommon.adjacencyGraphs,
  dictionary: {
    ...languageCommon.dictionary,
    ...languageEn.dictionary,
  },
})

/**
 * 使用 zxcvbn-ts 通用及英文词典的默认强度估算器。
 */
export class ZxcvbnTsStrengthEstimator implements StrengthEstimator {
  /**
   * @param password 已完成 NFC 规范化的密码
   * @param userInputs 用户名、邮箱、产品名等上下文输入
   */
  estimate(password: string, userInputs: readonly string[] = []): StrengthResult {
    const result = factory.check(password, [...userInputs])
    return {
      score: result.score,
      ...(result.feedback.warning ? { warning: result.feedback.warning } : {}),
      ...(result.feedback.suggestions.length > 0
        ? { suggestions: result.feedback.suggestions }
        : {}),
    }
  }
}
