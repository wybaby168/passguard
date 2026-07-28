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

export class ZxcvbnTsStrengthEstimator implements StrengthEstimator {
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
