package dev.flyfish.passguard;

import java.text.Normalizer;
import java.util.Locale;

final class PasswordNormalizer {
    private PasswordNormalizer() {}

    static String normalizePassword(String value) {
        // Deliberately do not trim, lowercase, or remove whitespace.
        return Normalizer.normalize(value, Normalizer.Form.NFC);
    }

    /**
     * Creates a comparison-only key for weak-password dictionaries.
     *
     * <p>NFKC closes compatibility-character bypasses (for example full-width Latin letters)
     * and case folding closes simple case variants. This key must never be used for hashing or
     * authentication because doing so would silently change the user's actual password.</p>
     */
    static String blocklistKey(String value) {
        return Normalizer.normalize(value, Normalizer.Form.NFKC)
                .toLowerCase(Locale.ROOT);
    }

    static String contextKey(String value) {
        return Normalizer.normalize(value, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }

    static int codePointLength(String value) {
        return value.codePointCount(0, value.length());
    }
}
