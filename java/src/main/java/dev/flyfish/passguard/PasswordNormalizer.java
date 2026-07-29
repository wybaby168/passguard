package dev.flyfish.passguard;

import java.text.Normalizer;
import java.util.Locale;

final class PasswordNormalizer {
    private PasswordNormalizer() {}

    static String normalizePassword(String value) {
        // Deliberately do not trim, lowercase, or remove whitespace.
        return Normalizer.normalize(value, Normalizer.Form.NFC);
    }

    static String contextKey(String value) {
        return Normalizer.normalize(value, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }

    static int codePointLength(String value) {
        return value.codePointCount(0, value.length());
    }
}
