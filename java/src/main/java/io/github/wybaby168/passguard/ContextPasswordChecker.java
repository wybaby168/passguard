package io.github.wybaby168.passguard;

import java.time.Year;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public final class ContextPasswordChecker {
    private static final Pattern SPLIT = Pattern.compile("[^\\p{L}\\p{N}]+");
    private static final List<String> SUFFIXES = Collections.unmodifiableList(Arrays.asList(
            "", "1", "01", "12", "123", "1234", "12345", "123456",
            "!", "!1", "!123", "@123", "#123", "_123", "-123"
    ));

    private final Set<String> globalCandidates;

    public ContextPasswordChecker(Collection<String> globalWords) {
        Set<String> candidates = new HashSet<>();
        if (globalWords != null) {
            for (String value : globalWords) {
                if (isBlank(value)) continue;
                for (String token : extractTokens(value)) addVariants(candidates, token);
            }
        }
        // Product and organization words are shared by all users. Precompute
        // their variants once instead of rebuilding them on every request.
        this.globalCandidates = Collections.unmodifiableSet(
                new HashSet<String>(candidates));
    }

    public boolean isBlocked(String password, PasswordContext context) {
        String key = PasswordNormalizer.contextKey(password);
        if (key.isEmpty()) return false;
        if (globalCandidates.contains(key)) return true;
        PasswordContext safeContext = context == null ? PasswordContext.empty() : context;
        if (safeContext.username() == null
                && safeContext.email() == null
                && safeContext.displayName() == null
                && safeContext.serviceName() == null
                && safeContext.organizationWords().isEmpty()) {
            return false;
        }

        List<String> values = new ArrayList<>();
        addIfPresent(values, safeContext.username());
        addIfPresent(values, safeContext.email());
        addIfPresent(values, safeContext.displayName());
        addIfPresent(values, safeContext.serviceName());
        values.addAll(safeContext.organizationWords());

        Set<String> candidates = new HashSet<>();
        for (String value : values) {
            for (String token : extractTokens(value)) addVariants(candidates, token);
        }
        // Whole-value comparison only. No substring rejection.
        return candidates.contains(key);
    }

    private static void addIfPresent(List<String> target, String value) {
        if (!isBlank(value)) target.add(value);
    }

    static boolean isBlank(String value) {
        if (value == null || value.isEmpty()) return true;
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            if (!Character.isWhitespace(codePoint)) return false;
            offset += Character.charCount(codePoint);
        }
        return true;
    }

    private static Set<String> extractTokens(String raw) {
        String value = PasswordNormalizer.contextKey(raw);
        Set<String> tokens = new HashSet<>();
        if (value.length() >= 3) tokens.add(value);
        int at = value.indexOf('@');
        if (at >= 3) tokens.add(value.substring(0, at));
        for (String token : SPLIT.split(value)) {
            if (token.length() >= 3) tokens.add(token);
        }
        return tokens;
    }

    private static void addVariants(Set<String> target, String token) {
        for (String suffix : SUFFIXES) target.add(token + suffix);
        target.add(token + token);
        target.add("123" + token);
        int year = Year.now(ZoneOffset.UTC).getValue();
        for (int offset = -1; offset <= 2; offset++) {
            target.add(token + (year + offset));
            target.add(token + "@" + (year + offset));
        }
    }
}
