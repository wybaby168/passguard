package io.github.wybaby168.passguard;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public final class LocalBlocklist {
    private final Set<String> entries;

    public LocalBlocklist(Collection<String> entries) {
        Objects.requireNonNull(entries, "entries");
        Set<String> normalized = new HashSet<>(Math.max(16, entries.size() * 2));
        for (String entry : entries) {
            if (entry != null && !entry.isEmpty()) {
                normalized.add(PasswordNormalizer.normalizePassword(entry));
            }
        }
        this.entries = Set.copyOf(normalized);
    }

    public static LocalBlocklist fromClasspath(String resource) throws IOException {
        InputStream stream = LocalBlocklist.class.getResourceAsStream(resource);
        if (stream == null) throw new IOException("Classpath resource not found: " + resource);
        try (stream) {
            return fromInputStream(stream);
        }
    }

    public static LocalBlocklist fromPath(Path path) throws IOException {
        try (InputStream stream = Files.newInputStream(path)) {
            return fromInputStream(stream);
        }
    }

    public static LocalBlocklist fromInputStream(InputStream input) throws IOException {
        Set<String> values = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // readLine removes line terminators only; it does not trim password spaces.
                if (!line.isEmpty()) values.add(PasswordNormalizer.normalizePassword(line));
            }
        }
        return new LocalBlocklist(values);
    }

    public boolean contains(String password) {
        return entries.contains(PasswordNormalizer.normalizePassword(password));
    }

    public int size() {
        return entries.size();
    }
}
