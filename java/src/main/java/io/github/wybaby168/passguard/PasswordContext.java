package io.github.wybaby168.passguard;

import java.util.List;

public record PasswordContext(
        String username,
        String email,
        String displayName,
        String serviceName,
        List<String> organizationWords
) {
    public PasswordContext {
        organizationWords = organizationWords == null ? List.of() : List.copyOf(organizationWords);
    }

    public static PasswordContext empty() {
        return new PasswordContext(null, null, null, null, List.of());
    }
}
