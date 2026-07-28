package io.github.wybaby168.passguard;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class PasswordContext {
    private final String username;
    private final String email;
    private final String displayName;
    private final String serviceName;
    private final List<String> organizationWords;

    public PasswordContext(
            String username,
            String email,
            String displayName,
            String serviceName,
            List<String> organizationWords
    ) {
        this.username = username;
        this.email = email;
        this.displayName = displayName;
        this.serviceName = serviceName;
        if (organizationWords == null) {
            this.organizationWords = Collections.emptyList();
        } else {
            ArrayList<String> copy = new ArrayList<String>(organizationWords.size());
            for (String word : organizationWords) {
                copy.add(Objects.requireNonNull(
                        word, "organizationWords contains null"));
            }
            this.organizationWords = Collections.unmodifiableList(copy);
        }
    }

    public String username() {
        return username;
    }

    public String email() {
        return email;
    }

    public String displayName() {
        return displayName;
    }

    public String serviceName() {
        return serviceName;
    }

    public List<String> organizationWords() {
        return organizationWords;
    }

    public static PasswordContext empty() {
        return new PasswordContext(null, null, null, null,
                Collections.<String>emptyList());
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof PasswordContext)) return false;
        PasswordContext that = (PasswordContext) other;
        return Objects.equals(username, that.username)
                && Objects.equals(email, that.email)
                && Objects.equals(displayName, that.displayName)
                && Objects.equals(serviceName, that.serviceName)
                && organizationWords.equals(that.organizationWords);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, email, displayName, serviceName, organizationWords);
    }

    @Override
    public String toString() {
        return "PasswordContext[username=" + username
                + ", email=" + email
                + ", displayName=" + displayName
                + ", serviceName=" + serviceName
                + ", organizationWords=" + organizationWords + "]";
    }
}
