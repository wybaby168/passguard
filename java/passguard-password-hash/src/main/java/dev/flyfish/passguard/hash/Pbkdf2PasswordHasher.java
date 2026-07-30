package dev.flyfish.passguard.hash;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * 适用于 FIPS 或旧环境的 PBKDF2-HMAC-SHA256 密码哈希。
 */
public final class Pbkdf2PasswordHasher implements PasswordHasher {
    /** OWASP 推荐的默认迭代次数。 */
    public static final int DEFAULT_ITERATIONS = 600_000;
    private static final int SALT_LENGTH = 16;
    private static final int HASH_BITS = 256;
    private static final int MAX_ITERATIONS = 10_000_000;

    private final int iterations;
    private final SecureRandom random;

    /** 使用 600,000 次迭代。 */
    public Pbkdf2PasswordHasher() {
        this(DEFAULT_ITERATIONS, new SecureRandom());
    }

    /** @param iterations 迭代次数，至少 100,000；@param random 盐值随机源 */
    public Pbkdf2PasswordHasher(int iterations, SecureRandom random) {
        if (iterations < 100_000 || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException(
                    "PBKDF2 iterations must be between 100000 and 10000000");
        }
        this.iterations = iterations;
        this.random = Objects.requireNonNull(random, "random");
    }

    @Override
    public String hash(char[] password) {
        Objects.requireNonNull(password, "password");
        byte[] salt = HashSupport.salt(random, SALT_LENGTH);
        byte[] result = derive(password, salt, iterations);
        try {
            return "$pbkdf2-sha256$i=" + iterations + "$"
                    + HashSupport.encode(salt) + "$" + HashSupport.encode(result);
        } finally {
            Arrays.fill(result, (byte) 0);
        }
    }

    @Override
    public boolean verify(char[] password, String encodedHash) {
        Objects.requireNonNull(password, "password");
        Parsed parsed;
        try {
            parsed = parse(encodedHash);
        } catch (RuntimeException invalid) {
            return false;
        }
        byte[] actual = null;
        try {
            actual = derive(password, parsed.salt, parsed.iterations);
            return HashSupport.equals(parsed.hash, actual);
        } finally {
            if (actual != null) Arrays.fill(actual, (byte) 0);
            parsed.clear();
        }
    }

    @Override
    public boolean needsRehash(String encodedHash) {
        try {
            Parsed parsed = parse(encodedHash);
            try {
                return parsed.iterations != iterations;
            } finally {
                parsed.clear();
            }
        } catch (RuntimeException invalid) {
            return true;
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2-HMAC-SHA256 is unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    private static Parsed parse(String encoded) {
        if (encoded == null) throw new IllegalArgumentException("hash is null");
        String[] parts = encoded.split("\\$", -1);
        if (parts.length != 5 || !"".equals(parts[0])
                || !"pbkdf2-sha256".equals(parts[1]) || !parts[2].startsWith("i=")) {
            throw new IllegalArgumentException("invalid PBKDF2 hash");
        }
        int iterations = Integer.parseInt(parts[2].substring(2));
        if (iterations < 1 || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("invalid iterations");
        }
        byte[] salt = HashSupport.decode(parts[3]);
        byte[] hash = HashSupport.decode(parts[4]);
        if (salt.length < 8 || hash.length != HASH_BITS / 8) {
            throw new IllegalArgumentException("invalid salt or hash length");
        }
        return new Parsed(iterations, salt, hash);
    }

    private static final class Parsed {
        private final int iterations;
        private final byte[] salt;
        private final byte[] hash;

        private Parsed(int iterations, byte[] salt, byte[] hash) {
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }

        private void clear() {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(hash, (byte) 0);
        }
    }
}
