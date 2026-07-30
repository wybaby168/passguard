package dev.flyfish.passguard.hash;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Argon2id 密码哈希，默认采用 OWASP 最低推荐参数。
 */
public final class Argon2idPasswordHasher implements PasswordHasher {
    /** 默认内存成本，单位 KiB（19 MiB）。 */
    public static final int DEFAULT_MEMORY_KIB = 19_456;
    /** 默认迭代次数。 */
    public static final int DEFAULT_ITERATIONS = 2;
    /** 默认并行度。 */
    public static final int DEFAULT_PARALLELISM = 1;

    private static final int VERSION = Argon2Parameters.ARGON2_VERSION_13;
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;
    private static final int MAX_MEMORY_KIB = 262_144;
    private static final int MAX_ITERATIONS = 20;
    private static final int MAX_PARALLELISM = 16;

    private final int memoryKiB;
    private final int iterations;
    private final int parallelism;
    private final SecureRandom random;

    /** 使用 OWASP 推荐的默认参数。 */
    public Argon2idPasswordHasher() {
        this(DEFAULT_MEMORY_KIB, DEFAULT_ITERATIONS, DEFAULT_PARALLELISM, new SecureRandom());
    }

    /**
     * @param memoryKiB 内存成本，至少 8 KiB
     * @param iterations 迭代次数，至少 1
     * @param parallelism 并行度，至少 1
     * @param random 盐值随机源
     */
    public Argon2idPasswordHasher(
            int memoryKiB, int iterations, int parallelism, SecureRandom random) {
        if (memoryKiB < 8 || memoryKiB > MAX_MEMORY_KIB
                || iterations < 1 || iterations > MAX_ITERATIONS
                || parallelism < 1 || parallelism > MAX_PARALLELISM) {
            throw new IllegalArgumentException("invalid Argon2id parameters");
        }
        this.memoryKiB = memoryKiB;
        this.iterations = iterations;
        this.parallelism = parallelism;
        this.random = Objects.requireNonNull(random, "random");
    }

    @Override
    public String hash(char[] password) {
        Objects.requireNonNull(password, "password");
        byte[] salt = HashSupport.salt(random, SALT_LENGTH);
        byte[] result = derive(password, salt, memoryKiB, iterations, parallelism);
        try {
            return "$argon2id$v=19$m=" + memoryKiB + ",t=" + iterations
                    + ",p=" + parallelism + "$" + HashSupport.encode(salt)
                    + "$" + HashSupport.encode(result);
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
            actual = derive(password, parsed.salt, parsed.memoryKiB,
                    parsed.iterations, parsed.parallelism);
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
                return parsed.memoryKiB != memoryKiB
                        || parsed.iterations != iterations
                        || parsed.parallelism != parallelism;
            } finally {
                parsed.clear();
            }
        } catch (RuntimeException invalid) {
            return true;
        }
    }

    private static byte[] derive(
            char[] password, byte[] salt, int memory, int iterations, int parallelism) {
        byte[] encoded = HashSupport.utf8(password);
        byte[] output = new byte[HASH_LENGTH];
        try {
            Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(VERSION)
                    .withMemoryAsKB(memory)
                    .withIterations(iterations)
                    .withParallelism(parallelism)
                    .withSalt(salt)
                    .build();
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(parameters);
            generator.generateBytes(encoded, output);
            return output;
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static Parsed parse(String encoded) {
        if (encoded == null) throw new IllegalArgumentException("hash is null");
        String[] parts = encoded.split("\\$", -1);
        if (parts.length != 6 || !"".equals(parts[0])
                || !"argon2id".equals(parts[1]) || !"v=19".equals(parts[2])) {
            throw new IllegalArgumentException("invalid Argon2id hash");
        }
        String[] parameters = parts[3].split(",");
        if (parameters.length != 3) throw new IllegalArgumentException("invalid parameters");
        int memory = value(parameters[0], "m=");
        int iterations = value(parameters[1], "t=");
        int parallelism = value(parameters[2], "p=");
        if (memory < 8 || memory > MAX_MEMORY_KIB
                || iterations > MAX_ITERATIONS || parallelism > MAX_PARALLELISM) {
            throw new IllegalArgumentException("unsafe Argon2id parameters");
        }
        byte[] salt = HashSupport.decode(parts[4]);
        byte[] hash = HashSupport.decode(parts[5]);
        if (salt.length < 8 || hash.length != HASH_LENGTH) {
            throw new IllegalArgumentException("invalid salt or hash length");
        }
        return new Parsed(memory, iterations, parallelism, salt, hash);
    }

    private static int value(String value, String prefix) {
        if (!value.startsWith(prefix)) throw new IllegalArgumentException("invalid parameter");
        int parsed = Integer.parseInt(value.substring(prefix.length()));
        if (parsed < 1) throw new IllegalArgumentException("invalid parameter");
        return parsed;
    }

    private static final class Parsed {
        private final int memoryKiB;
        private final int iterations;
        private final int parallelism;
        private final byte[] salt;
        private final byte[] hash;

        private Parsed(int memoryKiB, int iterations, int parallelism,
                       byte[] salt, byte[] hash) {
            this.memoryKiB = memoryKiB;
            this.iterations = iterations;
            this.parallelism = parallelism;
            this.salt = salt;
            this.hash = hash;
        }

        private void clear() {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(hash, (byte) 0);
        }
    }
}
