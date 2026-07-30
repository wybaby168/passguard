package dev.flyfish.passguard.generator;

import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

/**
 * 使用密码学安全随机源生成无偏密码。
 *
 * <p>实例无可变请求状态，可作为单例复用。默认构造器使用 {@link SecureRandom}；
 * 公共注入点同样只接受 {@code SecureRandom}，避免生产代码误用可预测随机源。</p>
 */
public final class SecurePasswordGenerator {
    private final Random random;

    /** 使用新的 {@link SecureRandom}。 */
    public SecurePasswordGenerator() {
        this(new SecureRandom());
    }

    /**
     * @param random 密码学安全随机源
     */
    public SecurePasswordGenerator(SecureRandom random) {
        this((Random) random);
    }

    /**
     * 仅供同包测试注入确定性随机源；不得作为公共 API 暴露。
     */
    SecurePasswordGenerator(Random random) {
        this.random = Objects.requireNonNull(random, "random");
    }

    /** @return 使用推荐默认值生成的密码 */
    public String generate() {
        return generate(PasswordGenerationOptions.secureDefaults());
    }

    /**
     * 生成满足全部最小字符类别约束的密码。
     *
     * @param options 已校验的生成配置
     * @return 新密码
     */
    public String generate(PasswordGenerationOptions options) {
        Objects.requireNonNull(options, "options");
        int[] lowercase = alphabet(options.lowercaseAlphabet(), options.excludeAmbiguous());
        int[] uppercase = alphabet(options.uppercaseAlphabet(), options.excludeAmbiguous());
        int[] digits = alphabet(options.digitAlphabet(), options.excludeAmbiguous());
        int[] symbols = alphabet(options.symbolAlphabet(), options.excludeAmbiguous());
        int[] all = concatenate(lowercase, uppercase, digits, symbols);

        int[] output = new int[options.length()];
        int cursor = 0;
        cursor = append(output, cursor, lowercase, options.minimumLowercase());
        cursor = append(output, cursor, uppercase, options.minimumUppercase());
        cursor = append(output, cursor, digits, options.minimumDigits());
        cursor = append(output, cursor, symbols, options.minimumSymbols());
        while (cursor < output.length) {
            output[cursor++] = choose(all);
        }

        // Fisher-Yates；Random#nextInt(bound) 本身采用拒绝采样，不产生取模偏差。
        for (int i = output.length - 1; i > 0; i--) {
            int replacement = random.nextInt(i + 1);
            int value = output[i];
            output[i] = output[replacement];
            output[replacement] = value;
        }
        StringBuilder password = new StringBuilder(output.length);
        for (int codePoint : output) password.appendCodePoint(codePoint);
        return password.toString();
    }

    private int append(int[] target, int cursor, int[] alphabet, int count) {
        for (int i = 0; i < count; i++) {
            target[cursor++] = choose(alphabet);
        }
        return cursor;
    }

    private int choose(int[] alphabet) {
        return alphabet[random.nextInt(alphabet.length)];
    }

    private static int[] alphabet(String value, boolean excludeAmbiguous) {
        String filtered = excludeAmbiguous
                ? PasswordGenerationOptions.filterAmbiguous(value) : value;
        return filtered.codePoints().toArray();
    }

    private static int[] concatenate(int[]... values) {
        int length = 0;
        for (int[] value : values) {
            length += value.length;
        }
        int[] result = new int[length];
        int offset = 0;
        for (int[] value : values) {
            System.arraycopy(value, 0, result, offset, value.length);
            offset += value.length;
        }
        return result;
    }
}
