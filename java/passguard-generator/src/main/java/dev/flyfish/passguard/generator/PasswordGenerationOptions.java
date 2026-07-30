package dev.flyfish.passguard.generator;

import java.util.Objects;

/**
 * 安全密码生成器的不可变配置。
 *
 * <p>每个字符类别的最小数量都会被严格满足。总长度必须不小于全部最小数量之和。</p>
 */
public final class PasswordGenerationOptions {
    /** 默认小写字母表。 */
    public static final String DEFAULT_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    /** 默认大写字母表。 */
    public static final String DEFAULT_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    /** 默认数字字母表。 */
    public static final String DEFAULT_DIGITS = "0123456789";
    /** 默认符号表，刻意排除空白、引号和反斜杠，便于安全地写入常见配置载体。 */
    public static final String DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?";

    private final int length;
    private final int minimumLowercase;
    private final int minimumUppercase;
    private final int minimumDigits;
    private final int minimumSymbols;
    private final String lowercaseAlphabet;
    private final String uppercaseAlphabet;
    private final String digitAlphabet;
    private final String symbolAlphabet;
    private final boolean excludeAmbiguous;

    private PasswordGenerationOptions(Builder builder) {
        this.length = builder.length;
        this.minimumLowercase = builder.minimumLowercase;
        this.minimumUppercase = builder.minimumUppercase;
        this.minimumDigits = builder.minimumDigits;
        this.minimumSymbols = builder.minimumSymbols;
        this.lowercaseAlphabet = requireAlphabet(builder.lowercaseAlphabet, "lowercaseAlphabet");
        this.uppercaseAlphabet = requireAlphabet(builder.uppercaseAlphabet, "uppercaseAlphabet");
        this.digitAlphabet = requireAlphabet(builder.digitAlphabet, "digitAlphabet");
        this.symbolAlphabet = requireAlphabet(builder.symbolAlphabet, "symbolAlphabet");
        this.excludeAmbiguous = builder.excludeAmbiguous;
        validate();
    }

    /** @return 推荐默认配置：长度 20，每类字符至少一个 */
    public static PasswordGenerationOptions secureDefaults() {
        return builder().build();
    }

    /** @return 新的配置构建器 */
    public static Builder builder() {
        return new Builder();
    }

    private static String requireAlphabet(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isEmpty()) {
            throw new IllegalArgumentException(name + " must not be empty");
        }
        return value;
    }

    private void validate() {
        if (length < 4) {
            throw new IllegalArgumentException("length must be at least 4");
        }
        if (minimumLowercase < 0 || minimumUppercase < 0
                || minimumDigits < 0 || minimumSymbols < 0) {
            throw new IllegalArgumentException("minimum character counts must not be negative");
        }
        long required = (long) minimumLowercase + minimumUppercase
                + minimumDigits + minimumSymbols;
        if (required > length) {
            throw new IllegalArgumentException("length is smaller than required character counts");
        }
        if (excludeAmbiguous) {
            if (filterAmbiguous(lowercaseAlphabet).isEmpty()
                    || filterAmbiguous(uppercaseAlphabet).isEmpty()
                    || filterAmbiguous(digitAlphabet).isEmpty()
                    || filterAmbiguous(symbolAlphabet).isEmpty()) {
                throw new IllegalArgumentException(
                        "excluding ambiguous characters leaves an alphabet empty");
            }
        }
    }

    static String filterAmbiguous(String alphabet) {
        StringBuilder result = new StringBuilder(alphabet.length());
        for (int offset = 0; offset < alphabet.length();) {
            int value = alphabet.codePointAt(offset);
            if ("0O1lI".indexOf(value) < 0) {
                result.appendCodePoint(value);
            }
            offset += Character.charCount(value);
        }
        return result.toString();
    }

    /** @return 生成长度 */
    public int length() { return length; }
    /** @return 最少小写字母数 */
    public int minimumLowercase() { return minimumLowercase; }
    /** @return 最少大写字母数 */
    public int minimumUppercase() { return minimumUppercase; }
    /** @return 最少数字数 */
    public int minimumDigits() { return minimumDigits; }
    /** @return 最少符号数 */
    public int minimumSymbols() { return minimumSymbols; }
    /** @return 小写字母表 */
    public String lowercaseAlphabet() { return lowercaseAlphabet; }
    /** @return 大写字母表 */
    public String uppercaseAlphabet() { return uppercaseAlphabet; }
    /** @return 数字字母表 */
    public String digitAlphabet() { return digitAlphabet; }
    /** @return 符号表 */
    public String symbolAlphabet() { return symbolAlphabet; }
    /** @return 是否排除 {@code 0O1lI} */
    public boolean excludeAmbiguous() { return excludeAmbiguous; }

    /** 构建 {@link PasswordGenerationOptions}。 */
    public static final class Builder {
        private int length = 20;
        private int minimumLowercase = 1;
        private int minimumUppercase = 1;
        private int minimumDigits = 1;
        private int minimumSymbols = 1;
        private String lowercaseAlphabet = DEFAULT_LOWERCASE;
        private String uppercaseAlphabet = DEFAULT_UPPERCASE;
        private String digitAlphabet = DEFAULT_DIGITS;
        private String symbolAlphabet = DEFAULT_SYMBOLS;
        private boolean excludeAmbiguous;

        private Builder() {}

        /** @param value 总长度，至少为 4 */
        public Builder length(int value) { this.length = value; return this; }
        /** @param value 最少小写字母数 */
        public Builder minimumLowercase(int value) { this.minimumLowercase = value; return this; }
        /** @param value 最少大写字母数 */
        public Builder minimumUppercase(int value) { this.minimumUppercase = value; return this; }
        /** @param value 最少数字数 */
        public Builder minimumDigits(int value) { this.minimumDigits = value; return this; }
        /** @param value 最少符号数 */
        public Builder minimumSymbols(int value) { this.minimumSymbols = value; return this; }
        /** @param value 非空小写字母表 */
        public Builder lowercaseAlphabet(String value) { this.lowercaseAlphabet = value; return this; }
        /** @param value 非空大写字母表 */
        public Builder uppercaseAlphabet(String value) { this.uppercaseAlphabet = value; return this; }
        /** @param value 非空数字字母表 */
        public Builder digitAlphabet(String value) { this.digitAlphabet = value; return this; }
        /** @param value 非空符号表 */
        public Builder symbolAlphabet(String value) { this.symbolAlphabet = value; return this; }
        /** @param value 是否排除视觉易混淆字符 {@code 0O1lI} */
        public Builder excludeAmbiguous(boolean value) { this.excludeAmbiguous = value; return this; }

        /** @return 已完成校验的不可变配置 */
        public PasswordGenerationOptions build() {
            return new PasswordGenerationOptions(this);
        }
    }
}
