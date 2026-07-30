package dev.flyfish.passguard.generator;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class SecurePasswordGeneratorTest {
    @Test
    void satisfiesDefaultConstraintsAndProducesDifferentValues() {
        SecurePasswordGenerator generator = new SecurePasswordGenerator();
        String first = generator.generate();
        String second = generator.generate();

        assertEquals(20, first.length());
        assertTrue(first.chars().anyMatch(Character::isLowerCase));
        assertTrue(first.chars().anyMatch(Character::isUpperCase));
        assertTrue(first.chars().anyMatch(Character::isDigit));
        assertTrue(first.chars().anyMatch(c ->
                PasswordGenerationOptions.DEFAULT_SYMBOLS.indexOf(c) >= 0));
        assertNotEquals(first, second);
    }

    @Test
    void honorsCustomCountsAndAmbiguousFilter() {
        PasswordGenerationOptions options = PasswordGenerationOptions.builder()
                .length(32)
                .minimumLowercase(4)
                .minimumUppercase(4)
                .minimumDigits(4)
                .minimumSymbols(4)
                .excludeAmbiguous(true)
                .build();
        String password = new SecurePasswordGenerator(new SecureRandom()).generate(options);
        assertEquals(32, password.length());
        assertTrue(password.chars().noneMatch(c -> "0O1lI".indexOf(c) >= 0));
    }

    @Test
    void rejectsImpossibleConfiguration() {
        assertThrows(IllegalArgumentException.class, () ->
                PasswordGenerationOptions.builder().length(4).minimumSymbols(5).build());
    }

    @Test
    void treatsSupplementaryUnicodeCharactersAsSingleSymbols() {
        PasswordGenerationOptions options = PasswordGenerationOptions.builder()
                .length(8)
                .minimumLowercase(8)
                .minimumUppercase(0)
                .minimumDigits(0)
                .minimumSymbols(0)
                .lowercaseAlphabet("😀🔐")
                .build();

        String generated = new SecurePasswordGenerator(new Random(42)).generate(options);

        assertEquals(8, generated.codePointCount(0, generated.length()));
        assertTrue(generated.codePoints()
                .allMatch(value -> value == 0x1F600 || value == 0x1F510));
    }
}
