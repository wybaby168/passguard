package dev.flyfish.passguard.hash;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

final class HashSupport {
    private HashSupport() {}

    static byte[] salt(SecureRandom random, int length) {
        byte[] result = new byte[length];
        random.nextBytes(result);
        return result;
    }

    static String encode(byte[] value) {
        return Base64.getEncoder().withoutPadding().encodeToString(value);
    }

    static byte[] decode(String value) {
        return Base64.getDecoder().decode(value);
    }

    static boolean equals(byte[] expected, byte[] actual) {
        return MessageDigest.isEqual(expected, actual);
    }

    static byte[] utf8(char[] value) {
        ByteBuffer buffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(value));
        byte[] encoded = new byte[buffer.remaining()];
        buffer.get(encoded);
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), (byte) 0);
        }
        return encoded;
    }
}
