package dev.flyfish.passguard.hash;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordHasherTest {
    @Test
    void argon2idHashesVerifiesAndUsesIndependentSalts() {
        PasswordHasher hasher = new Argon2idPasswordHasher();
        char[] password = "正确的密码🔐".toCharArray();
        String first = hasher.hash(password);
        String second = hasher.hash(password);
        assertTrue(first.startsWith("$argon2id$v=19$m=19456,t=2,p=1$"));
        assertNotEquals(first, second);
        assertTrue(hasher.verify(password, first));
        assertFalse(hasher.verify("wrong".toCharArray(), first));
        assertFalse(hasher.needsRehash(first));
    }

    @Test
    void pbkdf2HashesAndRejectsMalformedValues() {
        PasswordHasher hasher = new Pbkdf2PasswordHasher(100_000, new java.security.SecureRandom());
        String encoded = hasher.hash("password".toCharArray());
        assertTrue(hasher.verify("password".toCharArray(), encoded));
        assertFalse(hasher.verify("password".toCharArray(), "invalid"));
        assertTrue(hasher.needsRehash("invalid"));
    }

    @Test
    void rejectsResourceExhaustingEncodedParameters() {
        PasswordHasher argon = new Argon2idPasswordHasher(
                32, 1, 1, new java.security.SecureRandom());
        assertFalse(argon.verify("secret".toCharArray(),
                "$argon2id$v=19$m=999999999,t=2,p=1$YWJjZGVmZ2g$"
                        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assertTrue(argon.needsRehash("$md5$unsupported"));

        PasswordHasher pbkdf2 = new Pbkdf2PasswordHasher(
                100_000, new java.security.SecureRandom());
        assertFalse(pbkdf2.verify("secret".toCharArray(),
                "$pbkdf2-sha256$i=999999999$YWJjZGVmZ2g$"
                        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }
}
