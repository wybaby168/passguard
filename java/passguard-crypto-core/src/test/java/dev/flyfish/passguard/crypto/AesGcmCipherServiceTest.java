package dev.flyfish.passguard.crypto;

import dev.flyfish.passguard.crypto.annotation.BlindIndex;
import dev.flyfish.passguard.crypto.annotation.Encrypted;
import dev.flyfish.passguard.crypto.key.InMemoryKeyProvider;
import dev.flyfish.passguard.crypto.key.KeyManager;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

class AesGcmCipherServiceTest {
    @Test
    void encryptsAuthenticatesAndRotatesKeys() {
        InMemoryKeyProvider keys = new InMemoryKeyProvider();
        KeyManager manager = new KeyManager(keys);
        manager.generateAndActivate("data", "v1");
        AesGcmCipherService cipher = new AesGcmCipherService(keys);

        String first = cipher.encrypt("秘密🔐", "data", "users.password");
        String second = cipher.encrypt("秘密🔐", "data", "users.password");
        assertTrue(first.startsWith("PG1.v1."));
        assertNotEquals(first, second);
        assertEquals("秘密🔐", cipher.decrypt(first, "data", "users.password"));
        assertThrows(CryptoException.class,
                () -> cipher.decrypt(first, "data", "other.field"));

        manager.generateAndActivate("data", "v2");
        assertTrue(cipher.encrypt("new", "data", "users.password").startsWith("PG1.v2."));
        ReEncryptionService rotation = new ReEncryptionService(cipher, keys);
        assertTrue(rotation.needsReEncryption(first, "data"));
        String rotated = rotation.reEncrypt(first, "data", "users.password");
        assertTrue(rotated.startsWith("PG1.v2."));
        assertFalse(rotation.needsReEncryption(rotated, "data"));
        assertSame(rotated, rotation.reEncrypt(rotated, "data", "users.password"));

        Credential credential = new Credential(first);
        MigrationReport dryRun = rotation.migrate(
                Arrays.asList(credential), Credential.ACCESSOR,
                "data", "users.password", true);
        assertEquals(1, dryRun.changed());
        assertSame(first, credential.value);

        manager.deactivate("data");
        assertEquals("秘密🔐", cipher.decrypt(first, "data", "users.password"));
        assertThrows(CryptoException.class,
                () -> cipher.encrypt("blocked", "data", "users.password"));

        assertEquals("秘密🔐", cipher.decrypt(first, "data", "users.password"));
    }

    @Test
    void annotatedProcessorEncryptsRestoresAndBuildsBlindIndex() {
        InMemoryKeyProvider keys = new InMemoryKeyProvider();
        KeyManager manager = new KeyManager(keys);
        manager.generateAndActivate("data", "data1");
        manager.generateAndActivate("index", "index1");
        AesGcmCipherService cipher = new AesGcmCipherService(keys);
        AnnotatedFieldProcessor processor = new AnnotatedFieldProcessor(
                cipher, new BlindIndexService(keys), "data", ReadPolicy.STRICT);
        Account account = new Account("api-secret");

        processor.encryptForWrite(account);
        assertTrue(account.password.startsWith("PG1.data1."));
        assertTrue(account.passwordIndex.startsWith("BI1.index1."));
        processor.restoreAfterWrite(account);
        assertEquals("api-secret", account.password);
    }

    @Test
    void failsClosedForTamperingUnknownKeysAndLegacyPlaintext() {
        InMemoryKeyProvider keys = new InMemoryKeyProvider();
        new KeyManager(keys).generateAndActivate("data", "v1");
        AesGcmCipherService cipher = new AesGcmCipherService(keys);
        String ciphertext = cipher.encrypt("must-stay-secret", "data", "account.password");
        int payloadStart = ciphertext.lastIndexOf('.') + 1;
        char original = ciphertext.charAt(payloadStart);
        String tampered = ciphertext.substring(0, payloadStart)
                + (original == 'A' ? 'B' : 'A')
                + ciphertext.substring(payloadStart + 1);

        assertThrows(CryptoException.class,
                () -> cipher.decrypt(tampered, "data", "account.password"));
        assertThrows(CryptoException.class,
                () -> cipher.decrypt(ciphertext.replace(".v1.", ".missing."),
                        "data", "account.password"));
        assertThrows(CryptoException.class,
                () -> cipher.decrypt(ciphertext, "other", "account.password"));

        AnnotatedFieldProcessor strict = new AnnotatedFieldProcessor(
                cipher, new BlindIndexService(keys), "data", ReadPolicy.STRICT);
        assertThrows(CryptoException.class,
                () -> strict.decryptAfterRead(new Account("legacy-plaintext")));
        AnnotatedFieldProcessor migration = new AnnotatedFieldProcessor(
                cipher, new BlindIndexService(keys), "data", ReadPolicy.MIGRATION);
        Account legacy = new Account("legacy-plaintext");
        migration.decryptAfterRead(legacy);
        assertEquals("legacy-plaintext", legacy.password);
    }

    @Test
    void preparedWriteRestoresExactValuesAndRedactsDiagnostics() {
        InMemoryKeyProvider keys = new InMemoryKeyProvider();
        KeyManager manager = new KeyManager(keys);
        manager.generateAndActivate("data", "v1");
        manager.generateAndActivate("index", "v1");
        AnnotatedFieldProcessor processor = new AnnotatedFieldProcessor(
                new AesGcmCipherService(keys), new BlindIndexService(keys),
                "data", ReadPolicy.STRICT);
        Account account = new Account("api-secret");
        account.passwordIndex = "caller-owned-value";

        AnnotatedFieldProcessor.PreparedWrite prepared =
                processor.prepareForWrite(account);
        assertTrue(account.password.startsWith("PG1.v1."));
        assertTrue(account.passwordIndex.startsWith("BI1.v1."));
        assertFalse(prepared.toString().contains("api-secret"));
        prepared.close();
        prepared.close();

        assertEquals("api-secret", account.password);
        assertEquals("caller-owned-value", account.passwordIndex);
    }

    @Test
    void encryptsAndDecryptsConcurrently() throws Exception {
        InMemoryKeyProvider keys = new InMemoryKeyProvider();
        new KeyManager(keys).generateAndActivate("data", "v1");
        final AesGcmCipherService cipher = new AesGcmCipherService(keys);
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Callable<String>> tasks = new ArrayList<Callable<String>>();
            for (int index = 0; index < 64; index++) {
                final String plaintext = "parallel-secret-" + index;
                tasks.add(new Callable<String>() {
                    @Override
                    public String call() {
                        String encrypted =
                                cipher.encrypt(plaintext, "data", "parallel.field");
                        return cipher.decrypt(encrypted, "data", "parallel.field");
                    }
                });
            }
            List<Future<String>> results = executor.invokeAll(tasks);
            for (int index = 0; index < results.size(); index++) {
                assertEquals("parallel-secret-" + index, results.get(index).get());
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private static final class Account {
        @Encrypted(context = "accounts.password")
        private String password;

        @BlindIndex(source = "password", context = "accounts.password_index")
        private String passwordIndex;

        private Account(String password) {
            this.password = password;
        }
    }

    private static final class Credential {
        private static final ReEncryptionService.CiphertextAccessor<Credential> ACCESSOR =
                new ReEncryptionService.CiphertextAccessor<Credential>() {
                    @Override
                    public String read(Credential record) {
                        return record.value;
                    }

                    @Override
                    public void write(Credential record, String ciphertext) {
                        record.value = ciphertext;
                    }
                };

        private String value;

        private Credential(String value) {
            this.value = value;
        }
    }
}
