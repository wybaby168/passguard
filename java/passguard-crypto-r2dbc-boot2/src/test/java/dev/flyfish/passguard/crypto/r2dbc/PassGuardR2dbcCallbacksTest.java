package dev.flyfish.passguard.crypto.r2dbc;

import dev.flyfish.passguard.crypto.AesGcmCipherService;
import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import dev.flyfish.passguard.crypto.BlindIndexService;
import dev.flyfish.passguard.crypto.ReadPolicy;
import dev.flyfish.passguard.crypto.annotation.Encrypted;
import dev.flyfish.passguard.crypto.key.InMemoryKeyProvider;
import dev.flyfish.passguard.crypto.key.KeyManager;
import org.junit.jupiter.api.Test;
import org.springframework.data.r2dbc.mapping.OutboundRow;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.sql.SqlIdentifier;
import org.springframework.r2dbc.core.Parameter;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.*;

class PassGuardR2dbcCallbacksTest {
    @Test
    void replacesOutboundRowAndDecryptsConvertedEntity() {
        InMemoryKeyProvider keys = new InMemoryKeyProvider();
        new KeyManager(keys).generateAndActivate("data", "v1");
        AnnotatedFieldProcessor processor = new AnnotatedFieldProcessor(
                new AesGcmCipherService(keys), new BlindIndexService(keys),
                "data", ReadPolicy.STRICT);
        PassGuardR2dbcCallbacks callbacks = new PassGuardR2dbcCallbacks(processor);
        Account entity = new Account("secret");
        OutboundRow row = new OutboundRow();
        SqlIdentifier column = SqlIdentifier.unquoted("credential");
        row.put(column, Parameter.from("secret"));

        Mono.from(callbacks.onBeforeSave(
                entity, row, SqlIdentifier.unquoted("account"))).block();
        String ciphertext = (String) row.get(column).getValue();
        assertTrue(ciphertext.startsWith("PG1.v1."));
        assertEquals("secret", entity.password);

        entity.password = ciphertext;
        Mono.from(callbacks.onAfterConvert(
                entity, SqlIdentifier.unquoted("account"))).block();
        assertEquals("secret", entity.password);
    }

    private static final class Account {
        @Column("credential")
        @Encrypted(context = "account.password")
        private String password;
        private Account(String password) { this.password = password; }
    }
}
