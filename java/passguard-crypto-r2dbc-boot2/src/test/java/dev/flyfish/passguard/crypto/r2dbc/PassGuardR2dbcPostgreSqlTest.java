package dev.flyfish.passguard.crypto.r2dbc;

import dev.flyfish.passguard.crypto.AesGcmCipherService;
import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import dev.flyfish.passguard.crypto.BlindIndexService;
import dev.flyfish.passguard.crypto.ReadPolicy;
import dev.flyfish.passguard.crypto.annotation.BlindIndex;
import dev.flyfish.passguard.crypto.annotation.Encrypted;
import dev.flyfish.passguard.crypto.key.InMemoryKeyProvider;
import dev.flyfish.passguard.crypto.key.KeyManager;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryOptions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.data.annotation.Id;
import org.springframework.data.mapping.callback.ReactiveEntityCallbacks;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.data.relational.core.query.Query;
import org.testcontainers.containers.PostgreSQLContainer;

import static io.r2dbc.spi.ConnectionFactoryOptions.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PassGuardR2dbcPostgreSqlTest {
    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine");
    private static boolean containerStarted;

    @BeforeAll
    static void startPostgres() {
        if (hasExternalPostgres()) {
            return;
        }
        try {
            POSTGRES.start();
            containerStarted = true;
        } catch (IllegalStateException unavailable) {
            assumeTrue(false, "Docker unavailable: " + unavailable.getMessage());
        }
    }

    @AfterAll
    static void stopPostgres() {
        if (containerStarted) {
            POSTGRES.stop();
        }
    }

    @Test
    void storesOnlyCiphertextAndReadsPlaintext() {
        InMemoryKeyProvider keys = new InMemoryKeyProvider();
        KeyManager manager = new KeyManager(keys);
        manager.generateAndActivate("data", "v1");
        manager.generateAndActivate("index", "v1");
        BlindIndexService blindIndexes = new BlindIndexService(keys);
        AnnotatedFieldProcessor processor = new AnnotatedFieldProcessor(
                new AesGcmCipherService(keys), blindIndexes, "data", ReadPolicy.STRICT);

        ConnectionFactoryOptions options = ConnectionFactoryOptions.builder()
                .option(DRIVER, "postgresql")
                .option(HOST, host())
                .option(PORT, port())
                .option(USER, username())
                .option(PASSWORD, password())
                .option(DATABASE, database())
                .build();
        ConnectionFactory connections = ConnectionFactories.get(options);
        R2dbcEntityTemplate template = new R2dbcEntityTemplate(connections);
        ReactiveEntityCallbacks callbacks = ReactiveEntityCallbacks.create();
        callbacks.addEntityCallback(new PassGuardR2dbcCallbacks(processor));
        template.setEntityCallbacks(callbacks);
        template.getDatabaseClient().sql("drop table if exists pg_r2dbc2")
                .fetch().rowsUpdated().block();
        template.getDatabaseClient().sql(
                "create table pg_r2dbc2("
                        + "id bigint primary key,password varchar(2048) not null,"
                        + "password_index varchar(128))")
                .fetch().rowsUpdated().block();

        Credential saved = new Credential(1L, "r2dbc2-secret");
        template.insert(saved).block();
        assertEquals("r2dbc2-secret", saved.password);
        assertNull(saved.passwordIndex);

        String raw = template.getDatabaseClient()
                .sql("select password from pg_r2dbc2 where id=1")
                .map((row, metadata) -> row.get("password", String.class))
                .one().block();
        assertNotNull(raw);
        assertTrue(raw.startsWith("PG1.v1."));

        Credential loaded = template.selectOne(
                Query.query(Criteria.where("id").is(1L)), Credential.class).block();
        assertNotNull(loaded);
        assertEquals("r2dbc2-secret", loaded.password);

        String index = blindIndexes.compute(
                "r2dbc2-secret", "index", "pg_r2dbc2.password_index");
        Credential matched = template.selectOne(
                Query.query(Criteria.where("password_index").is(index)),
                Credential.class).block();
        assertNotNull(matched);
        assertEquals(Long.valueOf(1L), matched.id);

        saved.password = "r2dbc2-rotated";
        template.update(saved).block();
        assertEquals("r2dbc2-rotated", saved.password);
        assertNull(saved.passwordIndex);
        String rotatedRaw = template.getDatabaseClient()
                .sql("select password from pg_r2dbc2 where id=1")
                .map((row, metadata) -> row.get("password", String.class))
                .one().block();
        assertNotNull(rotatedRaw);
        assertTrue(rotatedRaw.startsWith("PG1.v1."));
    }

    private static boolean hasExternalPostgres() {
        return System.getenv("PASSGUARD_TEST_PG_HOST") != null;
    }

    private static String host() {
        return hasExternalPostgres()
                ? System.getenv("PASSGUARD_TEST_PG_HOST") : POSTGRES.getHost();
    }

    private static int port() {
        return hasExternalPostgres()
                ? Integer.parseInt(System.getenv("PASSGUARD_TEST_PG_PORT"))
                : POSTGRES.getFirstMappedPort();
    }

    private static String database() {
        return hasExternalPostgres()
                ? System.getenv("PASSGUARD_TEST_PG_DATABASE") : POSTGRES.getDatabaseName();
    }

    private static String username() {
        return hasExternalPostgres()
                ? System.getenv("PASSGUARD_TEST_PG_USER") : POSTGRES.getUsername();
    }

    private static String password() {
        return hasExternalPostgres()
                ? System.getenv("PASSGUARD_TEST_PG_PASSWORD") : POSTGRES.getPassword();
    }

    @Table("pg_r2dbc2")
    public static class Credential {
        @Id
        private Long id;

        @Encrypted(keyAlias = "data", context = "pg_r2dbc2.password")
        private String password;

        @BlindIndex(
                source = "password",
                keyAlias = "index",
                context = "pg_r2dbc2.password_index")
        @Column("password_index")
        private String passwordIndex;

        public Credential() {}

        Credential(Long id, String password) {
            this.id = id;
            this.password = password;
        }
    }
}
