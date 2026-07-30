package dev.flyfish.passguard.crypto.jpa;

import dev.flyfish.passguard.crypto.AesGcmCipherService;
import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import dev.flyfish.passguard.crypto.BlindIndexService;
import dev.flyfish.passguard.crypto.ReadPolicy;
import dev.flyfish.passguard.crypto.annotation.BlindIndex;
import dev.flyfish.passguard.crypto.annotation.Encrypted;
import dev.flyfish.passguard.crypto.key.InMemoryKeyProvider;
import dev.flyfish.passguard.crypto.key.KeyManager;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.registry.BootstrapServiceRegistry;
import org.hibernate.boot.registry.BootstrapServiceRegistryBuilder;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.AvailableSettings;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PassGuardHibernate6PostgreSqlTest {
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
    void storesOnlyCiphertextAndReadsPlaintext() throws Exception {
        InMemoryKeyProvider keys = new InMemoryKeyProvider();
        KeyManager manager = new KeyManager(keys);
        manager.generateAndActivate("data", "v1");
        manager.generateAndActivate("index", "v1");
        BlindIndexService blindIndexes = new BlindIndexService(keys);
        AnnotatedFieldProcessor processor = new AnnotatedFieldProcessor(
                new AesGcmCipherService(keys), blindIndexes, "data", ReadPolicy.STRICT);

        BootstrapServiceRegistry bootstrap = new BootstrapServiceRegistryBuilder()
                .applyIntegrator(new PassGuardHibernate6Integrator(processor))
                .build();
        StandardServiceRegistry registry = new StandardServiceRegistryBuilder(bootstrap)
                .applySetting(AvailableSettings.URL, jdbcUrl())
                .applySetting(AvailableSettings.USER, username())
                .applySetting(AvailableSettings.PASS, password())
                .applySetting(AvailableSettings.DRIVER, "org.postgresql.Driver")
                .applySetting(AvailableSettings.DIALECT,
                        "org.hibernate.dialect.PostgreSQLDialect")
                .applySetting(AvailableSettings.HBM2DDL_AUTO, "create-drop")
                .build();
        try (SessionFactory sessions = new MetadataSources(registry)
                .addAnnotatedClass(Credential.class)
                .buildMetadata()
                .getSessionFactoryBuilder()
                .build()) {
            Credential saved = new Credential(1L, "hibernate6-secret");
            try (Session session = sessions.openSession()) {
                session.beginTransaction();
                session.persist(saved);
                session.getTransaction().commit();
            }
            assertEquals("hibernate6-secret", saved.password);
            assertNull(saved.passwordIndex);

            try (Connection connection = DriverManager.getConnection(
                    jdbcUrl(), username(), password());
                 Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery(
                         "select password,password_index from pg_credential6 where id=1")) {
                assertTrue(result.next());
                assertTrue(result.getString(1).startsWith("PG1.v1."));
                assertTrue(result.getString(2).startsWith("BI1.v1."));
            }

            try (Session session = sessions.openSession()) {
                Credential loaded = session.find(Credential.class, 1L);
                assertEquals("hibernate6-secret", loaded.password);
                String index = blindIndexes.compute(
                        "hibernate6-secret", "index", "pg_credential6.password_index");
                Credential matched = session.createQuery(
                                "from Credential where passwordIndex=:index", Credential.class)
                        .setParameter("index", index)
                        .getSingleResult();
                assertEquals(1L, matched.id);
            }

            Credential updated;
            try (Session session = sessions.openSession()) {
                session.beginTransaction();
                updated = session.find(Credential.class, 1L);
                updated.password = "hibernate6-rotated";
                session.getTransaction().commit();
            }
            assertEquals("hibernate6-rotated", updated.password);
            try (Connection connection = DriverManager.getConnection(
                    jdbcUrl(), username(), password());
                 Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery(
                         "select password,password_index from pg_credential6 where id=1")) {
                assertTrue(result.next());
                assertTrue(result.getString(1).startsWith("PG1.v1."));
                assertEquals(blindIndexes.compute(
                                "hibernate6-rotated", "index",
                                "pg_credential6.password_index"),
                        result.getString(2));
            }
        } finally {
            StandardServiceRegistryBuilder.destroy(registry);
        }
    }

    private static boolean hasExternalPostgres() {
        return System.getenv("PASSGUARD_TEST_PG_HOST") != null;
    }

    private static String jdbcUrl() {
        if (hasExternalPostgres()) {
            return "jdbc:postgresql://" + System.getenv("PASSGUARD_TEST_PG_HOST")
                    + ":" + System.getenv("PASSGUARD_TEST_PG_PORT")
                    + "/" + System.getenv("PASSGUARD_TEST_PG_DATABASE");
        }
        return POSTGRES.getJdbcUrl();
    }

    private static String username() {
        return hasExternalPostgres()
                ? System.getenv("PASSGUARD_TEST_PG_USER") : POSTGRES.getUsername();
    }

    private static String password() {
        return hasExternalPostgres()
                ? System.getenv("PASSGUARD_TEST_PG_PASSWORD") : POSTGRES.getPassword();
    }

    @Entity(name = "Credential")
    @Table(name = "pg_credential6")
    public static class Credential {
        @Id
        private Long id;

        @Encrypted(keyAlias = "data", context = "pg_credential6.password")
        @Column(length = 2048, nullable = false)
        private String password;

        @BlindIndex(
                source = "password",
                keyAlias = "index",
                context = "pg_credential6.password_index")
        @Column(name = "password_index", length = 128)
        private String passwordIndex;

        protected Credential() {}

        Credential(Long id, String password) {
            this.id = id;
            this.password = password;
        }
    }
}
