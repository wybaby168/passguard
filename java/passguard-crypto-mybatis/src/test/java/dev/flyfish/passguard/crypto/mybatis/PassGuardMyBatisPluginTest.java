package dev.flyfish.passguard.crypto.mybatis;

import dev.flyfish.passguard.crypto.AesGcmCipherService;
import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import dev.flyfish.passguard.crypto.BlindIndexService;
import dev.flyfish.passguard.crypto.ReadPolicy;
import dev.flyfish.passguard.crypto.annotation.BlindIndex;
import dev.flyfish.passguard.crypto.annotation.Encrypted;
import dev.flyfish.passguard.crypto.key.InMemoryKeyProvider;
import dev.flyfish.passguard.crypto.key.KeyManager;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
import org.apache.ibatis.datasource.unpooled.UnpooledDataSource;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PassGuardMyBatisPluginTest {
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
    void storesCiphertextRestoresParameterAndDecryptsResult() throws Exception {
        DataSource dataSource = new UnpooledDataSource(
                "org.postgresql.Driver", jdbcUrl(), username(), password());
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("drop table if exists account");
            statement.execute("create table account("
                    + "id bigint primary key, password varchar(512), password_index varchar(128))");
        }

        InMemoryKeyProvider keys = new InMemoryKeyProvider();
        KeyManager manager = new KeyManager(keys);
        manager.generateAndActivate("data", "v1");
        manager.generateAndActivate("index", "v1");
        BlindIndexService blindIndexes = new BlindIndexService(keys);
        AnnotatedFieldProcessor processor = new AnnotatedFieldProcessor(
                new AesGcmCipherService(keys), blindIndexes,
                "data", ReadPolicy.STRICT);

        Configuration configuration = new Configuration(new Environment(
                "test", new JdbcTransactionFactory(), dataSource));
        configuration.addMapper(AccountMapper.class);
        configuration.addInterceptor(new PassGuardMyBatisPlugin(processor));
        SqlSessionFactory sessions = new SqlSessionFactoryBuilder().build(configuration);

        Account account = new Account(1L, "third-party-secret");
        try (SqlSession session = sessions.openSession(true)) {
            session.getMapper(AccountMapper.class).insert(account);
            assertEquals("third-party-secret", account.password);
            assertNull(account.passwordIndex);
            Account loaded = session.getMapper(AccountMapper.class).find(1L);
            assertEquals("third-party-secret", loaded.password);
            Account matched = session.getMapper(AccountMapper.class).findByPasswordIndex(
                    blindIndexes.compute(
                            "third-party-secret", "index", "account.password_index"));
            assertEquals(1L, matched.id);

            account.password = "rotated-third-party-secret";
            session.getMapper(AccountMapper.class).update(account);
            assertEquals("rotated-third-party-secret", account.password);
            assertNull(account.passwordIndex);
            Account updated = session.getMapper(AccountMapper.class).find(1L);
            assertEquals("rotated-third-party-secret", updated.password);
        }
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "select password,password_index from account where id=1")) {
            assertTrue(result.next());
            assertTrue(result.getString(1).startsWith("PG1.v1."));
            assertTrue(result.getString(2).startsWith("BI1.v1."));
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

    interface AccountMapper {
        @Insert("insert into account(id,password,password_index) "
                + "values(#{id},#{password},#{passwordIndex})")
        void insert(Account account);

        @Update("update account set password=#{password},password_index=#{passwordIndex} "
                + "where id=#{id}")
        void update(Account account);

        @Select("select id,password,password_index as passwordIndex from account where id=#{id}")
        Account find(long id);

        @Select("select id,password,password_index as passwordIndex from account "
                + "where password_index=#{value}")
        Account findByPasswordIndex(String value);
    }

    public static final class Account {
        public long id;
        @Encrypted(context = "account.password")
        public String password;
        @BlindIndex(source = "password", context = "account.password_index")
        public String passwordIndex;

        public Account() {}
        Account(long id, String password) {
            this.id = id;
            this.password = password;
        }
    }
}
