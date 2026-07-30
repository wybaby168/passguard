package dev.flyfish.passguard.spring;

import dev.flyfish.passguard.crypto.key.InMemoryKeyProvider;
import dev.flyfish.passguard.crypto.key.KeyDescriptor;
import dev.flyfish.passguard.crypto.key.KeyProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;

import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PassGuardJasyptIntegrationTest {
    private static final InMemoryKeyProvider KEYS = keys();

    @Test
    void resolvesEncPropertyFromPropertiesFile() {
        assertProfileResolves("properties-test");
    }

    @Test
    void resolvesEncPropertyFromYamlFile() {
        assertProfileResolves("yaml-test");
    }

    @Test
    void abortsStartupWhenConfigurationKeyIsMissing() {
        assertThrows(RuntimeException.class, () ->
                new SpringApplicationBuilder(MissingKeyApplication.class)
                        .web(WebApplicationType.NONE)
                        .profiles("properties-test")
                        .properties(
                                "spring.main.banner-mode=off",
                                "logging.level.root=OFF")
                        .run());
    }

    private static void assertProfileResolves(String profile) {
        try (ConfigurableApplicationContext context =
                     new SpringApplicationBuilder(TestApplication.class)
                             .web(WebApplicationType.NONE)
                             .profiles(profile)
                             .properties(
                                     "spring.main.banner-mode=off",
                                     "logging.level.root=OFF")
                             .run()) {
            assertEquals("database-secret",
                    context.getEnvironment().getProperty("demo.secret"));
            assertEquals("database-secret", context.getBean("requiredSecret"));
        }
    }

    private static InMemoryKeyProvider keys() {
        InMemoryKeyProvider provider = new InMemoryKeyProvider();
        byte[] material = Base64.getDecoder().decode(
                "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=");
        provider.putAndActivate("config",
                new KeyDescriptor("v1", new SecretKeySpec(material, "AES")));
        java.util.Arrays.fill(material, (byte) 0);
        return provider;
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApplication {
        @Bean
        KeyProvider keyProvider() {
            return KEYS;
        }

        @Bean
        String requiredSecret(@Value("${demo.secret}") String secret) {
            return secret;
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class MissingKeyApplication {
        @Bean
        String requiredSecret(@Value("${demo.secret}") String secret) {
            return secret;
        }
    }
}
