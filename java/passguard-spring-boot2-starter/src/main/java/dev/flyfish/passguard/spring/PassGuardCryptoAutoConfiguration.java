package dev.flyfish.passguard.spring;

import dev.flyfish.passguard.crypto.AesGcmCipherService;
import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import dev.flyfish.passguard.crypto.BlindIndexService;
import dev.flyfish.passguard.crypto.CipherService;
import dev.flyfish.passguard.crypto.CryptoException;
import dev.flyfish.passguard.crypto.key.EnvironmentKeyProvider;
import dev.flyfish.passguard.crypto.key.KeyProvider;
import dev.flyfish.passguard.crypto.key.KeyStoreKeyProvider;
import org.jasypt.encryption.StringEncryptor;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Spring Boot 2 密钥、加密、注解字段和 Jasypt 自动配置。
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(PassGuardCryptoProperties.class)
@ConditionalOnProperty(prefix = "passguard.crypto", name = "enabled",
        havingValue = "true", matchIfMissing = true)
@AutoConfigureBefore(name =
        "com.ulisesbocchio.jasyptspringboot.configuration.EncryptablePropertyResolverConfiguration")
public class PassGuardCryptoAutoConfiguration {
    /** @return 根据非秘密配置创建的内置密钥来源 */
    @Bean
    @ConditionalOnMissingBean(KeyProvider.class)
    public KeyProvider passGuardKeyProvider(PassGuardCryptoProperties properties) {
        if (properties.getProvider() == PassGuardCryptoProperties.Provider.ENVIRONMENT) {
            return new EnvironmentKeyProvider(
                    System.getenv(), properties.getEnvironmentPrefix());
        }
        PassGuardCryptoProperties.KeyStore config = properties.getKeyStore();
        if (config.getLocation() == null || config.getLocation().trim().isEmpty()) {
            throw new CryptoException("key store location is missing");
        }
        String password = keyStorePassword(config);
        char[] passwordChars = password.toCharArray();
        try {
            return new KeyStoreKeyProvider(
                    Paths.get(config.getLocation()), config.getType(),
                    passwordChars, config.getActiveIds());
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    private static String keyStorePassword(PassGuardCryptoProperties.KeyStore config) {
        String systemProperty = config.getPasswordSystemProperty();
        String password;
        if (systemProperty != null && !systemProperty.trim().isEmpty()) {
            password = System.getProperty(systemProperty.trim());
        } else {
            String environment = config.getPasswordEnvironment();
            if (environment == null || environment.trim().isEmpty()) {
                throw new CryptoException("key store password source is not configured");
            }
            password = System.getenv(environment.trim());
        }
        if (password == null) {
            throw new CryptoException("configured key store password source is missing");
        }
        return password;
    }

    /** @return AES-256-GCM 服务 */
    @Bean
    @ConditionalOnMissingBean(CipherService.class)
    public CipherService passGuardCipherService(KeyProvider provider) {
        return new AesGcmCipherService(provider);
    }

    /** @return HMAC 盲索引服务 */
    @Bean
    @ConditionalOnMissingBean
    public BlindIndexService passGuardBlindIndexService(KeyProvider provider) {
        return new BlindIndexService(provider);
    }

    /** @return 框架适配器共享的字段处理器 */
    @Bean
    @ConditionalOnMissingBean
    public AnnotatedFieldProcessor passGuardAnnotatedFieldProcessor(
            CipherService cipherService,
            BlindIndexService blindIndexes,
            PassGuardCryptoProperties properties) {
        return new AnnotatedFieldProcessor(cipherService, blindIndexes,
                properties.getDefaultKeyAlias(), properties.getReadPolicy());
    }

    /** @return jasypt-spring-boot 要求名称的 StringEncryptor */
    @Bean(name = "jasyptStringEncryptor")
    @ConditionalOnMissingBean(name = "jasyptStringEncryptor")
    public StringEncryptor jasyptStringEncryptor(
            CipherService cipherService, PassGuardCryptoProperties properties) {
        return new PassGuardStringEncryptor(
                cipherService, properties.getConfigKeyAlias());
    }
}
