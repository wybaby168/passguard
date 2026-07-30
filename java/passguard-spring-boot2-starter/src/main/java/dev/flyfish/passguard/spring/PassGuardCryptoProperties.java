package dev.flyfish.passguard.spring;

import dev.flyfish.passguard.crypto.ReadPolicy;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * PassGuard 密钥和数据库字段加密配置。
 *
 * <p>该对象只保存非秘密元数据。密钥材料和 KeyStore 密码只能来自环境变量或
 * 外部 JVM 系统属性。</p>
 */
@ConfigurationProperties("passguard.crypto")
public class PassGuardCryptoProperties {
    private String defaultKeyAlias = "data";
    private String configKeyAlias = "config";
    private ReadPolicy readPolicy = ReadPolicy.STRICT;
    private Provider provider = Provider.ENVIRONMENT;
    private String environmentPrefix = "PASSGUARD_KEY_";
    private final KeyStore keyStore = new KeyStore();

    /** @return 数据库字段默认密钥别名 */
    public String getDefaultKeyAlias() { return defaultKeyAlias; }
    /** @param value 数据库字段默认密钥别名 */
    public void setDefaultKeyAlias(String value) { this.defaultKeyAlias = value; }
    /** @return Spring 配置加密密钥别名 */
    public String getConfigKeyAlias() { return configKeyAlias; }
    /** @param value Spring 配置加密密钥别名 */
    public void setConfigKeyAlias(String value) { this.configKeyAlias = value; }
    /** @return 旧明文读取策略 */
    public ReadPolicy getReadPolicy() { return readPolicy; }
    /** @param value 旧明文读取策略 */
    public void setReadPolicy(ReadPolicy value) { this.readPolicy = value; }
    /** @return 内置密钥来源类型 */
    public Provider getProvider() { return provider; }
    /** @param value 内置密钥来源类型 */
    public void setProvider(Provider value) { this.provider = value; }
    /** @return 环境变量前缀 */
    public String getEnvironmentPrefix() { return environmentPrefix; }
    /** @param value 环境变量前缀 */
    public void setEnvironmentPrefix(String value) { this.environmentPrefix = value; }
    /** @return KeyStore 非秘密配置 */
    public KeyStore getKeyStore() { return keyStore; }

    /** 内置密钥来源。 */
    public enum Provider { ENVIRONMENT, KEYSTORE }

    /** PKCS12/JCEKS 配置。 */
    public static class KeyStore {
        private String location;
        private String type = "PKCS12";
        private String passwordEnvironment = "PASSGUARD_KEYSTORE_PASSWORD";
        private String passwordSystemProperty;
        private Map<String, String> activeIds = new LinkedHashMap<String, String>();

        /** @return KeyStore 文件路径 */
        public String getLocation() { return location; }
        /** @param value KeyStore 文件路径 */
        public void setLocation(String value) { this.location = value; }
        /** @return {@code PKCS12} 或 {@code JCEKS} */
        public String getType() { return type; }
        /** @param value {@code PKCS12} 或 {@code JCEKS} */
        public void setType(String value) { this.type = value; }
        /** @return 保存 KeyStore 密码的环境变量名 */
        public String getPasswordEnvironment() { return passwordEnvironment; }
        /** @param value 保存 KeyStore 密码的环境变量名 */
        public void setPasswordEnvironment(String value) { this.passwordEnvironment = value; }
        /** @return 可选的 KeyStore 密码系统属性名 */
        public String getPasswordSystemProperty() { return passwordSystemProperty; }
        /** @param value 可选的 KeyStore 密码系统属性名 */
        public void setPasswordSystemProperty(String value) { this.passwordSystemProperty = value; }
        /** @return 逻辑别名到 active key id 的映射 */
        public Map<String, String> getActiveIds() { return activeIds; }
        /** @param value 逻辑别名到 active key id 的映射 */
        public void setActiveIds(Map<String, String> value) { this.activeIds = value; }
    }
}
