package dev.flyfish.passguard.crypto.key;

import dev.flyfish.passguard.crypto.CryptoException;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Collections;
import java.util.Objects;

/**
 * 从 PKCS12 或 JCEKS 文件加载版本化密钥。
 *
 * <p>KeyStore alias 格式为 {@code logicalAlias.keyId}，active id 由非秘密配置提供。</p>
 */
public final class KeyStoreKeyProvider implements KeyProvider {
    private final KeyStore keyStore;
    private final char[] password;
    private final Map<String, String> activeIds;

    /**
     * @param location KeyStore 路径
     * @param type {@code PKCS12} 或 {@code JCEKS}
     * @param password KeyStore 密码；内部保存独立副本
     * @param activeIds 逻辑别名到 active key id 的映射
     */
    public KeyStoreKeyProvider(
            Path location, String type, char[] password, Map<String, String> activeIds) {
        Objects.requireNonNull(location, "location");
        Objects.requireNonNull(type, "type");
        if (!"PKCS12".equalsIgnoreCase(type) && !"JCEKS".equalsIgnoreCase(type)) {
            throw new IllegalArgumentException("key store type must be PKCS12 or JCEKS");
        }
        this.password = Objects.requireNonNull(password, "password").clone();
        this.activeIds = Collections.unmodifiableMap(
                new LinkedHashMap<String, String>(
                        Objects.requireNonNull(activeIds, "activeIds")));
        try {
            KeyStore loaded = KeyStore.getInstance(type);
            try (InputStream input = Files.newInputStream(location)) {
                loaded.load(input, this.password);
            }
            this.keyStore = loaded;
        } catch (GeneralSecurityException | IOException failure) {
            throw new CryptoException("unable to load key store", failure);
        }
    }

    @Override
    public KeyDescriptor activeKey(String alias) {
        String id = activeIds.get(alias);
        if (id == null) {
            throw new CryptoException("no active key id for key store alias " + alias);
        }
        return key(alias, id);
    }

    @Override
    public KeyDescriptor key(String alias, String keyId) {
        try {
            Key key = keyStore.getKey(alias + "." + keyId, password);
            if (!(key instanceof SecretKey)) {
                throw new CryptoException("key store entry is not a secret key");
            }
            return new KeyDescriptor(keyId, (SecretKey) key);
        } catch (GeneralSecurityException failure) {
            throw new CryptoException("unable to read key store entry", failure);
        }
    }
}
