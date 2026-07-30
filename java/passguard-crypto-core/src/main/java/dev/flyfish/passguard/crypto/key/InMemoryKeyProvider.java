package dev.flyfish.passguard.crypto.key;

import dev.flyfish.passguard.crypto.CryptoException;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 线程安全的内存密钥环，适用于测试、临时工具或作为外部密钥系统适配器的缓存。
 */
public final class InMemoryKeyProvider implements MutableKeyProvider {
    private final Map<String, Map<String, KeyDescriptor>> keys =
            new ConcurrentHashMap<String, Map<String, KeyDescriptor>>();
    private final Map<String, String> activeIds = new ConcurrentHashMap<String, String>();

    @Override
    public KeyDescriptor activeKey(String alias) {
        String normalized = normalize(alias);
        String id = activeIds.get(normalized);
        if (id == null) {
            throw new CryptoException("no active key for alias " + normalized);
        }
        return key(normalized, id);
    }

    @Override
    public KeyDescriptor key(String alias, String keyId) {
        String normalized = normalize(alias);
        Map<String, KeyDescriptor> versions = keys.get(normalized);
        KeyDescriptor descriptor = versions == null ? null : versions.get(normalizeId(keyId));
        if (descriptor == null) {
            throw new CryptoException("unknown key id for alias " + normalized);
        }
        return descriptor;
    }

    @Override
    public void putAndActivate(String alias, KeyDescriptor descriptor) {
        String normalized = normalize(alias);
        Map<String, KeyDescriptor> versions = keys.get(normalized);
        if (versions == null) {
            Map<String, KeyDescriptor> created =
                    new ConcurrentHashMap<String, KeyDescriptor>();
            Map<String, KeyDescriptor> existing = keys.putIfAbsent(normalized, created);
            versions = existing == null ? created : existing;
        }
        versions.put(descriptor.id(), descriptor);
        activeIds.put(normalized, descriptor.id());
    }

    @Override
    public void activate(String alias, String keyId) {
        String normalizedId = normalizeId(keyId);
        key(alias, normalizedId);
        activeIds.put(normalize(alias), normalizedId);
    }

    @Override
    public void deactivate(String alias) {
        activeIds.remove(normalize(alias));
    }

    private static String normalize(String alias) {
        if (alias == null || alias.trim().isEmpty()) {
            throw new IllegalArgumentException("key alias must not be blank");
        }
        return alias.trim();
    }

    private static String normalizeId(String keyId) {
        if (keyId == null || !keyId.matches("[A-Za-z0-9_-]{1,64}")) {
            throw new IllegalArgumentException("invalid key id");
        }
        return keyId;
    }
}
