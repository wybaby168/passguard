package dev.flyfish.passguard.crypto.key;

import dev.flyfish.passguard.crypto.CryptoException;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * 按顺序尝试多个密钥来源，便于平滑迁移或对接自定义 KMS。
 */
public final class CompositeKeyProvider implements KeyProvider {
    private final List<KeyProvider> providers;

    /** @param providers 至少一个密钥来源 */
    public CompositeKeyProvider(KeyProvider... providers) {
        Objects.requireNonNull(providers, "providers");
        if (providers.length == 0) throw new IllegalArgumentException("providers must not be empty");
        this.providers = Collections.unmodifiableList(Arrays.asList(providers.clone()));
    }

    @Override
    public KeyDescriptor activeKey(String alias) {
        return find(alias, null, true);
    }

    @Override
    public KeyDescriptor key(String alias, String keyId) {
        return find(alias, keyId, false);
    }

    private KeyDescriptor find(String alias, String keyId, boolean active) {
        CryptoException last = null;
        for (KeyProvider provider : providers) {
            try {
                return active ? provider.activeKey(alias) : provider.key(alias, keyId);
            } catch (CryptoException unavailable) {
                last = unavailable;
            }
        }
        throw new CryptoException("no configured key provider could resolve alias " + alias, last);
    }
}
