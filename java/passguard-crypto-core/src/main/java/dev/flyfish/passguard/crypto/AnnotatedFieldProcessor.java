package dev.flyfish.passguard.crypto;

import dev.flyfish.passguard.crypto.annotation.BlindIndex;
import dev.flyfish.passguard.crypto.annotation.Encrypted;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 为持久化框架适配器提供缓存后的注解字段转换。
 *
 * <p>框架适配器可以在写入前调用 {@link #encryptForWrite(Object)}，并必须在
 * {@code finally} 中调用 {@link #restoreAfterWrite(Object)}。读取后调用
 * {@link #decryptAfterRead(Object)}。</p>
 */
public final class AnnotatedFieldProcessor {
    private final CipherService cipherService;
    private final BlindIndexService blindIndexes;
    private final String defaultKeyAlias;
    private final ReadPolicy readPolicy;
    private final Map<Class<?>, Metadata> cache = new ConcurrentHashMap<Class<?>, Metadata>();

    /**
     * @param cipherService 文本加解密
     * @param blindIndexes 盲索引服务
     * @param defaultKeyAlias 注解未指定时使用的别名
     * @param readPolicy 旧明文读取策略
     */
    public AnnotatedFieldProcessor(
            CipherService cipherService,
            BlindIndexService blindIndexes,
            String defaultKeyAlias,
            ReadPolicy readPolicy) {
        this.cipherService = java.util.Objects.requireNonNull(cipherService, "cipherService");
        this.blindIndexes = java.util.Objects.requireNonNull(blindIndexes, "blindIndexes");
        if (defaultKeyAlias == null || defaultKeyAlias.trim().isEmpty()) {
            throw new IllegalArgumentException("defaultKeyAlias must not be blank");
        }
        this.defaultKeyAlias = defaultKeyAlias.trim();
        this.readPolicy = java.util.Objects.requireNonNull(readPolicy, "readPolicy");
    }

    /** @return 该类型是否包含 PassGuard 持久化注解 */
    public boolean supports(Class<?> type) {
        return !metadata(type).encrypted.isEmpty() || !metadata(type).blindIndexes.isEmpty();
    }

    /**
     * 原地生成盲索引并加密字段。适配器必须确保调用结束后恢复对象。
     *
     * @param entity 待写入对象
     */
    public void encryptForWrite(Object entity) {
        if (entity == null) return;
        Metadata metadata = metadata(entity.getClass());
        applyEncryption(entity, metadata);
    }

    /**
     * 加密实体并返回可精确恢复所有受管理字段的写入快照。
     *
     * <p>框架适配器应优先使用此入口，并在 {@code finally} 或
     * try-with-resources 中关闭快照。与重新解密相比，快照还能恢复原盲索引值。</p>
     *
     * @param entity 待写入对象
     * @return 可幂等关闭的恢复句柄
     */
    public PreparedWrite prepareForWrite(Object entity) {
        Objects.requireNonNull(entity, "entity");
        Metadata metadata = metadata(entity.getClass());
        PreparedWrite prepared = snapshot(entity, metadata);
        try {
            applyEncryption(entity, metadata);
            return prepared;
        } catch (RuntimeException failure) {
            prepared.close();
            throw failure;
        }
    }

    /**
     * 直接改写 ORM 已生成的 JDBC state，不改变实体中的明文。
     *
     * <p>该入口专供 Hibernate 事件适配器使用，属性名必须与 state 下标一一对应。</p>
     *
     * @param entity 实体对象
     * @param propertyNames Hibernate 属性名
     * @param state 待写入 JDBC 的属性值
     */
    public void encryptStateForWrite(
            Object entity, String[] propertyNames, Object[] state) {
        if (entity == null) return;
        if (propertyNames == null || state == null
                || propertyNames.length != state.length) {
            throw new IllegalArgumentException("property names and state must have equal length");
        }
        Metadata metadata = metadata(entity.getClass());
        try {
            for (BlindField blind : metadata.blindIndexes) {
                int index = indexOf(propertyNames, blind.target.getName());
                if (index >= 0) {
                    String source = (String) blind.source.get(entity);
                    state[index] = source == null ? null
                            : blindIndexes.compute(source, blind.keyAlias, blind.context);
                }
            }
            for (EncryptedField encrypted : metadata.encrypted) {
                int index = indexOf(propertyNames, encrypted.field.getName());
                if (index >= 0) {
                    String plaintext = (String) encrypted.field.get(entity);
                    state[index] = plaintext == null ? null : cipherService.encrypt(
                            plaintext, encrypted.keyAlias, encrypted.context);
                }
            }
        } catch (IllegalAccessException failure) {
            throw new CryptoException("unable to access encrypted entity field", failure);
        }
    }

    /**
     * 计算字段名到密文/盲索引值的不可变写入快照，不修改实体。
     *
     * @param entity 待写入对象
     * @return 只包含受 PassGuard 管理字段的快照
     */
    public Map<String, String> encryptedState(Object entity) {
        if (entity == null) return Collections.emptyMap();
        Metadata metadata = metadata(entity.getClass());
        Map<String, String> state = new LinkedHashMap<String, String>();
        try {
            for (BlindField blind : metadata.blindIndexes) {
                String source = (String) blind.source.get(entity);
                state.put(blind.target.getName(), source == null ? null
                        : blindIndexes.compute(source, blind.keyAlias, blind.context));
            }
            for (EncryptedField encrypted : metadata.encrypted) {
                String plaintext = (String) encrypted.field.get(entity);
                state.put(encrypted.field.getName(), plaintext == null ? null
                        : cipherService.encrypt(plaintext,
                        encrypted.keyAlias, encrypted.context));
            }
        } catch (IllegalAccessException failure) {
            throw new CryptoException("unable to access encrypted entity field", failure);
        }
        return Collections.unmodifiableMap(state);
    }

    /**
     * 在 ORM 实例化实体之前解密读取 state，使实体值与脏检查快照同时保持明文。
     *
     * @param type 实体类型
     * @param propertyNames ORM 属性名
     * @param state 查询结果 state
     * @return 至少一个值被解密时为 {@code true}
     */
    public boolean decryptStateAfterRead(
            Class<?> type, String[] propertyNames, Object[] state) {
        if (type == null || propertyNames == null || state == null
                || propertyNames.length != state.length) {
            throw new IllegalArgumentException("invalid ORM read state");
        }
        boolean changed = false;
        Metadata metadata = metadata(type);
        for (EncryptedField encrypted : metadata.encrypted) {
            int index = indexOf(propertyNames, encrypted.field.getName());
            if (index < 0 || state[index] == null) continue;
            if (!(state[index] instanceof String)) {
                throw new CryptoException("protected ORM state is not a String");
            }
            String value = (String) state[index];
            if (!value.startsWith(AesGcmCipherService.PREFIX)) {
                if (readPolicy == ReadPolicy.STRICT) {
                    throw new CryptoException("unencrypted value found in protected field");
                }
                continue;
            }
            state[index] = cipherService.decrypt(
                    value, encrypted.keyAlias, encrypted.context);
            changed = true;
        }
        return changed;
    }

    /** 恢复由 {@link #encryptForWrite(Object)} 临时改写的明文字段。 */
    public void restoreAfterWrite(Object entity) {
        decrypt(entity, ReadPolicy.STRICT);
    }

    /** 按配置策略解密查询结果。 */
    public void decryptAfterRead(Object entity) {
        decrypt(entity, readPolicy);
    }

    private void decrypt(Object entity, ReadPolicy policy) {
        if (entity == null) return;
        Metadata metadata = metadata(entity.getClass());
        try {
            for (EncryptedField encrypted : metadata.encrypted) {
                String value = (String) encrypted.field.get(entity);
                if (value == null) continue;
                if (!value.startsWith(AesGcmCipherService.PREFIX)) {
                    if (policy == ReadPolicy.STRICT) {
                        throw new CryptoException("unencrypted value found in protected field");
                    }
                    continue;
                }
                encrypted.field.set(entity, cipherService.decrypt(
                        value, encrypted.keyAlias, encrypted.context));
            }
        } catch (IllegalAccessException failure) {
            throw new CryptoException("unable to access encrypted entity field", failure);
        }
    }

    private void applyEncryption(Object entity, Metadata metadata) {
        try {
            for (BlindField blind : metadata.blindIndexes) {
                String source = (String) blind.source.get(entity);
                blind.target.set(entity, source == null ? null
                        : blindIndexes.compute(source, blind.keyAlias, blind.context));
            }
            for (EncryptedField encrypted : metadata.encrypted) {
                String plaintext = (String) encrypted.field.get(entity);
                if (plaintext != null) {
                    encrypted.field.set(entity, cipherService.encrypt(
                            plaintext, encrypted.keyAlias, encrypted.context));
                }
            }
        } catch (IllegalAccessException failure) {
            throw new CryptoException("unable to access encrypted entity field", failure);
        }
    }

    private static PreparedWrite snapshot(Object entity, Metadata metadata) {
        List<FieldValue> values = new ArrayList<FieldValue>();
        try {
            for (BlindField blind : metadata.blindIndexes) {
                addSnapshot(values, blind.target, entity);
            }
            for (EncryptedField encrypted : metadata.encrypted) {
                addSnapshot(values, encrypted.field, entity);
            }
            return new PreparedWrite(entity, values);
        } catch (IllegalAccessException failure) {
            throw new CryptoException("unable to snapshot encrypted entity field", failure);
        }
    }

    private static void addSnapshot(
            List<FieldValue> values, Field field, Object entity) throws IllegalAccessException {
        for (FieldValue value : values) {
            if (value.field.equals(field)) return;
        }
        values.add(new FieldValue(field, field.get(entity)));
    }

    private Metadata metadata(Class<?> type) {
        Metadata existing = cache.get(type);
        if (existing != null) return existing;
        Metadata created = inspect(type);
        Metadata raced = cache.putIfAbsent(type, created);
        return raced == null ? created : raced;
    }

    private Metadata inspect(Class<?> type) {
        List<Field> fields = allFields(type);
        List<EncryptedField> encrypted = new ArrayList<EncryptedField>();
        List<BlindField> blind = new ArrayList<BlindField>();
        for (Field field : fields) {
            Encrypted encryptedAnnotation = field.getAnnotation(Encrypted.class);
            if (encryptedAnnotation != null) {
                requireString(field, "@Encrypted");
                field.setAccessible(true);
                String context = valueOrDefault(encryptedAnnotation.context(),
                        type.getName() + "#" + field.getName());
                String keyAlias = valueOrDefault(encryptedAnnotation.keyAlias(), defaultKeyAlias);
                encrypted.add(new EncryptedField(field, keyAlias, context));
            }
            BlindIndex blindAnnotation = field.getAnnotation(BlindIndex.class);
            if (blindAnnotation != null) {
                requireString(field, "@BlindIndex");
                Field source = find(fields, blindAnnotation.source());
                requireString(source, "@BlindIndex source");
                field.setAccessible(true);
                source.setAccessible(true);
                String context = valueOrDefault(blindAnnotation.context(),
                        type.getName() + "#" + field.getName());
                blind.add(new BlindField(field, source,
                        blindAnnotation.keyAlias(), context));
            }
        }
        return new Metadata(
                Collections.unmodifiableList(encrypted),
                Collections.unmodifiableList(blind));
    }

    private static List<Field> allFields(Class<?> type) {
        List<Field> result = new ArrayList<Field>();
        for (Class<?> current = type;
             current != null && current != Object.class;
             current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (!Modifier.isStatic(field.getModifiers())) result.add(field);
            }
        }
        return result;
    }

    private static Field find(List<Field> fields, String name) {
        for (Field field : fields) {
            if (field.getName().equals(name)) return field;
        }
        throw new IllegalArgumentException("blind index source field does not exist: " + name);
    }

    private static void requireString(Field field, String annotation) {
        if (field.getType() != String.class) {
            throw new IllegalArgumentException(annotation + " only supports String fields");
        }
    }

    private static String valueOrDefault(String value, String fallback) {
        return value == null || value.trim().isEmpty() ? fallback : value.trim();
    }

    private static int indexOf(String[] values, String target) {
        for (int i = 0; i < values.length; i++) {
            if (target.equals(values[i])) return i;
        }
        return -1;
    }

    private static final class Metadata {
        private final List<EncryptedField> encrypted;
        private final List<BlindField> blindIndexes;
        private Metadata(List<EncryptedField> encrypted, List<BlindField> blindIndexes) {
            this.encrypted = encrypted;
            this.blindIndexes = blindIndexes;
        }
    }

    private static final class EncryptedField {
        private final Field field;
        private final String keyAlias;
        private final String context;
        private EncryptedField(Field field, String keyAlias, String context) {
            this.field = field;
            this.keyAlias = keyAlias;
            this.context = context;
        }
    }

    private static final class BlindField {
        private final Field target;
        private final Field source;
        private final String keyAlias;
        private final String context;
        private BlindField(Field target, Field source, String keyAlias, String context) {
            this.target = target;
            this.source = source;
            this.keyAlias = keyAlias;
            this.context = context;
        }
    }

    /**
     * 一次临时实体写入转换的恢复句柄。
     *
     * <p>句柄不会在 {@link #toString()} 中暴露捕获的字段值。</p>
     */
    public static final class PreparedWrite implements AutoCloseable {
        private final Object entity;
        private final List<FieldValue> values;
        private boolean closed;

        private PreparedWrite(Object entity, List<FieldValue> values) {
            this.entity = entity;
            this.values = values;
        }

        /** 精确恢复转换前的字段值；重复调用没有副作用。 */
        @Override
        public synchronized void close() {
            if (closed) return;
            try {
                for (FieldValue value : values) {
                    value.field.set(entity, value.value);
                }
                closed = true;
            } catch (IllegalAccessException failure) {
                throw new CryptoException("unable to restore encrypted entity field", failure);
            }
        }

        @Override
        public String toString() {
            return "PreparedWrite[fields=" + values.size() + ", values=<redacted>]";
        }
    }

    private static final class FieldValue {
        private final Field field;
        private final Object value;

        private FieldValue(Field field, Object value) {
            this.field = field;
            this.value = value;
        }
    }
}
