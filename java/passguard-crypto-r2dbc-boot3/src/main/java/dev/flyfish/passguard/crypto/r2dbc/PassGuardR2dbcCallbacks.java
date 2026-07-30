package dev.flyfish.passguard.crypto.r2dbc;

import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import org.reactivestreams.Publisher;
import org.springframework.data.r2dbc.mapping.OutboundRow;
import org.springframework.data.r2dbc.mapping.event.AfterConvertCallback;
import org.springframework.data.r2dbc.mapping.event.BeforeSaveCallback;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.sql.SqlIdentifier;
import org.springframework.r2dbc.core.Parameter;
import reactor.core.publisher.Mono;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/** Spring Data R2DBC 3.x 写入行加密和读取实体解密回调。 */
public final class PassGuardR2dbcCallbacks
        implements BeforeSaveCallback<Object>, AfterConvertCallback<Object> {
    private final AnnotatedFieldProcessor processor;
    private final Map<Class<?>, Map<String, String>> columnCache =
            new ConcurrentHashMap<>();

    /** @param processor 共享字段处理器 */
    public PassGuardR2dbcCallbacks(AnnotatedFieldProcessor processor) {
        this.processor = Objects.requireNonNull(processor, "processor");
    }

    @Override
    public Publisher<Object> onBeforeSave(
            Object entity, OutboundRow row, SqlIdentifier table) {
        Map<String, String> state = processor.encryptedState(entity);
        if (!state.isEmpty()) {
            Map<String, String> columns = columnsFor(entity.getClass());
            for (Map.Entry<String, String> entry : state.entrySet()) {
                String column = columns.get(entry.getKey());
                for (SqlIdentifier identifier : row.keySet()) {
                    if (identifier.getReference().equals(column)) {
                        row.put(identifier, Parameter.fromOrEmpty(entry.getValue(), String.class));
                        break;
                    }
                }
            }
        }
        return Mono.just(entity);
    }

    @Override
    public Publisher<Object> onAfterConvert(Object entity, SqlIdentifier table) {
        processor.decryptAfterRead(entity);
        return Mono.just(entity);
    }

    private Map<String, String> columnsFor(Class<?> type) {
        Map<String, String> existing = columnCache.get(type);
        if (existing != null) return existing;
        Map<String, String> created = columns(type);
        Map<String, String> raced = columnCache.putIfAbsent(type, created);
        return raced == null ? created : raced;
    }

    private static Map<String, String> columns(Class<?> type) {
        Map<String, String> result = new HashMap<String, String>();
        for (Class<?> current = type; current != null && current != Object.class;
             current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                Column annotation = field.getAnnotation(Column.class);
                result.put(field.getName(),
                        annotation == null ? field.getName() : annotation.value());
            }
        }
        return Collections.unmodifiableMap(result);
    }
}
