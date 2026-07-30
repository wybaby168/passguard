package dev.flyfish.passguard.crypto.mybatis;

import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.Intercepts;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.plugin.Plugin;
import org.apache.ibatis.plugin.Signature;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * MyBatis 写入参数加密与查询结果解密插件。
 *
 * <p>写入期间可能短暂改写参数实体，但插件使用不可泄密的字段快照并始终在
 * {@code finally} 中精确恢复；应用仍不应跨线程复用可变的 MyBatis 参数对象。</p>
 */
@Intercepts({
        @Signature(type = Executor.class, method = "update",
                args = {MappedStatement.class, Object.class}),
        @Signature(type = Executor.class, method = "query",
                args = {MappedStatement.class, Object.class,
                        RowBounds.class, ResultHandler.class})
})
public final class PassGuardMyBatisPlugin implements Interceptor {
    private final AnnotatedFieldProcessor processor;

    /** @param processor 共享的注解字段处理器 */
    public PassGuardMyBatisPlugin(AnnotatedFieldProcessor processor) {
        this.processor = java.util.Objects.requireNonNull(processor, "processor");
    }

    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        MappedStatement statement = (MappedStatement) invocation.getArgs()[0];
        if (statement.getSqlCommandType() == SqlCommandType.INSERT
                || statement.getSqlCommandType() == SqlCommandType.UPDATE) {
            Object parameter = invocation.getArgs()[1];
            Set<Object> visited =
                    Collections.newSetFromMap(new IdentityHashMap<Object, Boolean>());
            List<AnnotatedFieldProcessor.PreparedWrite> prepared =
                    new ArrayList<AnnotatedFieldProcessor.PreparedWrite>();
            try {
                encrypt(parameter, visited, prepared);
                return invocation.proceed();
            } finally {
                restore(prepared);
            }
        }
        Object result = invocation.proceed();
        decrypt(result, Collections.newSetFromMap(
                new IdentityHashMap<Object, Boolean>()));
        return result;
    }

    @Override
    public Object plugin(Object target) {
        return target instanceof Executor ? Plugin.wrap(target, this) : target;
    }

    @Override
    public void setProperties(Properties properties) {
        // 所有安全配置通过构造器注入，避免字符串形式的密钥或密码进入 MyBatis 配置。
    }

    private void encrypt(
            Object value,
            Set<Object> visited,
            List<AnnotatedFieldProcessor.PreparedWrite> prepared) {
        if (value == null || simple(value.getClass()) || !visited.add(value)) return;
        if (processor.supports(value.getClass())) {
            synchronized (value) {
                prepared.add(processor.prepareForWrite(value));
            }
            return;
        }
        forEach(value, child -> encrypt(child, visited, prepared));
    }

    private void restore(List<AnnotatedFieldProcessor.PreparedWrite> prepared) {
        for (int index = prepared.size() - 1; index >= 0; index--) {
            prepared.get(index).close();
        }
    }

    private void decrypt(Object value, Set<Object> visited) {
        if (value == null || simple(value.getClass()) || !visited.add(value)) return;
        if (processor.supports(value.getClass())) {
            processor.decryptAfterRead(value);
            return;
        }
        forEach(value, child -> decrypt(child, visited));
    }

    private static void forEach(Object value, Consumer consumer) {
        if (value instanceof Map) {
            for (Object child : ((Map<?, ?>) value).values()) consumer.accept(child);
        } else if (value instanceof Collection) {
            for (Object child : (Collection<?>) value) consumer.accept(child);
        } else if (value.getClass().isArray()) {
            for (int i = 0; i < Array.getLength(value); i++) {
                consumer.accept(Array.get(value, i));
            }
        }
    }

    private static boolean simple(Class<?> type) {
        return type.isPrimitive() || CharSequence.class.isAssignableFrom(type)
                || Number.class.isAssignableFrom(type) || Boolean.class == type
                || Character.class == type || type.isEnum()
                || type.getName().startsWith("java.time.");
    }

    private interface Consumer {
        void accept(Object value);
    }
}
