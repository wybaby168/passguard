package dev.flyfish.passguard.crypto.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标记保存等值查询盲索引的字符串字段。
 *
 * <p>盲索引使用独立 HMAC-SHA256 密钥，不允许与数据加密密钥共用。
 * 它只支持精确等值查询，不提供模糊、范围或排序语义。</p>
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface BlindIndex {
    /** @return 当前对象中作为明文来源的字段名 */
    String source();

    /** @return HMAC 密钥逻辑别名 */
    String keyAlias() default "index";

    /** @return 稳定的索引上下文；空字符串时由实体类型和当前字段名推导 */
    String context() default "";
}
