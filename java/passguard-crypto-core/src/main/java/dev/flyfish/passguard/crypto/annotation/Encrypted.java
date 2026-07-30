package dev.flyfish.passguard.crypto.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标记需要在持久化层透明加解密、并从 JSON 响应中排除的字符串字段。
 *
 * <p>{@link #context()} 会参与 GCM 附加认证数据。生产项目应填写跨重构稳定的
 * “表.列”标识，避免字段改名后无法解密历史数据。</p>
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD})
public @interface Encrypted {
    /** @return 密钥逻辑别名；空字符串使用应用默认别名 */
    String keyAlias() default "";

    /** @return 稳定的加密上下文；空字符串时由实体类型和属性名推导 */
    String context() default "";
}
