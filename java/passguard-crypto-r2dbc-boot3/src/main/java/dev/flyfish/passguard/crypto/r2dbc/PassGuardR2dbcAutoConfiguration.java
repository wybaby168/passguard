package dev.flyfish.passguard.crypto.r2dbc;

import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.data.r2dbc.mapping.OutboundRow;

/** Spring Boot 3 R2DBC 自动配置。 */
@AutoConfiguration
@ConditionalOnClass(OutboundRow.class)
@ConditionalOnBean(AnnotatedFieldProcessor.class)
public class PassGuardR2dbcAutoConfiguration {
    /** @return R2DBC 加解密回调 */
    @Bean
    public PassGuardR2dbcCallbacks passGuardR2dbcCallbacks(
            AnnotatedFieldProcessor processor) {
        return new PassGuardR2dbcCallbacks(processor);
    }
}
