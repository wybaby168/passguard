package dev.flyfish.passguard.crypto.mybatis;

import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import org.apache.ibatis.plugin.Interceptor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Spring Boot 2/3 自动注册 MyBatis 插件。 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(Interceptor.class)
@ConditionalOnBean(AnnotatedFieldProcessor.class)
public class PassGuardMyBatisAutoConfiguration {
    /** @return MyBatis Starter 会自动收集的插件 Bean */
    @Bean
    @ConditionalOnMissingBean(PassGuardMyBatisPlugin.class)
    public PassGuardMyBatisPlugin passGuardMyBatisPlugin(
            AnnotatedFieldProcessor processor) {
        return new PassGuardMyBatisPlugin(processor);
    }
}
