package dev.flyfish.passguard.crypto.jackson;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Spring Boot 2/3 自动注册 Jackson 敏感字段模块。 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(ObjectMapper.class)
public class PassGuardJacksonAutoConfiguration {
    /** @return 自动被 Spring Boot ObjectMapper 收集的模块 Bean */
    @Bean
    @ConditionalOnMissingBean(PassGuardJacksonModule.class)
    public Module passGuardJacksonModule() {
        return new PassGuardJacksonModule();
    }
}
