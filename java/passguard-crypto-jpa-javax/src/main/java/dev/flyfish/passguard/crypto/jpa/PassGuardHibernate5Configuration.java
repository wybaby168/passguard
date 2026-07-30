package dev.flyfish.passguard.crypto.jpa;

import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.jpa.boot.spi.IntegratorProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.orm.jpa.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;
import java.util.Map;

/**
 * Spring Boot 2 自动注册 Hibernate 5 集成器。
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass({HibernatePropertiesCustomizer.class, Integrator.class})
@ConditionalOnBean(AnnotatedFieldProcessor.class)
public class PassGuardHibernate5Configuration {
    /** @return 把 PassGuard 事件集成器写入 Hibernate 属性的定制器 */
    @Bean
    public HibernatePropertiesCustomizer passGuardHibernate5Customizer(
            final AnnotatedFieldProcessor processor) {
        return new HibernatePropertiesCustomizer() {
            @Override
            public void customize(Map<String, Object> hibernateProperties) {
                hibernateProperties.put("hibernate.integrator_provider",
                        new IntegratorProvider() {
                            @Override
                            public java.util.List<Integrator> getIntegrators() {
                                return Collections.<Integrator>singletonList(
                                        new PassGuardHibernate5Integrator(processor));
                            }
                        });
            }
        };
    }
}
