package dev.flyfish.passguard.crypto.jpa;

import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.jpa.boot.spi.IntegratorProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.orm.jpa.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;

import java.util.Collections;
import java.util.Map;

/** Spring Boot 3 自动注册 Hibernate 6 集成器。 */
@AutoConfiguration
@ConditionalOnClass({HibernatePropertiesCustomizer.class, Integrator.class})
@ConditionalOnBean(AnnotatedFieldProcessor.class)
public class PassGuardHibernate6AutoConfiguration {
    /** @return Hibernate 属性定制器 */
    @Bean
    public HibernatePropertiesCustomizer passGuardHibernate6Customizer(
            final AnnotatedFieldProcessor processor) {
        return new HibernatePropertiesCustomizer() {
            @Override
            public void customize(Map<String, Object> properties) {
                properties.put("hibernate.integrator_provider",
                        new IntegratorProvider() {
                            @Override
                            public java.util.List<Integrator> getIntegrators() {
                                return Collections.<Integrator>singletonList(
                                        new PassGuardHibernate6Integrator(processor));
                            }
                        });
            }
        };
    }
}
