package dev.flyfish.passguard.spring;

import org.springframework.boot.actuate.endpoint.SanitizableData;
import org.springframework.boot.actuate.endpoint.SanitizingFunction;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Locale;

/**
 * 加强 Actuator 环境和配置属性端点的敏感值脱敏。
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(SanitizingFunction.class)
public class PassGuardActuatorSanitizationConfiguration {
    /**
     * @return 同时识别敏感键名与 PassGuard 密文格式的脱敏函数
     */
    @Bean
    @ConditionalOnMissingBean(name = "passGuardSanitizingFunction")
    public SanitizingFunction passGuardSanitizingFunction() {
        return data -> sensitive(data) ? data.withValue(SanitizableData.SANITIZED_VALUE) : data;
    }

    private static boolean sensitive(SanitizableData data) {
        String key = data.getKey().toLowerCase(Locale.ROOT)
                .replace("-", "").replace("_", "").replace(".", "");
        if (key.contains("password") || key.contains("secret") || key.contains("credential")
                || key.contains("token") || key.contains("apikey")
                || key.contains("privatekey") || key.contains("keystorepassword")) {
            return true;
        }
        Object value = data.getValue();
        if (!(value instanceof String)) return false;
        String text = (String) value;
        return text.startsWith("PG1.") || text.startsWith("BI1.")
                || text.startsWith("ENC(PG1.");
    }
}
