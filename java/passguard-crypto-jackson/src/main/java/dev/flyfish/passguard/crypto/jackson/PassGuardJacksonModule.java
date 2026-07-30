package dev.flyfish.passguard.crypto.jackson;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * 注册 PassGuard 敏感字段序列化规则。
 */
public final class PassGuardJacksonModule extends SimpleModule {
    /** 创建可直接注册到 {@code ObjectMapper} 的模块。 */
    public PassGuardJacksonModule() {
        super("PassGuardJacksonModule", new Version(2, 1, 0, null, null, null));
    }

    @Override
    public void setupModule(Module.SetupContext context) {
        super.setupModule(context);
        context.insertAnnotationIntrospector(new EncryptedAnnotationIntrospector());
    }
}
