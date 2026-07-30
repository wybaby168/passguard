package dev.flyfish.passguard.crypto.jackson;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.introspect.Annotated;
import dev.flyfish.passguard.crypto.annotation.Encrypted;

/**
 * 将 {@link Encrypted} 属性声明为仅可写，避免解密后的秘密进入前端响应。
 */
public final class EncryptedAnnotationIntrospector extends AnnotationIntrospector {
    @Override
    public JsonProperty.Access findPropertyAccess(Annotated annotated) {
        if (annotated.hasAnnotation(Encrypted.class)) {
            return JsonProperty.Access.WRITE_ONLY;
        }
        return null;
    }

    @Override
    public Version version() {
        return Version.unknownVersion();
    }
}
