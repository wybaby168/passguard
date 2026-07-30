package dev.flyfish.passguard.crypto.jackson;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.flyfish.passguard.crypto.annotation.Encrypted;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PassGuardJacksonModuleTest {
    @Test
    void omitsEncryptedValueFromResponseButAcceptsRequest() throws Exception {
        ObjectMapper mapper = new ObjectMapper().registerModule(new PassGuardJacksonModule());
        Credential value = new Credential();
        value.name = "service";
        value.password = "plaintext";
        String json = mapper.writeValueAsString(value);
        assertEquals("{\"name\":\"service\"}", json);

        Credential parsed = mapper.readValue(
                "{\"name\":\"service\",\"password\":\"incoming\"}", Credential.class);
        assertEquals("incoming", parsed.password);
    }

    static final class Credential {
        public String name;
        @Encrypted(context = "credential.password")
        public String password;
    }
}
