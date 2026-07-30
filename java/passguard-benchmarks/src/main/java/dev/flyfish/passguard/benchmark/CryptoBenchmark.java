package dev.flyfish.passguard.benchmark;

import dev.flyfish.passguard.crypto.AesGcmCipherService;
import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import dev.flyfish.passguard.crypto.BlindIndexService;
import dev.flyfish.passguard.crypto.CipherService;
import dev.flyfish.passguard.crypto.ReadPolicy;
import dev.flyfish.passguard.crypto.annotation.Encrypted;
import dev.flyfish.passguard.crypto.key.InMemoryKeyProvider;
import dev.flyfish.passguard.crypto.key.KeyManager;
import dev.flyfish.passguard.generator.SecurePasswordGenerator;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.util.concurrent.TimeUnit;

/**
 * AES-GCM 和密码生成的发布性能基线。
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
public class CryptoBenchmark {
    /** 每个 JMH 线程独享的基准状态，避免测量无关锁竞争。 */
    @State(Scope.Thread)
    public static class BenchmarkState {
        /** AES-GCM 明文长度，覆盖常见短凭据、令牌和较长配置秘密。 */
        @Param({"32", "128", "1024"})
        public int size;

        private CipherService cipher;
        private String ciphertext;
        private String plaintext;
        private SecurePasswordGenerator generator;
        private AnnotatedFieldProcessor fields;

        /** 初始化并预热密钥与 JCE Provider。 */
        @Setup(Level.Trial)
        public void setup() {
            InMemoryKeyProvider keys = new InMemoryKeyProvider();
            new KeyManager(keys).generateAndActivate("data", "v1");
            cipher = new AesGcmCipherService(keys);
            StringBuilder value = new StringBuilder(size);
            while (value.length() < size) value.append("x9F!passguard0123456789");
            plaintext = value.substring(0, size);
            ciphertext = cipher.encrypt(plaintext, "data", "benchmark.field");
            generator = new SecurePasswordGenerator();
            fields = new AnnotatedFieldProcessor(
                    cipher, new BlindIndexService(keys), "data", ReadPolicy.STRICT);
            // 在测量前完成唯一一次反射解析；基准只测缓存命中路径。
            fields.supports(SampleSecret.class);
        }
    }

    /** @return 参数指定长度明文的新 AES-GCM 密文 */
    @Benchmark
    public String encrypt(BenchmarkState state) {
        return state.cipher.encrypt(state.plaintext, "data", "benchmark.field");
    }

    /** @return 已认证密文的明文 */
    @Benchmark
    public String decrypt(BenchmarkState state) {
        return state.cipher.decrypt(state.ciphertext, "data", "benchmark.field");
    }

    /** @return 已完成首次反射解析后的元数据缓存查询结果 */
    @Benchmark
    public boolean metadataCacheHit(BenchmarkState state) {
        return state.fields.supports(SampleSecret.class);
    }

    /** @return 默认 20 字符安全密码 */
    @Benchmark
    public String generatePassword(BenchmarkState state) {
        return state.generator.generate();
    }

    private static final class SampleSecret {
        @Encrypted(keyAlias = "data", context = "benchmark.field")
        private String value;
    }
}
