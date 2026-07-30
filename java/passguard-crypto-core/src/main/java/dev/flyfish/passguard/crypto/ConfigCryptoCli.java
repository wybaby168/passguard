package dev.flyfish.passguard.crypto;

import dev.flyfish.passguard.crypto.key.EnvironmentKeyProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * 通过标准输入输出生成或解析 Spring 配置密文。
 *
 * <p>用法：{@code java ... ConfigCryptoCli encrypt [alias]}。明文不接受命令行参数，
 * 避免进入 shell history 或进程列表。</p>
 */
public final class ConfigCryptoCli {
    private static final String CONTEXT = "spring-config";
    private static final int MAX_INPUT_BYTES = 16 * 1024 * 1024;

    private ConfigCryptoCli() {}

    /** 命令行入口。 */
    public static void main(String[] args) throws IOException {
        if (args.length < 1 || args.length > 2
                || (!"encrypt".equals(args[0]) && !"decrypt".equals(args[0]))) {
            throw new IllegalArgumentException("usage: encrypt|decrypt [keyAlias]");
        }
        String alias = args.length == 2 ? args[1] : "config";
        CipherService cipher = new AesGcmCipherService(new EnvironmentKeyProvider());
        String input = readStdin();
        if ("encrypt".equals(args[0])) {
            System.out.print("ENC(" + cipher.encrypt(input, alias, CONTEXT) + ")");
        } else {
            String ciphertext = input;
            if (ciphertext.startsWith("ENC(") && ciphertext.endsWith(")")) {
                ciphertext = ciphertext.substring(4, ciphertext.length() - 1);
            }
            System.out.print(cipher.decrypt(ciphertext, alias, CONTEXT));
        }
    }

    private static String readStdin() throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int read;
        while ((read = System.in.read(buffer)) >= 0) {
            if (output.size() + read > MAX_INPUT_BYTES) {
                Arrays.fill(buffer, (byte) 0);
                throw new IOException("standard input exceeds 16 MiB limit");
            }
            output.write(buffer, 0, read);
        }
        byte[] input = output.toByteArray();
        try {
            return new String(input, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(buffer, (byte) 0);
            Arrays.fill(input, (byte) 0);
        }
    }
}
