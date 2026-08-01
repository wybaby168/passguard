package dev.flyfish.passguard;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * UTF-8 弱密码整串名单。
 *
 * <p>名单匹配使用 NFKC 兼容规范化和不区分大小写的比较键，避免通过全角字符、
 * 兼容字符或简单大小写变化绕过弱密码检查。该规范化仅用于名单比较，不会改变
 * 后续哈希或认证所使用的真实密码。</p>
 */
public final class LocalBlocklist {
    private final Set<String> entries;

    /**
     * 从内存词条创建名单。
     *
     * @param entries 原始词条；空字符串和 {@code null} 词条会被忽略
     */
    public LocalBlocklist(Collection<String> entries) {
        Objects.requireNonNull(entries, "entries");
        Set<String> normalized = new HashSet<>(Math.max(16, entries.size() * 2));
        for (String entry : entries) {
            if (entry != null && !entry.isEmpty()) {
                normalized.add(PasswordNormalizer.blocklistKey(entry));
            }
        }
        this.entries = Collections.unmodifiableSet(
                new HashSet<String>(normalized));
    }

    /**
     * 从 classpath UTF-8 资源加载，每行一条密码。
     *
     * @param resource 以当前类为基准的资源路径
     * @return 加载后的名单
     * @throws IOException 资源不存在或读取失败
     */
    public static LocalBlocklist fromClasspath(String resource) throws IOException {
        InputStream stream = LocalBlocklist.class.getResourceAsStream(resource);
        if (stream == null) throw new IOException("Classpath resource not found: " + resource);
        try (InputStream input = stream) {
            return fromInputStream(input);
        }
    }

    /**
     * 从 UTF-8 文件加载，每行一条密码。
     *
     * @param path 文件路径
     * @return 加载后的名单
     * @throws IOException 读取失败
     */
    public static LocalBlocklist fromPath(Path path) throws IOException {
        try (InputStream stream = Files.newInputStream(path)) {
            return fromInputStream(stream);
        }
    }

    /**
     * 从 UTF-8 输入流加载并关闭该流。只移除行终止符，不会 trim 密码。
     *
     * @param input 输入流
     * @return 加载后的名单
     * @throws IOException 读取失败
     */
    public static LocalBlocklist fromInputStream(InputStream input) throws IOException {
        Set<String> values = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // readLine removes line terminators only; it does not trim password spaces.
                if (!line.isEmpty()) values.add(line);
            }
        }
        return new LocalBlocklist(values);
    }

    /**
     * @param password 待查询密码
     * @return NFKC 且不区分大小写的整串比较值是否命中
     */
    public boolean contains(String password) {
        return entries.contains(PasswordNormalizer.blocklistKey(password));
    }

    /** @return 去重后的词条数 */
    public int size() {
        return entries.size();
    }
}
