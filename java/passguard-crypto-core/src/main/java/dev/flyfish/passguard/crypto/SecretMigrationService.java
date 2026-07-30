package dev.flyfish.passguard.crypto;

import java.util.Objects;

/**
 * 框架无关的幂等批量迁移编排器。
 *
 * <p>调用方控制分页读取和事务写入，本服务不猜测表结构，也不会记录任何字段值。</p>
 */
public final class SecretMigrationService<T> {
    private final Detector<T> detector;
    private final Writer<T> writer;

    /** @param detector 判断记录是否需要迁移；@param writer 执行单条更新 */
    public SecretMigrationService(Detector<T> detector, Writer<T> writer) {
        this.detector = Objects.requireNonNull(detector, "detector");
        this.writer = Objects.requireNonNull(writer, "writer");
    }

    /**
     * @param records 已由调用方分页获得的记录
     * @param dryRun 为 {@code true} 时只统计不写入
     * @return 当前批次统计
     */
    public MigrationReport migrate(Iterable<T> records, boolean dryRun) {
        Objects.requireNonNull(records, "records");
        long examined = 0;
        long changed = 0;
        for (T record : records) {
            examined++;
            if (detector.needsMigration(record)) {
                changed++;
                if (!dryRun) writer.write(record);
            }
        }
        return new MigrationReport(examined, changed, dryRun);
    }

    /** 判断记录是否需要迁移。 */
    public interface Detector<T> {
        boolean needsMigration(T record);
    }

    /** 把记录写回调用方管理的数据源。 */
    public interface Writer<T> {
        void write(T record);
    }
}
