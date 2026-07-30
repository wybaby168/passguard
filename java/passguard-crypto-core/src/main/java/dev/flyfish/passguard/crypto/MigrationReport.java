package dev.flyfish.passguard.crypto;

/** 一次明文迁移或密钥重加密的不可变统计。 */
public final class MigrationReport {
    private final long examined;
    private final long changed;
    private final boolean dryRun;

    /** @param examined 检查数量；@param changed 需要或已经更新数量；@param dryRun 是否试运行 */
    public MigrationReport(long examined, long changed, boolean dryRun) {
        if (examined < 0 || changed < 0 || changed > examined) {
            throw new IllegalArgumentException("invalid migration counters");
        }
        this.examined = examined;
        this.changed = changed;
        this.dryRun = dryRun;
    }

    /** @return 检查数量 */
    public long examined() { return examined; }
    /** @return 需要或已经更新数量 */
    public long changed() { return changed; }
    /** @return 是否未执行写入 */
    public boolean dryRun() { return dryRun; }
}
