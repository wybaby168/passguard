package io.github.wybaby168.passguard;

import me.gosimple.nbvcxz.Nbvcxz;

/**
 * 基于 nbvcxz 的默认强度估算器。
 */
public final class NbvcxzStrengthEstimator implements StrengthEstimator {
    private final Nbvcxz nbvcxz;

    /** 使用默认 {@link Nbvcxz} 配置。 */
    public NbvcxzStrengthEstimator() {
        this(new Nbvcxz());
    }

    /**
     * @param nbvcxz 已配置的 nbvcxz 实例
     */
    public NbvcxzStrengthEstimator(Nbvcxz nbvcxz) {
        this.nbvcxz = nbvcxz;
    }

    /** {@inheritDoc} */
    @Override
    public int score(String password) {
        return nbvcxz.estimate(password).getBasicScore();
    }
}
