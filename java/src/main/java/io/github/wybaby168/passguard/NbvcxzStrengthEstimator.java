package io.github.wybaby168.passguard;

import me.gosimple.nbvcxz.Nbvcxz;

public final class NbvcxzStrengthEstimator implements StrengthEstimator {
    private final Nbvcxz nbvcxz;

    public NbvcxzStrengthEstimator() {
        this(new Nbvcxz());
    }

    public NbvcxzStrengthEstimator(Nbvcxz nbvcxz) {
        this.nbvcxz = nbvcxz;
    }

    @Override
    public int score(String password) {
        return nbvcxz.estimate(password).getBasicScore();
    }
}
