package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.List;

/**
 * A discrete-log-equality statement {@code log_G P = log_X D} of {@code elgamal-jubjub-v1}
 * §9.2, as the library hands it to a {@link DleqStatementVerifier}.
 *
 * <p>Statements are built only by the library, from data it already trusts:
 * <ul>
 *   <li>a possession statement takes {@code X = G} and {@code D = P = } the candidate key
 *       (§3.3);</li>
 *   <li>a decryption-share statement takes {@code X} = the admitted ciphertext's handle and
 *       {@code P} = the trustee's registered key (§10.2).</li>
 * </ul>
 * A verifier therefore never chooses the base or the key, which is what invariants I9 and I14
 * require. It only decides whether a proof exists for exactly this statement.
 */
public final class DleqStatement {

    /** What the statement is used for. */
    public enum Kind {
        /** Proof of possession of a key share: {@code X = G}, {@code D = P}. */
        POSSESSION,
        /** Correctness of a decryption share: {@code X} = an admitted handle. */
        DECRYPTION_SHARE
    }

    private final Kind kind;
    private final JubjubPoint base;
    private final JubjubPoint publicKey;
    private final JubjubPoint share;

    private DleqStatement(Kind kind, JubjubPoint base, JubjubPoint publicKey, JubjubPoint share) {
        this.kind = kind;
        this.base = base.normalized();
        this.publicKey = publicKey.normalized();
        this.share = share.normalized();
    }

    static DleqStatement possession(JubjubPoint key) {
        return new DleqStatement(Kind.POSSESSION, JubjubPoint.SUBGROUP_GENERATOR, key, key);
    }

    static DleqStatement decryptionShare(JubjubPoint handle, JubjubPoint key, JubjubPoint share) {
        return new DleqStatement(Kind.DECRYPTION_SHARE, handle, key, share);
    }

    /** The statement's use. */
    public Kind kind() {
        return kind;
    }

    /** The base {@code X}. */
    public JubjubPoint base() {
        return base;
    }

    /** The key {@code P = [x]·G}. */
    public JubjubPoint publicKey() {
        return publicKey;
    }

    /** The share {@code D = [x]·X}. */
    public JubjubPoint share() {
        return share;
    }

    /** Public inputs in spec §8 order: {@code X.u, X.v, P.u, P.v, D.u, D.v}. */
    public List<BigInteger> publicInputs() {
        return ElGamalEncodings.affine(base, publicKey, share);
    }

    @Override
    public String toString() {
        return "DleqStatement{" + kind + ", publicInputs=" + publicInputs() + "}";
    }
}
