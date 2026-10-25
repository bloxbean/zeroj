package org.zeroj.bls12381.bulletproofs;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.PureJavaBls12381Provider;

import java.math.BigInteger;
import java.util.Objects;

/**
 * The verifier of {@code bulletproof-range-bls12-381-g1-v1} (spec §8): accepts a proof for a
 * commitment {@code V ≠ O} if and only if it establishes {@code 0 ≤ v < 2^n} under the verifier's
 * own width {@code n} and application context {@code ctx}.
 *
 * <p><b>The width and the context are the verifier's configuration</b>, never taken from the proof
 * or the message (spec §8, §13). The context must be 1 to 1,024 octets, unique to the application;
 * it binds the proof to that application, not to a message, sender or epoch, unless the application
 * puts those into it (spec §5.1). A valid proof gives no authorization, replay protection or balance
 * rule: those stay with the application (spec §1.1, §13).
 *
 * <h2>Verdict</h2>
 * {@code true} (accept), {@code false} (reject: an identity commitment, a zero challenge or a failed
 * check), or a {@link CommitmentFormatException} carrying the class of a format failure. The verdict
 * is a pure function of {@code (V, proof, n, ctx)} and the pinned constants: there is no randomness,
 * clock, I/O or unordered iteration, and the work is fixed by {@code n} (spec §8.4, §13). Both
 * checks are evaluated separately and deterministically; they are never merged with a random weight
 * (ADR-0061 D5).
 *
 * <h2>Providers</h2>
 * Verification uses only the provider's public multiplication. The verdict trusts it, as the
 * provider is trusted code; every scalar passed to it is already reduced into {@code [0, q)}.
 * Instances are immutable and thread-safe.
 *
 * <p>Experimental: not approved for value-bearing or mainnet use.
 */
public final class G1RangeVerifier {

    private final Bls12381Provider provider;

    private G1RangeVerifier(Bls12381Provider provider) {
        this.provider = provider;
    }

    /** The verifier over the pure-Java provider. */
    public static G1RangeVerifier pureJava() {
        return PureJava.INSTANCE;
    }

    /**
     * A verifier over {@code provider}.
     *
     * @throws NullPointerException if {@code provider} is null
     */
    public static G1RangeVerifier withProvider(Bls12381Provider provider) {
        return new G1RangeVerifier(Objects.requireNonNull(provider, "provider"));
    }

    /** The provider this verifier uses. */
    public Bls12381Provider provider() {
        return provider;
    }

    /**
     * Verifies a decoded proof against a decoded commitment.
     *
     * <p>Checks, in order: nulls; {@code bits ∈ {16, 32, 64}} and {@code context} of 1 to 1,024 octets
     * ({@code INVALID_CONFIGURATION}); the proof was decoded for {@code bits}, else
     * {@code MALFORMED_ENCODING}, exactly as a wrong-length octet string (spec §8); {@code V = O} →
     * {@code false}; then the challenges and both checks. A {@link G1PedersenCommitment} is a
     * validated element of the prime-order subgroup.
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException with the class of the first format failure
     */
    public boolean verify(G1PedersenCommitment commitment, G1RangeProof proof, int bits, byte[] context) {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(proof, "proof");
        byte[] ctx = configuration(bits, context);
        if (proof.bits() != bits) {
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING,
                    "the proof was decoded for another width");
        }
        return evaluate(PointCodec.point(commitment), proof, ctx).accepted();
    }

    /**
     * Verifies proof octets against a decoded commitment. Checks, in order: nulls; configuration
     * ({@code INVALID_CONFIGURATION}); the proof's length and fields, by {@link G1RangeProof#decode}
     * (spec §8.1 steps 2–3); {@code V = O} → {@code false}; then the challenges and both checks.
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException with the class of the first format failure
     */
    public boolean verify(G1PedersenCommitment commitment, byte[] proof, int bits, byte[] context) {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(proof, "proof");
        byte[] ctx = configuration(bits, context);
        G1RangeProof decoded = G1RangeProof.decode(proof, bits);
        return evaluate(PointCodec.point(commitment), decoded, ctx).accepted();
    }

    /**
     * Verifies proof octets against a commitment given as its 48-octet encoding. Checks, in order
     * (spec §8.1): nulls; configuration ({@code INVALID_CONFIGURATION}); the proof's length and
     * fields; then {@code V} by the profile's strict decoder ({@code MALFORMED_ENCODING},
     * {@code NOT_IN_SUBGROUP}); {@code V = O} → {@code false}; then the challenges and both checks.
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException with the class of the first format failure
     */
    public boolean verify(byte[] commitment, byte[] proof, int bits, byte[] context) {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(proof, "proof");
        byte[] ctx = configuration(bits, context);
        G1RangeProof decoded = G1RangeProof.decode(proof, bits);
        G1PedersenCommitment v = G1PedersenCommitment.decode(commitment);
        return evaluate(PointCodec.point(v), decoded, ctx).accepted();
    }

    /** Null check, snapshot, then spec §8.1 step 1. The snapshot is the only copy used afterwards. */
    private static byte[] configuration(int bits, byte[] context) {
        Objects.requireNonNull(context, "context");
        byte[] ctx = context.clone();
        RangeTranscript.requireConfiguration(bits, ctx);
        return ctx;
    }

    /**
     * Spec §8.1 step 5 to §8.3 for a validated {@code V} and a well-formed proof of the configured
     * width: the identity check, the transcript, then both checks. The outcome names the first
     * failing layer; it is diagnostic only (spec §8.4).
     */
    Outcome evaluate(G1Point v, G1RangeProof proof, byte[] ctx) {
        if (v.isInfinity()) {
            return new Outcome(Layer.STATEMENT, null);
        }
        Challenges ch = Challenges.derive(v, proof, ctx);
        return new Outcome(checks(v, proof, ch), ch);
    }

    /**
     * The zero-challenge rule (spec §5.3, §8.2), then checks 1 and 2 (spec §8.3), both evaluated
     * whenever every challenge is non-zero. Package-private so that tests can drive it with chosen
     * challenges.
     */
    Layer checks(G1Point v, G1RangeProof proof, Challenges ch) {
        if (ch.anyZero()) {
            return Layer.CHALLENGE;
        }
        boolean first = check1(v, proof, ch);
        boolean second = check2(proof, ch);
        if (!first) {
            return Layer.CHECK1;
        }
        return second ? Layer.ACCEPT : Layer.CHECK2;
    }

    /** {@code [t̂ − δ(y, z)]·G + [τ_x]·H + [−z²]·V + [−x]·T₁ + [−x²]·T₂ == O} (spec §8.3). */
    private boolean check1(G1Point v, G1RangeProof proof, Challenges ch) {
        int n = proof.bits();
        BigInteger z2 = RangeMath.mul(ch.z(), ch.z());
        BigInteger x2 = RangeMath.mul(ch.x(), ch.x());
        G1Point sum = mul(BulletproofGenerators.g(), RangeMath.sub(proof.tHat(), RangeMath.delta(ch.y(), ch.z(), n)));
        sum = sum.add(mul(BulletproofGenerators.h(), proof.tauX()));
        sum = sum.add(mul(v, RangeMath.neg(z2)));
        sum = sum.add(mul(proof.t1(), RangeMath.neg(ch.x())));
        sum = sum.add(mul(proof.t2(), RangeMath.neg(x2)));
        return sum.isInfinity();
    }

    /**
     * Paper (105) with the independent generator {@code U} (spec §8.3), {@code 2n + 2k + 4} terms:
     * {@code Σ [a·s_i + z]·G_i + Σ [y^{−i}·(b·s_i⁻¹ − z²·2^i) − z]·H_i + [x_u·(a·b − t̂)]·U + [μ]·H
     * + [−1]·A + [−x]·S + Σ ([−x_j²]·L_j + [−x_j^{−2}]·R_j) == O}.
     */
    private boolean check2(G1RangeProof proof, Challenges ch) {
        int n = proof.bits();
        int k = RangeTranscript.rounds(n);
        BigInteger[] xj = ch.xj();
        BigInteger[] xjInv = new BigInteger[k];
        for (int j = 0; j < k; j++) {
            xjInv[j] = RangeMath.inv(xj[j]);
        }
        BigInteger[] s = RangeMath.challengeProducts(xj, xjInv, n);
        BigInteger[] sInv = RangeMath.challengeProducts(xjInv, xj, n);
        BigInteger z = ch.z();
        BigInteger z2 = RangeMath.mul(z, z);
        BigInteger yInv = RangeMath.inv(ch.y());
        BigInteger a = proof.aFinal();
        BigInteger b = proof.bFinal();

        G1Point sum = G1Point.INFINITY;
        BigInteger yInvPow = BigInteger.ONE;
        BigInteger twoPow = BigInteger.ONE;
        for (int i = 0; i < n; i++) {
            sum = sum.add(mul(BulletproofGenerators.gVec(i), RangeMath.add(RangeMath.mul(a, s[i]), z)));
            BigInteger hCoeff = RangeMath.sub(
                    RangeMath.mul(yInvPow, RangeMath.sub(RangeMath.mul(b, sInv[i]), RangeMath.mul(z2, twoPow))), z);
            sum = sum.add(mul(BulletproofGenerators.hVec(i), hCoeff));
            yInvPow = RangeMath.mul(yInvPow, yInv);
            twoPow = RangeMath.add(twoPow, twoPow);
        }
        sum = sum.add(mul(BulletproofGenerators.u(), RangeMath.mul(ch.xu(), RangeMath.sub(RangeMath.mul(a, b), proof.tHat()))));
        sum = sum.add(mul(BulletproofGenerators.h(), proof.mu()));
        sum = sum.add(mul(proof.a(), RangeMath.neg(BigInteger.ONE)));
        sum = sum.add(mul(proof.s(), RangeMath.neg(ch.x())));
        for (int j = 0; j < k; j++) {
            BigInteger x2 = RangeMath.mul(xj[j], xj[j]);
            BigInteger x2Inv = RangeMath.mul(xjInv[j], xjInv[j]);
            sum = sum.add(mul(proof.l(j), RangeMath.neg(x2)));
            sum = sum.add(mul(proof.r(j), RangeMath.neg(x2Inv)));
        }
        return sum.isInfinity();
    }

    /** The provider's public multiplication by a reduced scalar; a null result is a provider fault. */
    private G1Point mul(G1Point point, BigInteger scalar) {
        G1Point result = provider.g1ScalarMul(point, scalar);
        if (result == null) {
            throw new IllegalStateException("provider " + provider.id() + " returned null");
        }
        return result;
    }

    /** Where verification stopped (spec §11 {@code layer}); diagnostic only. */
    enum Layer {
        ACCEPT, STATEMENT, CHALLENGE, CHECK1, CHECK2
    }

    /** A verification outcome, with the challenges when they were derived. */
    record Outcome(Layer layer, Challenges challenges) {
        boolean accepted() {
            return layer == Layer.ACCEPT;
        }
    }

    /** The challenges of spec §5.3, with the session identifier and instance they came from. */
    record Challenges(byte[] sessionId, byte[] instance, BigInteger y, BigInteger z, BigInteger x, BigInteger xu,
                      BigInteger[] xj) {

        /** Replays the transcript over a proof's messages (spec §5.3). */
        static Challenges derive(G1Point v, G1RangeProof proof, byte[] ctx) {
            RangeTranscript t = RangeTranscript.start(proof.bits(), ctx, v);
            BigInteger y = t.absorbPointsSqueeze(proof.a(), proof.s());
            BigInteger z = t.challenge();
            BigInteger x = t.absorbPointsSqueeze(proof.t1(), proof.t2());
            t.absorbScalars(proof.tHat(), proof.tauX(), proof.mu());
            BigInteger xu = t.challenge();
            int k = RangeTranscript.rounds(proof.bits());
            BigInteger[] xj = new BigInteger[k];
            for (int j = 0; j < k; j++) {
                xj[j] = t.absorbPointsSqueeze(proof.l(j), proof.r(j));
            }
            return new Challenges(t.sessionId(), t.instanceBytes(), y, z, x, xu, xj);
        }

        boolean anyZero() {
            if (y.signum() == 0 || z.signum() == 0 || x.signum() == 0 || xu.signum() == 0) {
                return true;
            }
            for (BigInteger c : xj) {
                if (c.signum() == 0) {
                    return true;
                }
            }
            return false;
        }
    }

    private static final class PureJava {
        static final G1RangeVerifier INSTANCE = new G1RangeVerifier(PureJavaBls12381Provider.INSTANCE);
    }
}
