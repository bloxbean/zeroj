package org.zeroj.bls12381.bulletproofs;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.PureJavaBls12381Provider;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * The prover of {@code bulletproof-range-bls12-381-g1-v1} (spec §7): for an opening {@code (v, γ)}
 * of a {@code pedersen-bls12-381-g1-v1} commitment {@code V = [v]·G + [γ]·H ≠ O} with
 * {@code 0 ≤ v < 2^n}, a proof under width {@code n} and application context {@code ctx}.
 *
 * <h2>Proving is offline/isolated only</h2>
 * The prover handles the opening and the nonces with variable-time {@link BigInteger} arithmetic
 * and makes no constant-time claim on any provider (ADR-0038, spec §7.4). Commitments to secrets
 * ({@code V}, {@code A}, {@code S}, {@code T₁}, {@code T₂}) use only the provider's
 * {@code g1SecretScalarMul}; {@code A} is a full sum over all {@code 2n} generators, so the sequence
 * of calls does not depend on the bits of {@code v} (a schedule property, not a constant-time
 * guarantee). The inner-product rounds use the public multiplication on the blinded vectors.
 *
 * <h2>Randomness</h2>
 * Every proof draws fresh nonces from a {@code SecureRandom} the prover creates itself; no API
 * accepts nonces, a seed or a random source. Reusing nonces across two proofs leaks the witness.
 * The runtime's entropy configuration is trusted (spec §7.3): a misconfigured JDK or operating
 * system defeats the hiding and zero-knowledge of every proof. A source whose algorithm is not one
 * of {@code NativePRNG}, {@code NativePRNGNonBlocking}, {@code DRBG} or {@code Windows-PRNG} is
 * refused with {@link IllegalStateException}; that check does not establish entropy quality.
 *
 * <p>Instances are immutable and thread-safe. Experimental: not approved for value-bearing or
 * mainnet use.
 */
public final class G1RangeProver {

    /** Attempts before the prover gives up (spec §7.3). */
    static final int MAX_ATTEMPTS = 8;

    private final Bls12381Provider provider;
    private final boolean proving;

    private G1RangeProver(Bls12381Provider provider, boolean proving) {
        this.provider = provider;
        this.proving = proving;
    }

    /** The prover over the pure-Java provider; it supports proving. */
    public static G1RangeProver pureJava() {
        return PureJava.INSTANCE;
    }

    /**
     * A prover over {@code provider}. The provider's {@code g1SecretScalarMul} is called once on
     * public data ({@code G} and the scalar 1), as {@code G1Pedersen.withProvider} does: an
     * {@link UnsupportedOperationException} means the prover cannot prove; any other exception
     * propagates; a result other than {@code G} (including null) is an {@link IllegalStateException}.
     *
     * @throws NullPointerException  if {@code provider} is null
     * @throws IllegalStateException if the probe returns a point other than {@code G}
     */
    public static G1RangeProver withProvider(Bls12381Provider provider) {
        Objects.requireNonNull(provider, "provider");
        G1Point probe;
        boolean proving;
        try {
            probe = provider.g1SecretScalarMul(BulletproofGenerators.g(), BigInteger.ONE);
            proving = true;
        } catch (UnsupportedOperationException e) {
            probe = null;
            proving = false;
        }
        if (proving && !BulletproofGenerators.g().equals(probe)) {
            throw new IllegalStateException("provider " + provider.id()
                    + " returned a wrong result for a secret-scalar multiplication by 1");
        }
        return new G1RangeProver(provider, proving);
    }

    /** The provider this prover uses. */
    public Bls12381Provider provider() {
        return provider;
    }

    /** Whether the provider offers a secret-scalar G1 multiplication, as decided by {@link #withProvider}. */
    public boolean supportsProving() {
        return proving;
    }

    /**
     * Proves that the value of {@code opening} is below {@code 2^bits}, offline/isolated only.
     *
     * <p>Checks, in order, before any curve work (spec §7.1): nulls; proving supported
     * ({@link UnsupportedOperationException}); {@code bits ∈ {16, 32, 64}} and {@code context} of 1
     * to 1,024 octets ({@code INVALID_CONFIGURATION}); {@code v} and {@code γ} in {@code [0, q)}
     * ({@code NON_CANONICAL_SCALAR}; a {@link G1PedersenOpening} already guarantees it);
     * {@code v < 2^bits} ({@code OUT_OF_RANGE}). Then the nonce source is created
     * ({@link IllegalStateException} if its algorithm is refused), {@code V} is computed, and an
     * identity {@code V} is refused ({@code INVALID_STATEMENT}). The context is copied on entry.
     *
     * @throws NullPointerException          if an argument is null
     * @throws UnsupportedOperationException if this prover does not support proving
     * @throws CommitmentFormatException     with the class of the first refusal
     * @throws IllegalStateException         if the random source is refused, a provider result is
     *                                       invalid, or eight attempts all needed a restart
     */
    public G1RangeProof prove(G1PedersenOpening opening, int bits, byte[] context) {
        Objects.requireNonNull(opening, "opening");
        Objects.requireNonNull(context, "context");
        requireProving();
        byte[] ctx = RangeTranscript.configuredContext(bits, context);
        refusals(opening, bits, ctx);
        return proveChecked(opening.value(), opening.blinding(), bits, ctx, SystemNonceSource.create(), ChallengeTap.NONE);
    }

    /**
     * The test hook of spec §7.5: {@link #prove} with the nonces of {@code nonces}. It accepts a source
     * object only, never a seed; the deterministic source is in the unpublished test fixtures.
     */
    G1RangeProof prove(G1PedersenOpening opening, int bits, byte[] context, NonceSource nonces) {
        Objects.requireNonNull(opening, "opening");
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(nonces, "nonces");
        requireProving();
        byte[] ctx = RangeTranscript.configuredContext(bits, context);
        refusals(opening, bits, ctx);
        return proveChecked(opening.value(), opening.blinding(), bits, ctx, nonces, ChallengeTap.NONE);
    }

    private void requireProving() {
        if (!proving) {
            throw new UnsupportedOperationException("provider " + provider.id()
                    + " offers no secret-scalar G1 multiplication; range proving is unavailable");
        }
    }

    /** Spec §7.1 refusals 1–3, in order. */
    private static void refusals(G1PedersenOpening opening, int bits, byte[] ctx) {
        RangeTranscript.requireConfiguration(bits, ctx);
        BigInteger v = opening.value();
        BigInteger gamma = opening.blinding();
        if (v.signum() < 0 || v.compareTo(RangeMath.Q) >= 0 || gamma.signum() < 0 || gamma.compareTo(RangeMath.Q) >= 0) {
            throw new CommitmentFormatException(CommitmentError.NON_CANONICAL_SCALAR, "opening scalars must be in [0, q)");
        }
        // v is non-negative here, so v < 2^n iff bitLength(v) ≤ n.
        if (v.bitLength() > bits) {
            throw new CommitmentFormatException(CommitmentError.OUT_OF_RANGE, "value must be below 2^" + bits);
        }
    }

    /**
     * The proving algorithm of spec §7.1 (after the refusals) to §7.3, for canonical {@code v},
     * {@code γ} and a valid configuration. Package-private so that a test can force an out-of-range
     * value through it (ADR-0061 I6) and force zero challenges ({@code tap}); the public paths always
     * run the refusals first. It still checks the configuration, and needs canonical {@code v},
     * {@code γ} (the multiplications refuse others). Like the nonce hook, it is a bounded test seam
     * (spec §7.5): a caller must already hold the opening, and can at worst emit a proof that does not
     * verify.
     */
    G1RangeProof proveChecked(BigInteger v, BigInteger gamma, int bits, byte[] ctx, NonceSource nonces,
                              ChallengeTap tap) {
        // Kept even here: no path, public or not, runs with an invalid width or context.
        RangeTranscript.requireConfiguration(bits, ctx);
        G1Point commitment = secretSum(BulletproofGenerators.g(), v, BulletproofGenerators.h(), gamma);
        if (commitment.isInfinity()) {
            throw new CommitmentFormatException(CommitmentError.INVALID_STATEMENT,
                    "the opening commits to the identity; no range proof exists for it");
        }
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            if (attempt > 1) {
                nonces.beforeRestart();
            }
            G1RangeProof proof = attempt(v, gamma, commitment, bits, ctx, nonces, tap);
            if (proof != null) {
                return proof;
            }
        }
        throw new IllegalStateException("range proving needed more than " + MAX_ATTEMPTS + " attempts");
    }

    /** One attempt with fresh nonces; {@code null} if a restart is needed (spec §7.3). */
    private G1RangeProof attempt(BigInteger v, BigInteger gamma, G1Point commitment, int n, byte[] ctx,
                                 NonceSource nonces, ChallengeTap tap) {
        int k = RangeTranscript.rounds(n);
        BigInteger[] aL = new BigInteger[n];
        BigInteger[] aR = new BigInteger[n];
        BigInteger[] sL = new BigInteger[n];
        BigInteger[] sR = new BigInteger[n];
        BigInteger[] l = new BigInteger[n];
        BigInteger[] r = new BigInteger[n];
        BigInteger[] l0 = new BigInteger[n];
        BigInteger[] r0 = new BigInteger[n];
        BigInteger[] r1 = new BigInteger[n];
        try {
            // Nonces, in the order of spec §7.5: α, ρ, s_L, s_R, τ₁, τ₂.
            BigInteger alpha = nonces.next();
            BigInteger rho = nonces.next();
            for (int i = 0; i < n; i++) sL[i] = nonces.next();
            for (int i = 0; i < n; i++) sR[i] = nonces.next();
            BigInteger tau1 = nonces.next();
            BigInteger tau2 = nonces.next();

            for (int i = 0; i < n; i++) {
                aL[i] = v.testBit(i) ? BigInteger.ONE : BigInteger.ZERO;
                aR[i] = RangeMath.sub(aL[i], BigInteger.ONE);
            }
            G1Point a = vectorCommitment(alpha, aL, aR, n);
            G1Point s = vectorCommitment(rho, sL, sR, n);
            if (a.isInfinity() || s.isInfinity()) {
                return null;
            }

            RangeTranscript t = RangeTranscript.start(n, ctx, commitment);
            BigInteger y = tapped(tap, Challenge.Y, t.absorbPointsSqueeze(a, s));
            BigInteger z = tapped(tap, Challenge.Z, t.challenge());
            if (y.signum() == 0 || z.signum() == 0) {
                return null;
            }

            BigInteger z2 = RangeMath.mul(z, z);
            BigInteger[] yPow = RangeMath.powers(y, n);
            BigInteger twoPow = BigInteger.ONE;
            for (int i = 0; i < n; i++) {
                l0[i] = RangeMath.sub(aL[i], z);
                r0[i] = RangeMath.add(RangeMath.mul(yPow[i], RangeMath.add(aR[i], z)), RangeMath.mul(z2, twoPow));
                r1[i] = RangeMath.mul(yPow[i], sR[i]);
                twoPow = twoPow.shiftLeft(1);
            }
            BigInteger t1 = RangeMath.add(RangeMath.inner(l0, r1), RangeMath.inner(sL, r0));
            BigInteger t2 = RangeMath.inner(sL, r1);
            G1Point bigT1 = secretSum(BulletproofGenerators.g(), t1, BulletproofGenerators.h(), tau1);
            G1Point bigT2 = secretSum(BulletproofGenerators.g(), t2, BulletproofGenerators.h(), tau2);
            if (bigT1.isInfinity() || bigT2.isInfinity()) {
                return null;
            }
            BigInteger x = tapped(tap, Challenge.X, t.absorbPointsSqueeze(bigT1, bigT2));
            if (x.signum() == 0) {
                return null;
            }

            for (int i = 0; i < n; i++) {
                l[i] = RangeMath.add(l0[i], RangeMath.mul(x, sL[i]));
                r[i] = RangeMath.add(r0[i], RangeMath.mul(x, r1[i]));
            }
            BigInteger tHat = RangeMath.inner(l, r);
            BigInteger tauX = RangeMath.add(RangeMath.add(RangeMath.mul(tau2, RangeMath.mul(x, x)), RangeMath.mul(tau1, x)),
                    RangeMath.mul(z2, gamma));
            BigInteger mu = RangeMath.add(alpha, RangeMath.mul(rho, x));
            t.absorbScalars(tHat, tauX, mu);
            BigInteger xu = tapped(tap, Challenge.XU, t.challenge());
            if (xu.signum() == 0) {
                return null;
            }

            InnerProduct ipa = innerProduct(t, y, xu, l, r, n, k, tap);
            if (ipa == null) {
                return null;
            }
            return G1RangeProof.of(n, a, s, bigT1, bigT2, tHat, tauX, mu, ipa.l, ipa.r, ipa.a, ipa.b);
        } finally {
            // Best effort: BigInteger values cannot be wiped, but the arrays stop referencing them.
            for (BigInteger[] secret : new BigInteger[][] {aL, aR, sL, sR, l, r, l0, r0, r1}) {
                Arrays.fill(secret, null);
            }
        }
    }

    /**
     * {@code [blind]·H + Σ_i [left_i]·G_i + Σ_i [right_i]·H_i} over all {@code 2n} generators, through
     * the secret-scalar method only (spec §7.4).
     */
    private G1Point vectorCommitment(BigInteger blind, BigInteger[] left, BigInteger[] right, int n) {
        G1Point sum = secretMul(BulletproofGenerators.h(), blind);
        for (int i = 0; i < n; i++) {
            sum = sum.add(secretMul(BulletproofGenerators.gVec(i), left[i]));
        }
        for (int i = 0; i < n; i++) {
            sum = sum.add(secretMul(BulletproofGenerators.hVec(i), right[i]));
        }
        return valid(sum);
    }

    /** {@code [x]·P + [y]·Q} through the secret-scalar method only. */
    private G1Point secretSum(G1Point p, BigInteger x, G1Point q, BigInteger y) {
        return valid(secretMul(p, x).add(secretMul(q, y)));
    }

    /**
     * One secret-scalar multiplication by a reduced scalar. The result must be on the curve (field
     * arithmetic only); the full subgroup check runs once on the public sum, as in
     * {@code G1Pedersen.generate}.
     */
    private G1Point secretMul(G1Point point, BigInteger scalar) {
        G1Point result = provider.g1SecretScalarMul(point, scalar);
        if (result == null || !result.isOnCurve()) {
            throw new IllegalStateException("provider " + provider.id() + " returned an invalid G1 point");
        }
        return result;
    }

    private G1Point valid(G1Point sum) {
        if (!sum.isValid()) {
            throw new IllegalStateException("provider " + provider.id() + " returned an invalid G1 point");
        }
        return sum;
    }

    /** The provider's public multiplication; a null result is a provider fault. */
    private G1Point publicMul(G1Point point, BigInteger scalar) {
        G1Point result = provider.g1ScalarMul(point, scalar);
        if (result == null) {
            throw new IllegalStateException("provider " + provider.id() + " returned null");
        }
        return result;
    }

    /** The inner-product argument (spec §7.2, Protocols 1 and 2); {@code null} if a restart is needed. */
    private InnerProduct innerProduct(RangeTranscript t, BigInteger y, BigInteger xu, BigInteger[] l, BigInteger[] r,
                                      int n, int k, ChallengeTap tap) {
        G1Point[] g = new G1Point[n];
        G1Point[] h = new G1Point[n];
        BigInteger yInv = RangeMath.inv(y);
        BigInteger yInvPow = BigInteger.ONE;
        for (int i = 0; i < n; i++) {
            g[i] = BulletproofGenerators.gVec(i);
            h[i] = publicMul(BulletproofGenerators.hVec(i), yInvPow);
            yInvPow = RangeMath.mul(yInvPow, yInv);
        }
        G1Point u = publicMul(BulletproofGenerators.u(), xu);
        BigInteger[] a = l.clone();
        BigInteger[] b = r.clone();
        G1Point[] ls = new G1Point[k];
        G1Point[] rs = new G1Point[k];
        try {
            int len = n;
            for (int j = 0; j < k; j++) {
                int half = len / 2;
                BigInteger cL = RangeMath.inner(a, 0, b, half, half);
                BigInteger cR = RangeMath.inner(a, half, b, 0, half);
                G1Point lj = publicMul(u, cL);
                G1Point rj = publicMul(u, cR);
                for (int i = 0; i < half; i++) {
                    lj = lj.add(publicMul(g[half + i], a[i])).add(publicMul(h[i], b[half + i]));
                    rj = rj.add(publicMul(g[i], a[half + i])).add(publicMul(h[half + i], b[i]));
                }
                if (lj.isInfinity() || rj.isInfinity()) {
                    return null;
                }
                BigInteger x = tapped(tap, Challenge.XJ, t.absorbPointsSqueeze(lj, rj));
                if (x.signum() == 0) {
                    return null;
                }
                BigInteger xInv = RangeMath.inv(x);
                // The folded generators are needed only by a later round.
                boolean last = j == k - 1;
                for (int i = 0; i < half; i++) {
                    if (!last) {
                        g[i] = publicMul(g[i], xInv).add(publicMul(g[half + i], x));
                        h[i] = publicMul(h[i], x).add(publicMul(h[half + i], xInv));
                    }
                    a[i] = RangeMath.add(RangeMath.mul(x, a[i]), RangeMath.mul(xInv, a[half + i]));
                    b[i] = RangeMath.add(RangeMath.mul(xInv, b[i]), RangeMath.mul(x, b[half + i]));
                }
                ls[j] = lj;
                rs[j] = rj;
                len = half;
            }
            return new InnerProduct(ls, rs, a[0], b[0]);
        } finally {
            Arrays.fill(a, null);
            Arrays.fill(b, null);
        }
    }

    private record InnerProduct(G1Point[] l, G1Point[] r, BigInteger a, BigInteger b) {
    }

    /** Which challenge a {@link ChallengeTap} sees. */
    enum Challenge {
        Y, Z, X, XU, XJ
    }

    /**
     * A test seam over the prover's challenges (ADR-0061 I4): tests force a zero challenge to exercise
     * the restart rule. It can only force zero, so it can only make the prover restart; the public
     * paths always use {@link #NONE} (spec §7.5).
     */
    interface ChallengeTap {
        ChallengeTap NONE = which -> false;

        /** {@code true} to replace this challenge by zero. It can force zero only, never another value. */
        boolean forceZero(Challenge which);
    }

    private static BigInteger tapped(ChallengeTap tap, Challenge which, BigInteger value) {
        return tap.forceZero(which) ? BigInteger.ZERO : value;
    }

    private static final class PureJava {
        static final G1RangeProver INSTANCE = withProvider(PureJavaBls12381Provider.INSTANCE);
    }
}
