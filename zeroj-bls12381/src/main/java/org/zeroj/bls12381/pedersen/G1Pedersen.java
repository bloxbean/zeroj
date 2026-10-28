package org.zeroj.bls12381.pedersen;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.PureJavaBls12381Provider;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Entry point of the BLS12-381 G1 Pedersen profiles {@code pedersen-bls12-381-g1-v1} (scalar) and
 * {@code pedersen-bls12-381-g1-bytes-v1} (bytes), normatively specified in
 * {@code docs/specs/pedersen-bls12-381-g1-v1.md} (ADR-0060):
 * {@code C(m, r) = [m]·G + [r]·H}, and {@code C = [HashBytesToScalarG1(B)]·G + [r]·H}.
 *
 * <p>Experimental: not approved for value-bearing or mainnet use.
 *
 * <h2>Providers</h2>
 * An instance is bound to one {@link Bls12381Provider}; {@link #pureJava()} uses the pure-Java
 * provider. Point decoding is shared code and identical for every provider. Generation uses only the
 * provider's {@code g1SecretScalarMul}, never a public multiplication; {@link #withProvider} decides
 * once, on public data, whether the provider offers it (spec §8). Verification uses only public
 * operations and works with every provider; its verdict trusts the provider's public multiplication,
 * as the provider is trusted code. Instances are immutable and thread-safe.
 *
 * <h2>Generation is offline/isolated only</h2>
 * Neither provider is constant-time: the pure-Java ladders split each scalar and run a fixed
 * operation schedule (ADR-0062 D1), and generation splits the committed value so small values run
 * the same operations as random ones, but data-dependent branches and {@link BigInteger} arithmetic
 * remain, and the blst binding documents no side-channel contract. The byte mapping, the blinding sampler and the curve arithmetic run on
 * secrets with variable-time code. Generate commitments offline or inside an isolated process that
 * performs the complete operation (spec §7, {@code commitment-profiles-v1} §6.2).
 *
 * <h2>Disclosed verification (class V1)</h2>
 * The {@code verify*} methods recompute the commitment with public, variable-time arithmetic. Use
 * them only where the opening is already public or no party from whom it is still secret can
 * observe the verifier's timing; otherwise recompute with {@code commit*} offline and compare.
 *
 * <h2>Strict paths</h2>
 * No scalar is reduced; every argument check precedes any curve operation on the inputs, digest
 * acquisition or stream read; every rejection of an argument is a {@link CommitmentFormatException}
 * carrying its error class. Each {@link BigInteger} argument is snapshotted once to a plain
 * {@code BigInteger} after the null checks, and only the snapshot is checked and used. The check
 * order of each method is that of spec §8. {@code BigInteger} values cannot be wiped from memory.
 */
public final class G1Pedersen {

    /** Octets drawn per blinding by {@link #randomBlinding(SecureRandom)}. */
    static final int BLINDING_SAMPLE_BYTES = 64;

    private final Bls12381Provider provider;
    private final boolean generation;

    private G1Pedersen(Bls12381Provider provider, boolean generation) {
        this.provider = provider;
        this.generation = generation;
    }

    /** The instance over the pure-Java provider; it supports generation. */
    public static G1Pedersen pureJava() {
        return PureJava.INSTANCE;
    }

    /**
     * An instance over {@code provider}. The provider's {@code g1SecretScalarMul} is called once on
     * public data ({@code G} and the scalar 1): an {@link UnsupportedOperationException} means the
     * instance does not support generation; any other exception propagates; a result other than
     * {@code G} (including null) is an {@link IllegalStateException}. The probe never sees a
     * caller's value and is a capability check, not a known-answer test.
     *
     * @throws NullPointerException  if {@code provider} is null
     * @throws IllegalStateException if the probe returns a point other than {@code G}
     */
    public static G1Pedersen withProvider(Bls12381Provider provider) {
        Objects.requireNonNull(provider, "provider");
        boolean generation;
        G1Point probe;
        try {
            probe = provider.g1SecretScalarMul(G1PedersenBases.G, BigInteger.ONE);
            generation = true;
        } catch (UnsupportedOperationException e) {
            probe = null;
            generation = false;
        }
        if (generation && !G1PedersenBases.G.equals(probe)) {
            throw new IllegalStateException("provider " + provider.id()
                    + " returned a wrong result for a secret-scalar multiplication by 1");
        }
        return new G1Pedersen(provider, generation);
    }

    /** The provider this instance uses. */
    public Bls12381Provider provider() {
        return provider;
    }

    /** Whether the provider offers a secret-scalar G1 multiplication, as decided by {@link #withProvider}. */
    public boolean supportsGeneration() {
        return generation;
    }

    /**
     * Samples a blinding uniform on {@code [0, q)} up to statistical distance below {@code 2^-257}:
     * {@value #BLINDING_SAMPLE_BYTES} octets from {@code random}, read unsigned big-endian and reduced
     * mod {@code q} (spec §7). The buffer is wiped on every exit; an entropy failure propagates.
     *
     * <p>Same execution restriction as generation: the reduction is variable-time arithmetic on a
     * secret, so sample offline or in an isolated process.
     *
     * @throws NullPointerException if {@code random} is null
     */
    public static BigInteger randomBlinding(SecureRandom random) {
        Objects.requireNonNull(random, "random");
        byte[] sample = new byte[BLINDING_SAMPLE_BYTES];
        try {
            random.nextBytes(sample);
            return new BigInteger(1, sample).mod(G1PedersenStrict.Q);
        } finally {
            Arrays.fill(sample, (byte) 0);
        }
    }

    // ---- pedersen-bls12-381-g1-v1 ----

    /**
     * Commits to a canonical scalar: {@code C = [value]·G + [blinding]·H}, offline/isolated only.
     *
     * <p>Checks, in order: nulls; generation supported ({@link UnsupportedOperationException});
     * snapshots; {@code value}, then {@code blinding}, in {@code [0, q)}
     * ({@code NON_CANONICAL_SCALAR}); then generation through the provider's secret-scalar method.
     *
     * @throws NullPointerException          if an argument is null
     * @throws UnsupportedOperationException if this instance does not support generation
     * @throws CommitmentFormatException     ({@code NON_CANONICAL_SCALAR}) if a scalar is not canonical
     */
    public G1PedersenCommitment commitScalar(BigInteger value, BigInteger blinding) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        requireGeneration();
        BigInteger m = G1PedersenStrict.snapshot(value);
        BigInteger r = G1PedersenStrict.snapshot(blinding);
        G1PedersenStrict.requireCanonical(m, "value");
        G1PedersenStrict.requireCanonical(r, "blinding");
        return new G1PedersenCommitment(generate(m, r));
    }

    /**
     * Strict disclosed verification (class V1): {@code true} iff
     * {@code commitment == [value]·G + [blinding]·H}.
     *
     * <p>Checks, in order: nulls; snapshots; {@code value}, then {@code blinding}, in {@code [0, q)}
     * ({@code NON_CANONICAL_SCALAR}); then the equation ({@code false} on mismatch).
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException ({@code NON_CANONICAL_SCALAR}) if a scalar is not canonical
     */
    public boolean verifyScalar(G1PedersenCommitment commitment, BigInteger value, BigInteger blinding) {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        BigInteger m = G1PedersenStrict.snapshot(value);
        BigInteger r = G1PedersenStrict.snapshot(blinding);
        G1PedersenStrict.requireCanonical(m, "value");
        G1PedersenStrict.requireCanonical(r, "blinding");
        return recompute(m, r).equals(commitment.point());
    }

    /**
     * {@link #verifyScalar(G1PedersenCommitment, BigInteger, BigInteger)} with the application amount
     * bound (check 2): additionally requires {@code value < 2^amountBits}.
     *
     * <p>Checks, in order: nulls; {@code amountBits ∈ [1, 254]} ({@code INVALID_CONFIGURATION});
     * snapshots; {@code value}, then {@code blinding}, in {@code [0, q)} ({@code NON_CANONICAL_SCALAR});
     * {@code value < 2^amountBits} ({@code OUT_OF_RANGE}); then the equation. The bound never applies
     * to the blinding.
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException with the class of the first failure
     */
    public boolean verifyScalar(G1PedersenCommitment commitment, BigInteger value, BigInteger blinding,
                                int amountBits) {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        G1PedersenStrict.requireBits(amountBits, G1PedersenStrict.MAX_BITS, "amountBits");
        BigInteger m = G1PedersenStrict.snapshot(value);
        BigInteger r = G1PedersenStrict.snapshot(blinding);
        G1PedersenStrict.requireCanonical(m, "value");
        G1PedersenStrict.requireCanonical(r, "blinding");
        // m is non-negative here, so m < 2^k iff bitLength(m) ≤ k.
        if (m.bitLength() > amountBits) {
            throw new CommitmentFormatException(CommitmentError.OUT_OF_RANGE,
                    "value must be below 2^" + amountBits);
        }
        return recompute(m, r).equals(commitment.point());
    }

    // ---- pedersen-bls12-381-g1-bytes-v1 ----

    /**
     * Commits to the exact octets of {@code payload}:
     * {@code C = [HashBytesToScalarG1(payload)]·G + [blinding]·H}, offline/isolated only.
     *
     * <p>Every octet is significant and an empty array is a valid payload. The payload is read once
     * and not copied or retained; the caller must not modify it during the call.
     *
     * <p>Checks, in order: nulls; generation supported ({@link UnsupportedOperationException});
     * snapshot; {@code blinding ∈ [0, q)} ({@code NON_CANONICAL_SCALAR}); then hashing and generation.
     *
     * @throws NullPointerException          if an argument is null
     * @throws UnsupportedOperationException if this instance does not support generation
     * @throws CommitmentFormatException     ({@code NON_CANONICAL_SCALAR}) if {@code blinding} is not canonical
     * @throws IllegalStateException         if SHA-256 is unavailable
     */
    public G1PedersenBytesCommitment commitBytes(byte[] payload, BigInteger blinding) {
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(blinding, "blinding");
        requireGeneration();
        BigInteger r = G1PedersenStrict.canonical(blinding, "blinding");
        return new G1PedersenBytesCommitment(generate(G1PedersenBytesHash.hashToScalar(payload), r));
    }

    /**
     * {@link #commitBytes(byte[], BigInteger)} over a stream that must hold exactly {@code length}
     * octets, read once through a bounded buffer (spec §5.1). After {@code length} octets one probe
     * read checks for end of stream: an extra octet (never hashed), or end of stream before
     * {@code length}, fails with {@link IOException} and produces no commitment. At most
     * {@code length + 1} octets are read. The stream is never closed, reset or retried.
     *
     * <p>Checks, in order: nulls; generation supported; snapshot; {@code blinding ∈ [0, q)}
     * ({@code NON_CANONICAL_SCALAR}); {@code length ∈ [0, 2^61 − 256]} ({@code LENGTH_OUT_OF_RANGE});
     * then reading, hashing and generation.
     *
     * @throws IOException on truncation, excess input or a read failure
     */
    public G1PedersenBytesCommitment commitBytes(InputStream payload, long length, BigInteger blinding)
            throws IOException {
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(blinding, "blinding");
        requireGeneration();
        BigInteger r = G1PedersenStrict.canonical(blinding, "blinding");
        requirePayloadBound(length, "length");
        return new G1PedersenBytesCommitment(generate(G1PedersenBytesHash.hashToScalar(payload, length, true), r));
    }

    /**
     * {@link #commitBytes(byte[], BigInteger)} over a stream of unknown length, read to end of stream
     * in one pass. It may hold at most {@code maxBytes} octets; if it holds more, the call fails with
     * {@link IOException} after reading {@code maxBytes + 1} octets. The same octets give the same
     * commitment as the array and declared-length forms.
     *
     * <p>Checks, in order: nulls; generation supported; snapshot; {@code blinding ∈ [0, q)}
     * ({@code NON_CANONICAL_SCALAR}); {@code maxBytes ∈ [0, 2^61 − 256]} ({@code LENGTH_OUT_OF_RANGE});
     * then reading, hashing and generation.
     *
     * @throws IOException on excess input or a read failure
     */
    public G1PedersenBytesCommitment commitBytesToEnd(InputStream payload, long maxBytes, BigInteger blinding)
            throws IOException {
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(blinding, "blinding");
        requireGeneration();
        BigInteger r = G1PedersenStrict.canonical(blinding, "blinding");
        requirePayloadBound(maxBytes, "maxBytes");
        return new G1PedersenBytesCommitment(generate(G1PedersenBytesHash.hashToScalar(payload, maxBytes, false), r));
    }

    /**
     * Verifies a <b>disclosed</b> byte opening (class V1): {@code true} iff
     * {@code commitment == [HashBytesToScalarG1(payload)]·G + [blinding]·H}. A {@code true} result
     * says the opening matches the point, not under which profile or in which context it was issued.
     *
     * <p>Checks, in order: nulls; snapshot; {@code blinding ∈ [0, q)} ({@code NON_CANONICAL_SCALAR});
     * then hashing and the equation.
     */
    public boolean verifyBytes(G1PedersenBytesCommitment commitment, byte[] payload, BigInteger blinding) {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(blinding, "blinding");
        BigInteger r = G1PedersenStrict.canonical(blinding, "blinding");
        return recompute(G1PedersenBytesHash.hashToScalar(payload), r).equals(commitment.point());
    }

    /**
     * {@link #verifyBytes(G1PedersenBytesCommitment, byte[], BigInteger)} over a stream holding exactly
     * {@code length} octets, with the stream rules of {@link #commitBytes(InputStream, long, BigInteger)}.
     * Truncation, excess input and read failures throw {@link IOException}; they never return
     * {@code true}. Error classes: {@code NON_CANONICAL_SCALAR}, then {@code LENGTH_OUT_OF_RANGE}.
     */
    public boolean verifyBytes(G1PedersenBytesCommitment commitment, InputStream payload, long length,
                               BigInteger blinding) throws IOException {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(blinding, "blinding");
        BigInteger r = G1PedersenStrict.canonical(blinding, "blinding");
        requirePayloadBound(length, "length");
        return recompute(G1PedersenBytesHash.hashToScalar(payload, length, true), r).equals(commitment.point());
    }

    /**
     * {@link #verifyBytes(G1PedersenBytesCommitment, byte[], BigInteger)} over a stream read to end of
     * stream, holding at most {@code maxBytes} octets, with the stream rules of
     * {@link #commitBytesToEnd(InputStream, long, BigInteger)}. Error classes:
     * {@code NON_CANONICAL_SCALAR}, then {@code LENGTH_OUT_OF_RANGE}.
     */
    public boolean verifyBytesToEnd(G1PedersenBytesCommitment commitment, InputStream payload, long maxBytes,
                                    BigInteger blinding) throws IOException {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(blinding, "blinding");
        BigInteger r = G1PedersenStrict.canonical(blinding, "blinding");
        requirePayloadBound(maxBytes, "maxBytes");
        return recompute(G1PedersenBytesHash.hashToScalar(payload, maxBytes, false), r).equals(commitment.point());
    }

    // ---- internals ----

    private void requireGeneration() {
        if (!generation) {
            throw new UnsupportedOperationException("provider " + provider.id()
                    + " offers no secret-scalar G1 multiplication; G1 Pedersen generation is unavailable");
        }
    }

    private static void requirePayloadBound(long bound, String name) {
        if (bound < 0 || bound > G1PedersenBytesHash.MAX_PAYLOAD_BYTES) {
            throw new CommitmentFormatException(CommitmentError.LENGTH_OUT_OF_RANGE,
                    name + " must be in [0, " + G1PedersenBytesHash.MAX_PAYLOAD_BYTES + "]");
        }
    }

    /** Randomness for the split of the committed value in {@link #generate}. */
    private static final ThreadLocal<SecureRandom> SPLIT_RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    /**
     * {@code [x]·G + [r]·H} through the provider's secret-scalar method only, for canonical
     * {@code x, r}.
     *
     * <p>The committed value is split (ADR-0062 D1 r4, F12): with a fresh uniform {@code t},
     * {@code C = ([x − t]·G + [r]·H) + [t]·G}. Each multiplication then sees a uniform scalar, and no
     * intermediate point depends on {@code x} being small: computing {@code [x]·G} directly would make
     * it the identity for {@code x = 0}, and the following affine addition would return early. The
     * result is the same point; generation costs three secret multiplications instead of two. A
     * caller-chosen blinding {@code r = 0} still yields an identity {@code [r]·H} (such a commitment
     * hides nothing anyway).</p>
     *
     * <p>Each provider result must be a finite-or-identity point on the curve (field arithmetic
     * only), and the public sum must be a valid subgroup point. So a misbehaving provider can never
     * produce a commitment that strict decoding would reject, nor off-curve points that cancel; the
     * full subgroup check runs once, on the public sum rather than on the secret-derived components.
     * A valid but wrong point is not detectable here; provider parity rests on the vectors and the
     * parity tests.</p>
     */
    private G1Point generate(BigInteger x, BigInteger r) {
        BigInteger t = randomBlinding(SPLIT_RANDOM.get());
        BigInteger xMinusT = x.subtract(t).mod(G1PedersenStrict.Q);
        G1Point a = onCurve(provider.g1SecretScalarMul(G1PedersenBases.G, G1PedersenStrict.requireMultipliable(xMinusT)));
        G1Point rh = onCurve(provider.g1SecretScalarMul(G1PedersenBases.H, G1PedersenStrict.requireMultipliable(r)));
        G1Point tg = onCurve(provider.g1SecretScalarMul(G1PedersenBases.G, G1PedersenStrict.requireMultipliable(t)));
        G1Point sum = a.add(rh).add(tg);
        if (!sum.isValid()) {
            throw new IllegalStateException("provider " + provider.id() + " returned an invalid G1 point");
        }
        return sum;
    }

    /**
     * {@code [x]·G + [r]·H} with the provider's public multiplication, for canonical {@code x, r}.
     * The verdict trusts the provider's results (the provider is trusted code, spec §8); they are
     * compared with a strictly decoded commitment, never returned.
     */
    private G1Point recompute(BigInteger x, BigInteger r) {
        G1Point xg = result(provider.g1ScalarMul(G1PedersenBases.G, G1PedersenStrict.requireMultipliable(x)));
        G1Point rh = result(provider.g1ScalarMul(G1PedersenBases.H, G1PedersenStrict.requireMultipliable(r)));
        return xg.add(rh);
    }

    private G1Point result(G1Point point) {
        if (point == null) {
            throw new IllegalStateException("provider " + provider.id() + " returned null");
        }
        return point;
    }

    private G1Point onCurve(G1Point point) {
        if (!result(point).isOnCurve()) {
            throw new IllegalStateException("provider " + provider.id() + " returned a point off the curve");
        }
        return point;
    }

    private static final class PureJava {
        static final G1Pedersen INSTANCE = withProvider(PureJavaBls12381Provider.INSTANCE);
    }
}
