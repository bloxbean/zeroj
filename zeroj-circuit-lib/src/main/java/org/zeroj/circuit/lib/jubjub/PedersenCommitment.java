package org.zeroj.circuit.lib.jubjub;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Off-circuit Pedersen commitment over Jubjub ({@code pedersen-jubjub-v1}, normatively
 * specified in {@code docs/specs/pedersen-jubjub-v1.md}):
 * {@code C(v, r) = [v]·G + [r]·H}
 *
 * <p>G is {@link JubjubPoint#SUBGROUP_GENERATOR}. H is the first Jubjub
 * subgroup point derived deterministically from a domain-separated Poseidon
 * hash (see {@link #H} below). Because H is produced by a random oracle
 * output with no known discrete-log relation to G, Pedersen commitments
 * using (G, H) are <b>binding</b>. Hiding comes from the uniformly random
 * blinding scalar {@code r}.
 *
 * <h2>Domain separation</h2>
 * H is derived from the UTF-8 byte string {@code "zeroj.pedersen.v1.H"}
 * hashed via Poseidon over BLS12-381 (ADR-0015 preset). The derivation is
 * try-and-increment: hash the domain tag, reduce to a field element, check
 * whether that value is a valid v-coordinate on Jubjub; if not, increment
 * a counter and rehash. The first successful hit is taken, cofactor-cleared,
 * and cached.
 *
 * <h2>Caveats</h2>
 * <ul>
 *   <li>This implementation is deterministic — any two correct runs produce
 *       the same H.</li>
 *   <li>The domain tag {@code "zeroj.pedersen.v1.H"} is a protocol version.
 *       Changing it invalidates all commitments produced under the previous
 *       H; treat as a breaking change.</li>
 *   <li>H has <b>no known discrete log</b> w.r.t. G. If a future
 *       implementation hard-codes {@code H = [h]·G} for known h, binding is
 *       broken. The derivation recipe above avoids this trap by construction.</li>
 *   <li><b>Commitment generation is not constant-time — generate offline or in an isolated
 *       process.</b> See the section below; this is a restriction on execution, not on the
 *       scheme.</li>
 * </ul>
 *
 * <h2>Side-channel restriction on generation (ADR-0038)</h2>
 * {@link #commit(BigInteger, BigInteger)} runs both secret scalars through a fixed
 * 316-iteration, multiple-of-l-blinded schedule. The historical loop-bound, zero early-return,
 * Hamming-weight operation-count and raw trailing-zero/identity-duration channels are therefore
 * removed or blinded at the call site.
 *
 * <p>This is still <b>not constant-time</b>. The blinding reduction, secret branch and all
 * coordinate arithmetic use variable-time {@link BigInteger}; JVM/JIT/GC behaviour is outside
 * the implementation's control. Generation must remain offline or inside a reviewed isolated
 * boundary that performs the complete operation.
 *
 * <p><b>Hiding and binding of the commitment itself are unaffected.</b> Perfect hiding is an
 * information-theoretic property of the commitment string; a timing channel during generation
 * sits outside that model and does not weaken it. Nor does this expose the Schnorr/Hidden
 * Number Problem relation that makes the analogous leak in {@link EdDSAJubjub#sign} a
 * key-recovery concern — there is no published practical value-recovery attack here.
 *
 * <p>The in-circuit gadgets ({@code InCircuitPedersen}, {@code ZkPedersen}) are unaffected:
 * they emit constraints and perform no secret-dependent host arithmetic.
 *
 * <p><b>Do not expose secret-bearing commitment generation to an untrusted timing observer or a
 * co-resident adversary.</b> {@link #verify(JubjubPoint, BigInteger, BigInteger)} is different:
 * an opening supplied for verification is disclosed to that verifier, so it deliberately uses the
 * faster variable-length public-scalar path. Disclosed is not public: run it on variable-time
 * arithmetic only if the opening is already public, or no party from whom it is still secret can
 * observe the verifier's timing; otherwise verify offline or in an isolated process
 * ({@code commitment-profiles-v1} §6.2, ADR-0059 A2).
 *
 * <h2>Strict entry points (ADR-0059)</h2>
 * {@link #commitScalar}, {@link #verifyScalar} and {@link #decode} implement the strict paths of
 * {@code docs/specs/commitment-profiles-v1.md} §12.3: no scalar is reduced, and every rejection is a
 * {@link CommitmentFormatException} carrying its error class. The legacy {@link #commit} and
 * {@link #verify} keep reducing their inputs mod {@code l}.
 *
 * @see <a href="../../../../../../../../../docs/adr/0038-jubjub-dsl-remediation-plan.md">ADR-0038</a>
 */
public final class PedersenCommitment {

    private PedersenCommitment() {}

    /** Domain tag for the second base derivation. Must not change. */
    public static final String H_DOMAIN_TAG = "zeroj.pedersen.v1.H";

    /**
     * Second Pedersen base, derived from {@link #H_DOMAIN_TAG} via a
     * deterministic Poseidon-based try-and-increment. The discrete log of
     * H w.r.t. {@link JubjubPoint#SUBGROUP_GENERATOR} is unknown.
     */
    public static final JubjubPoint H = deriveSecondBase();

    /**
     * Commits to {@code v} with blinding {@code r}:
     * {@code C(v, r) = [v]·G + [r]·H}.
     *
     * <p><b>Binding is to the residue {@code value mod l}, not to the integer.</b> {@code G}
     * has order {@code l}, so {@code [v]·G} depends only on {@code v mod l} and
     * {@code commit(v, r)} equals {@code commit(v + l, r)}. Both inputs are canonicalised here
     * for that reason. An application that needs commitments to distinguish integers beyond
     * that range must range-bound them itself.
     *
     * <p><b>Hiding requires a uniformly random blinding scalar</b> drawn from {@code [0, l)}.
     * A predictable, reused, or low-entropy {@code r} forfeits it.
     *
     * <p><b>Best-effort, not constant-time.</b> Both legs use a freshly multiple-of-l-blinded
     * scalar and a fixed 316-iteration add/double schedule. Residual channels remain: the
     * {@code mod} reductions, branch selection and all {@link BigInteger} arithmetic are
     * variable-time. Generate offline or in an isolated process. The commitment's hiding and
     * binding are unaffected either way — the restriction is on execution.
     *
     * @param value    committed value (typically small; bound as {@code value mod l})
     * @param blinding uniformly random blinding scalar (required for hiding)
     * @return a Jubjub point representing the commitment
     */
    public static JubjubPoint commit(BigInteger value, BigInteger blinding) {
        BigInteger[] scalars = canonicalScalars(value, blinding);
        BigInteger v = scalars[0];
        BigInteger r = scalars[1];
        JubjubPoint vG = JubjubPoint.SUBGROUP_GENERATOR.scalarMulSecretBlindedBestEffort(v);
        JubjubPoint rH = H.scalarMulSecretBlindedBestEffort(r);
        return vG.add(rH).normalized();
    }

    /**
     * Strict generation for {@code pedersen-jubjub-v1} ({@code commitment-profiles-v1} §12.3):
     * {@code C = [value]·G + [blinding]·H} with both scalars already canonical.
     *
     * <p>Checks, in order: nulls; {@code value} in {@code [0, l)}; {@code blinding} in
     * {@code [0, l)} ({@code NON_CANONICAL_SCALAR}). Nothing is reduced, and invalid input does no
     * curve work. Generation then runs through the same two blinded fixed schedules as
     * {@link #commit}, under the same execution restriction: offline or in an isolated process.
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException ({@code NON_CANONICAL_SCALAR}) if a scalar is not canonical
     */
    public static PedersenScalarCommitment commitScalar(BigInteger value, BigInteger blinding) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        BigInteger m = PedersenStrict.canonical(value, "value");
        BigInteger r = PedersenStrict.canonical(blinding, "blinding");
        return new PedersenScalarCommitment(commit(m, r));
    }

    /**
     * Strict disclosed verification (class V1, {@code commitment-profiles-v1} §6.2, §12.3):
     * {@code true} iff {@code commitment == [value]·G + [blinding]·H}.
     *
     * <p>Checks, in order: nulls; {@code value}, then {@code blinding}, in {@code [0, l)}
     * ({@code NON_CANONICAL_SCALAR}); then the equation. Uses the variable-time public-scalar path:
     * <b>only</b> where the opening is already public or no party from whom it is still secret can
     * observe this verifier's timing. To check an opening that must stay private, recompute with
     * {@link #commitScalar} offline and compare encodings (class V2).
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException ({@code NON_CANONICAL_SCALAR}) if a scalar is not canonical
     */
    public static boolean verifyScalar(PedersenScalarCommitment commitment, BigInteger value, BigInteger blinding) {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        BigInteger m = PedersenStrict.canonical(value, "value");
        BigInteger r = PedersenStrict.canonical(blinding, "blinding");
        return verify(commitment.point(), m, r);
    }

    /** Largest amount-bound width for Jubjub: {@code ⌊log₂ l⌋} ({@code commitment-profiles-v1} §7). */
    static final int MAX_AMOUNT_BITS = JubjubCurve.SUBGROUP_ORDER.bitLength() - 1;

    /**
     * {@link #verifyScalar(PedersenScalarCommitment, BigInteger, BigInteger)} with the application
     * amount bound (check 2): additionally requires {@code value < 2^amountBits}.
     *
     * <p>Checks, in order: nulls; {@code amountBits} in {@code [1, 251]}
     * ({@code INVALID_CONFIGURATION}); {@code value}, then {@code blinding}, in {@code [0, l)}
     * ({@code NON_CANONICAL_SCALAR}); {@code value < 2^amountBits} ({@code OUT_OF_RANGE}); then the
     * equation. The bound may reject a valid residue; it never applies to the blinding.
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException with the class of the first failure
     */
    public static boolean verifyScalar(PedersenScalarCommitment commitment, BigInteger value, BigInteger blinding,
                                       int amountBits) {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        if (amountBits < 1 || amountBits > MAX_AMOUNT_BITS) {
            throw new CommitmentFormatException(CommitmentError.INVALID_CONFIGURATION,
                    "amountBits must be in [1, " + MAX_AMOUNT_BITS + "]");
        }
        BigInteger m = PedersenStrict.canonical(value, "value");
        BigInteger r = PedersenStrict.canonical(blinding, "blinding");
        // m is non-negative here, so m < 2^k iff bitLength(m) ≤ k.
        if (m.bitLength() > amountBits) {
            throw new CommitmentFormatException(CommitmentError.OUT_OF_RANGE,
                    "value must be below 2^" + amountBits);
        }
        return verify(commitment.point(), m, r);
    }

    /** Bytes drawn per blinding by {@link #randomBlinding(SecureRandom)}. */
    static final int BLINDING_SAMPLE_BYTES = 64;

    /**
     * Samples a blinding scalar for {@link #commit(BigInteger, BigInteger)} that is
     * statistically uniform on {@code [0, l)}.
     *
     * <p>Draws {@value #BLINDING_SAMPLE_BYTES} bytes from {@code random}, reads them as an
     * unsigned big-endian integer and reduces mod {@code l}. The statistical distance from
     * uniform is at most {@code l / 2^512 < 2^-259} — the same width Zcash's {@code ToScalar}
     * uses ({@code docs/specs/pedersen-jubjub-v1.md} §3.1, ADR-0051 D2).
     *
     * <p><b>Same execution restriction as {@link #commit}.</b> The reduction is variable-time
     * {@link BigInteger} arithmetic on a secret. Sample offline or inside an isolated process,
     * exactly as for commitment generation (ADR-0038). The intermediate byte array is wiped;
     * {@code BigInteger} copies cannot be.
     *
     * @param random a cryptographically secure source; the caller owns its seeding
     * @return a blinding scalar in {@code [0, l)}
     */
    public static BigInteger randomBlinding(SecureRandom random) {
        Objects.requireNonNull(random, "random");
        byte[] sample = new byte[BLINDING_SAMPLE_BYTES];
        try {
            random.nextBytes(sample);
            return new BigInteger(1, sample).mod(JubjubCurve.SUBGROUP_ORDER);
        } finally {
            Arrays.fill(sample, (byte) 0);
        }
    }

    /**
     * Decodes a commitment received from another party ({@code pedersen-jubjub-v1} §4.1,
     * ADR-0051 D3).
     *
     * <p>Accepts exactly one encoding per point — {@link JubjubPoint#fromBytes} rejects a wrong
     * length, {@code v ≥ p}, a non-square {@code u²}, and {@code u = 0} with the sign bit set
     * (ZIP 216) — and additionally requires prime-order subgroup membership, which decoding
     * alone does not establish. The identity is a valid commitment (to {@code (0, 0)}) and is
     * accepted; a protocol that must exclude it checks {@link JubjubPoint#isIdentity()}.
     *
     * <p>A verifier that accepts a proof using
     * {@code ZkPedersenCommitment.fromVerifierCheckedPublic} discharges that constructor's
     * subgroup obligation with this method.
     *
     * <p>Rejections are {@link CommitmentFormatException} (an {@link IllegalArgumentException})
     * carrying {@code MALFORMED_ENCODING} for an encoding defect and {@code NOT_IN_SUBGROUP} for a
     * valid curve point outside the subgroup ({@code commitment-profiles-v1} §10). A null array
     * keeps throwing a plain {@link IllegalArgumentException}, as before.
     *
     * @throws IllegalArgumentException if the bytes are not a canonical encoding of a point in
     *         the prime-order subgroup
     */
    public static JubjubPoint decode(byte[] encoded) {
        if (encoded == null) {
            throw new IllegalArgumentException("Encoded point must be " + JubjubCurve.COMPRESSED_POINT_BYTES + " bytes");
        }
        return PedersenStrict.decodePoint(encoded);
    }

    /**
     * Verifies an opening: returns {@code true} iff {@code C == [v]·G + [r]·H}.
     *
     * <p>The opening is disclosed to the verifier, so this uses the faster public-scalar path.
     * It shares canonicalisation with {@link #commit(BigInteger, BigInteger)}, preserving the
     * exact residue-mod-l semantics without paying the secret-scalar schedule.
     *
     * <p><b>Timing rule (class V1, ADR-0059 A2).</b> Disclosed is not public: use this
     * variable-time check only where the opening is already public or no party from whom it is
     * still secret can observe the verifier's timing; otherwise verify offline or in an isolated
     * process. The strict form is
     * {@link #verifyScalar(PedersenScalarCommitment, BigInteger, BigInteger)}.
     */
    public static boolean verify(JubjubPoint commitment, BigInteger value, BigInteger blinding) {
        return commitPublic(value, blinding).projectiveEquals(commitment);
    }

    // ---- pedersen-jubjub-bytes-v1 (ADR-0058, docs/specs/pedersen-jubjub-bytes-v1.md) ----

    /**
     * Commits to the exact octets of {@code payload}:
     * {@code C = [HashBytesToScalar(payload)]·G + [r]·H} ({@code pedersen-jubjub-bytes-v1}).
     *
     * <p>Every octet is significant; nothing is normalized or decoded, and an empty array is a
     * valid payload. Unlike {@link #commit}, the blinding must already be canonical,
     * {@code 0 ≤ r < l}; use {@link #randomBlinding(SecureRandom)}. The payload is read once and
     * not copied or retained; the caller must not modify it during the call.
     *
     * <p><b>Same execution restriction as {@link #commit}</b>: the payload, the derived scalar and
     * {@code r} are secret, the hash reduction and curve arithmetic use variable-time
     * {@link BigInteger}, and generation must run offline or in an isolated process. Both scalars
     * go through {@code commit}'s two blinded fixed schedules.
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException ({@code NON_CANONICAL_SCALAR}) if {@code blinding} is not in
     *                                   {@code [0, l)}
     * @throws IllegalStateException     if SHA-256 is unavailable
     */
    public static PedersenBytesCommitment commitBytes(byte[] payload, BigInteger blinding) {
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(blinding, "blinding");
        blinding = requireCanonicalBlinding(blinding);
        return commitHashed(PedersenBytesHash.hashToScalar(payload), blinding);
    }

    /**
     * {@link #commitBytes(byte[], BigInteger)} over a stream that must hold exactly
     * {@code length} octets, read once through a bounded buffer.
     *
     * <p>After {@code length} octets one more read checks for end of stream: an extra octet, or
     * end of stream before {@code length}, fails with {@link IOException} and produces no
     * commitment. At most {@code length + 1} octets are read. The stream is never closed, reset or
     * retried; the caller owns it, its deadlines and its limits, and the end-of-stream check can
     * block. All arguments are validated before the first read.
     *
     * @throws CommitmentFormatException {@code NON_CANONICAL_SCALAR} if {@code blinding} is not in
     *         {@code [0, l)}, then {@code LENGTH_OUT_OF_RANGE} if {@code length} is not in
     *         {@code [0, 2^61 − 256]}
     * @throws IOException              on truncation, excess input or a read failure
     */
    public static PedersenBytesCommitment commitBytes(InputStream payload, long length, BigInteger blinding)
            throws IOException {
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(blinding, "blinding");
        blinding = requireCanonicalBlinding(blinding);
        requirePayloadBound(length, "length");
        return commitHashed(PedersenBytesHash.hashToScalar(payload, length, true), blinding);
    }

    /**
     * {@link #commitBytes(byte[], BigInteger)} over a stream of unknown length, read to end of
     * stream in one pass. The stream may hold at most {@code maxBytes} octets; if it holds more,
     * the call fails with {@link IOException} after reading {@code maxBytes + 1} octets. The same
     * octets give the same commitment as the array and declared-length forms. Ownership and
     * blocking behaviour are as for {@link #commitBytes(InputStream, long, BigInteger)}.
     *
     * @throws CommitmentFormatException {@code NON_CANONICAL_SCALAR} if {@code blinding} is not in
     *         {@code [0, l)}, then {@code LENGTH_OUT_OF_RANGE} if {@code maxBytes} is not in
     *         {@code [0, 2^61 − 256]}
     * @throws IOException              on excess input or a read failure
     */
    public static PedersenBytesCommitment commitBytesToEnd(InputStream payload, long maxBytes, BigInteger blinding)
            throws IOException {
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(blinding, "blinding");
        blinding = requireCanonicalBlinding(blinding);
        requirePayloadBound(maxBytes, "maxBytes");
        return commitHashed(PedersenBytesHash.hashToScalar(payload, maxBytes, false), blinding);
    }

    /**
     * Verifies a <b>disclosed</b> byte opening: {@code true} iff
     * {@code commitment == [HashBytesToScalar(payload)]·G + [r]·H}.
     *
     * <p>Like {@link #verify}, this uses the faster public-scalar path, because the payload and
     * blinding are disclosed to the verifier. Disclosed is not public (class V1, ADR-0059 A2): use
     * it only where the opening is already public or no party from whom it is still secret can
     * observe the verifier's timing. To check a payload or opening that must stay private,
     * recompute with {@link #commitBytes(byte[], BigInteger)} offline or in an isolated process and
     * compare commitments instead. The same rule applies to both stream forms.
     *
     * <p>A {@code true} result says the opening matches the point. It does not say under which
     * profile or in which context the point was issued: the same point also has a numeric opening.
     *
     * @throws CommitmentFormatException ({@code NON_CANONICAL_SCALAR}) if {@code blinding} is not in
     *         {@code [0, l)}
     */
    public static boolean verifyBytes(PedersenBytesCommitment commitment, byte[] payload, BigInteger blinding) {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(blinding, "blinding");
        blinding = requireCanonicalBlinding(blinding);
        return verify(commitment.point(), PedersenBytesHash.hashToScalar(payload), blinding);
    }

    /**
     * {@link #verifyBytes(PedersenBytesCommitment, byte[], BigInteger)} over a stream holding
     * exactly {@code length} octets, with the stream rules of
     * {@link #commitBytes(InputStream, long, BigInteger)}. Truncation, excess input and read
     * failures throw {@link IOException}; they never return {@code true}. Same timing rule and
     * error classes ({@code NON_CANONICAL_SCALAR}, then {@code LENGTH_OUT_OF_RANGE}).
     */
    public static boolean verifyBytes(PedersenBytesCommitment commitment, InputStream payload, long length,
                                      BigInteger blinding) throws IOException {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(blinding, "blinding");
        blinding = requireCanonicalBlinding(blinding);
        requirePayloadBound(length, "length");
        return verify(commitment.point(), PedersenBytesHash.hashToScalar(payload, length, true), blinding);
    }

    /**
     * {@link #verifyBytes(PedersenBytesCommitment, byte[], BigInteger)} over a stream read to end of
     * stream, holding at most {@code maxBytes} octets, with the stream rules of
     * {@link #commitBytesToEnd(InputStream, long, BigInteger)}. Same timing rule and error classes
     * ({@code NON_CANONICAL_SCALAR}, then {@code LENGTH_OUT_OF_RANGE}).
     */
    public static boolean verifyBytesToEnd(PedersenBytesCommitment commitment, InputStream payload, long maxBytes,
                                           BigInteger blinding) throws IOException {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(blinding, "blinding");
        blinding = requireCanonicalBlinding(blinding);
        requirePayloadBound(maxBytes, "maxBytes");
        return verify(commitment.point(), PedersenBytesHash.hashToScalar(payload, maxBytes, false), blinding);
    }

    private static PedersenBytesCommitment commitHashed(BigInteger scalar, BigInteger blinding) {
        return new PedersenBytesCommitment(commit(scalar, blinding));
    }

    private static BigInteger requireCanonicalBlinding(BigInteger blinding) {
        return PedersenStrict.canonical(blinding, "blinding");
    }

    private static void requirePayloadBound(long bound, String name) {
        if (bound < 0 || bound > PedersenBytesHash.MAX_PAYLOAD_BYTES) {
            throw new CommitmentFormatException(CommitmentError.LENGTH_OUT_OF_RANGE,
                    name + " must be in [0, " + PedersenBytesHash.MAX_PAYLOAD_BYTES + "]");
        }
    }

    private static JubjubPoint commitPublic(BigInteger value, BigInteger blinding) {
        BigInteger[] scalars = canonicalScalars(value, blinding);
        return JubjubPoint.SUBGROUP_GENERATOR.scalarMul(scalars[0])
                .add(H.scalarMul(scalars[1]));
    }

    private static BigInteger[] canonicalScalars(BigInteger value, BigInteger blinding) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        // Binding is to residues mod l. Canonicalisation also establishes the range required by
        // the fixed secret schedule used by commit().
        return new BigInteger[]{
                value.mod(JubjubCurve.SUBGROUP_ORDER),
                blinding.mod(JubjubCurve.SUBGROUP_ORDER)
        };
    }

    private static JubjubPoint deriveSecondBase() {
        BigInteger p = JubjubCurve.BASE_FIELD_PRIME;
        // Hash the domain tag bytes into the field via Poseidon.
        byte[] domainBytes = H_DOMAIN_TAG.getBytes(StandardCharsets.UTF_8);
        BigInteger a = new BigInteger(1, domainBytes).mod(p);
        for (int counter = 0; counter < 1_000_000; counter++) {
            BigInteger b = BigInteger.valueOf(counter);
            BigInteger seed = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, a, b);
            BigInteger vCandidate = seed.mod(p);
            // Try to solve -u^2 + v^2 = 1 + d·u^2·v^2 for u.
            // u^2 = (v^2 - 1) / (d·v^2 + 1).
            BigInteger vv = vCandidate.multiply(vCandidate).mod(p);
            BigInteger num = vv.subtract(BigInteger.ONE).mod(p);
            BigInteger den = JubjubCurve.D.multiply(vv).add(BigInteger.ONE).mod(p);
            if (den.signum() == 0) continue;
            BigInteger uSquared = num.multiply(den.modInverse(p)).mod(p);
            BigInteger u = modSqrtOrNull(uSquared, p);
            if (u == null) continue;
            // Deterministic sign choice: take the lexicographically-smaller root.
            BigInteger altU = p.subtract(u);
            if (altU.compareTo(u) < 0) u = altU;
            // Cofactor-clear to ensure H is in the prime-order subgroup.
            JubjubPoint candidate = JubjubPoint.fromAffine(u, vCandidate).mulByCofactor();
            if (candidate.isIdentity()) continue; // extremely unlikely, but safe
            return candidate;
        }
        throw new IllegalStateException(
                "PedersenCommitment second-base derivation did not converge after 1M tries — "
                        + "this should be cryptographically impossible; check Poseidon/Jubjub wiring");
    }

    private static BigInteger modSqrtOrNull(BigInteger a, BigInteger p) {
        if (a.signum() == 0) return BigInteger.ZERO;
        // Euler criterion: a is a QR iff a^((p-1)/2) == 1.
        BigInteger exp = p.subtract(BigInteger.ONE).shiftRight(1);
        if (!a.modPow(exp, p).equals(BigInteger.ONE)) return null;
        // Tonelli-Shanks
        BigInteger s = p.subtract(BigInteger.ONE);
        int e = 0;
        while (!s.testBit(0)) { s = s.shiftRight(1); e++; }
        BigInteger n = BigInteger.TWO;
        while (!n.modPow(exp, p).equals(p.subtract(BigInteger.ONE))) {
            n = n.add(BigInteger.ONE);
        }
        BigInteger x = a.modPow(s.add(BigInteger.ONE).shiftRight(1), p);
        BigInteger b = a.modPow(s, p);
        BigInteger g = n.modPow(s, p);
        int r = e;
        while (true) {
            BigInteger tmp = b;
            int m = 0;
            while (!tmp.equals(BigInteger.ONE)) {
                tmp = tmp.multiply(tmp).mod(p);
                m++;
                if (m == r) return null;
            }
            if (m == 0) return x;
            BigInteger gs = g.modPow(BigInteger.TWO.pow(r - m - 1), p);
            g = gs.multiply(gs).mod(p);
            x = x.multiply(gs).mod(p);
            b = b.multiply(g).mod(p);
            r = m;
        }
    }
}
