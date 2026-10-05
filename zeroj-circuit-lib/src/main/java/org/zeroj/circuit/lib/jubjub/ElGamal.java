package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.TreeMap;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * Exponential ("lifted") ElGamal on Jubjub, profile {@code elgamal-jubjub-v1}
 * (<a href="../../../../../../../../../docs/specs/elgamal-jubjub-v1.md">spec</a>, ADR-0052).
 *
 * <pre>
 *   A = [k]·G,   B = [m]·G + [k]·PK,   m ∈ [0, 2^w), 1 ≤ w ≤ 64
 * </pre>
 * Ciphertexts under one key add up to encryptions of the sum. Decryption recovers {@code [m]·G}
 * and then the unique {@code m ∈ [0, bound]} by a bounded search, failing closed.
 *
 * <h2>Safe layer</h2>
 * <ul>
 *   <li>Ciphertexts are {@link ElGamalCiphertext}s, which carry a key context and an established
 *       plaintext bound. They come only from {@link #encrypt} or {@link #admit}.</li>
 *   <li>Distributed decryption ({@link #decrypt}) needs exactly one
 *       {@link VerifiedDecryptionShare} per registered trustee.</li>
 *   <li>Single-key decryption ({@link #decryptWithSecret}) needs the secret of the joint key
 *       itself.</li>
 * </ul>
 * {@link RawElGamalCiphertext} is the unchecked raw layer.
 *
 * <h2>Secrets: compatibility/offline class (ADR-0039 §3.1)</h2>
 * Encryption (the randomness {@code k} and the message {@code m}), decryption shares and
 * single-key decryption multiply secrets with variable-time {@link BigInteger} arithmetic through
 * the blinded best-effort schedule ({@link JubjubPoint#scalarMulSecretBlindedBestEffort}), as
 * Pedersen commitment generation does. The plaintext search runs in time that depends on the
 * plaintext. Run these operations offline or in an isolated process. Nothing here is
 * constant-time, and no method name implies online approval. {@code [m]·G} is computed by scalar
 * multiplication for every {@code m}, so {@code m = 0} takes no separate path. Public-data
 * operations (decoding, subgroup checks, sums, share verification) use the faster public path.
 */
public final class ElGamal {

    /** The profile identifier. */
    public static final String PROFILE = "elgamal-jubjub-v1";

    /**
     * The widest message, in bits (spec §4).
     *
     * <p>Admitting a width does not make it decryptable. Decryption searches {@code [0, bound]}
     * and refuses bounds beyond the caller's {@code long} search limit and the search table's
     * reach (by default about {@code 2^43}; see {@link JubjubDiscreteLog}). A width-64 ciphertext
     * (bound {@code 2^64 − 1}) can be admitted and combined, but not decrypted, on the safe path.
     * Choose widths so that the bound of the sum you will decrypt stays searchable.
     */
    public static final int MAX_MESSAGE_BITS = 64;

    /** Bytes drawn per scalar sample (spec §2). */
    static final int SAMPLE_BYTES = 64;

    private ElGamal() {}

    // ---------------------------------------------------------------- encryption and admission

    /**
     * Encrypts {@code m} at width {@code width} under the context's joint key (spec §4). The
     * result's bound is {@code 2^width − 1}.
     *
     * @throws IllegalArgumentException unless {@code 1 ≤ width ≤ 64} and {@code 0 ≤ m < 2^width}
     */
    public static ElGamalCiphertext encrypt(
            ElGamalKeyContext context, BigInteger message, int width, SecureRandom random) {
        Objects.requireNonNull(random, "random");
        return encryptWithRandomness(context, message, width, sample(random));
    }

    /** {@link #encrypt(ElGamalKeyContext, BigInteger, int, SecureRandom)} for a non-negative {@code long}. */
    public static ElGamalCiphertext encrypt(
            ElGamalKeyContext context, long message, int width, SecureRandom random) {
        return encrypt(context, BigInteger.valueOf(message), width, random);
    }

    /**
     * Encrypts as {@link #encrypt(ElGamalKeyContext, BigInteger, int, SecureRandom)} and also
     * returns the opening {@code (m, k)}, which the encrypting party needs as the witness of the
     * encryption proof (spec §9.1). The opening is secret; see {@link ElGamalEncryption}.
     */
    public static ElGamalEncryption encryptWithOpening(
            ElGamalKeyContext context, BigInteger message, int width, SecureRandom random) {
        Objects.requireNonNull(random, "random");
        BigInteger k = sample(random);
        ElGamalCiphertext ciphertext = encryptWithRandomness(context, message, width, k);
        return new ElGamalEncryption(ciphertext, message, k, width);
    }

    /** Test seam for fixed randomness {@code k ∈ [0, l)}. Not for production use. */
    static ElGamalCiphertext encryptWithRandomness(
            ElGamalKeyContext context, BigInteger message, int width, BigInteger k) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(k, "k");
        requireWidth(width);
        requireMessage(message, width);
        if (k.signum() < 0 || k.compareTo(SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException("randomness must satisfy 0 <= k < l");
        }
        JubjubPoint key = context.jointKey().point();
        JubjubPoint handle = JubjubPoint.SUBGROUP_GENERATOR.scalarMulSecretBlindedBestEffort(k);
        JubjubPoint mask = key.scalarMulSecretBlindedBestEffort(k);
        JubjubPoint encoded = JubjubPoint.SUBGROUP_GENERATOR.scalarMulSecretBlindedBestEffort(message);
        return new ElGamalCiphertext(handle, encoded.add(mask), context, boundOf(width));
    }

    /**
     * Admits a raw ciphertext into the safe layer under {@code context} at {@code width}
     * (spec §10.1, ADR-0052 D2a). The verifier must check the encryption relation for exactly
     * this joint key, ciphertext and width. See {@link EncryptionStatementVerifier} for that
     * delegated obligation.
     *
     * @throws IllegalArgumentException if the width is out of range or the verifier rejects
     */
    public static ElGamalCiphertext admit(
            RawElGamalCiphertext raw, ElGamalKeyContext context, int width,
            EncryptionStatementVerifier verifier) {
        Objects.requireNonNull(raw, "raw");
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(verifier, "verifier");
        requireWidth(width);
        EncryptionStatement statement =
                new EncryptionStatement(context.jointKey(), raw.handle(), raw.blinded(), width);
        if (!verifier.verify(statement)) {
            throw new IllegalArgumentException("encryption statement rejected; ciphertext not admitted");
        }
        return new ElGamalCiphertext(raw.handle(), raw.blinded(), context, boundOf(width));
    }

    // ---------------------------------------------------------------- decryption

    /**
     * Computes this trustee's decryption share {@code D_j = [sk_j]·A} (spec §6.2). The share is
     * verified by construction: the secret's public key must be registered in the ciphertext's
     * context. Publish {@link VerifiedDecryptionShare#encode()} with a proof of
     * {@link VerifiedDecryptionShare#statement()}.
     *
     * @throws IllegalArgumentException if the secret's public key is not registered in the
     *         ciphertext's context
     */
    public static VerifiedDecryptionShare decryptionShare(
            ElGamalSecretKey trusteeSecret, ElGamalCiphertext ciphertext) {
        Objects.requireNonNull(trusteeSecret, "trusteeSecret");
        Objects.requireNonNull(ciphertext, "ciphertext");
        if (!(ciphertext.context() instanceof NOfNKeyContext context)) {
            throw new IllegalArgumentException("an n-of-n secret cannot produce a share for this context");
        }
        int index = context.indexOf(trusteeSecret.publicKey());
        if (index < 0) {
            throw new IllegalArgumentException(
                    "the secret's public key is not registered in the ciphertext's context");
        }
        JubjubPoint d = trusteeSecret.multiply(ciphertext.handle()).normalized();
        DleqStatement statement = DleqStatement.decryptionShare(
                ciphertext.handle(), trusteeSecret.publicKey().point(), d);
        return new VerifiedDecryptionShare(ciphertext, index, d, statement);
    }

    /**
     * Computes a threshold participant's decryption share {@code D_j = [x_j]·A}
     * ({@code elgamal-jubjub-threshold-v1} §9). The share is verified by construction: the
     * secret is checked against the identifier's verification key {@code Y_j} in the
     * ciphertext's context, which may be the identity (D5a).
     *
     * @throws IllegalArgumentException if the ciphertext is not under this share's threshold
     *         context, the participant is not in {@code QUAL}, or {@code [x_j]·G ≠ Y_j}
     */
    public static VerifiedDecryptionShare decryptionShare(ThresholdKeyShare share, ElGamalCiphertext ciphertext) {
        Objects.requireNonNull(share, "share");
        Objects.requireNonNull(ciphertext, "ciphertext");
        if (!(ciphertext.context() instanceof ThresholdKeyContext context) || !context.equals(share.context())) {
            throw new IllegalArgumentException("the ciphertext is not under this share's threshold context");
        }
        int id = share.id();
        if (!context.qual().contains(id)) {
            throw new IllegalArgumentException("participant " + id + " is not qualified");
        }
        JubjubPoint yj = context.verificationKey(id);
        if (!JubjubPoint.SUBGROUP_GENERATOR.scalarMulSecretBlindedBestEffort(share.secret()).projectiveEquals(yj)) {
            throw new IllegalArgumentException("the secret does not match participant " + id + "'s verification key");
        }
        JubjubPoint d = ciphertext.handle().scalarMulSecretBlindedBestEffort(share.secret()).normalized();
        return new VerifiedDecryptionShare(ciphertext, id, d, DleqStatement.decryptionShare(ciphertext.handle(), yj, d));
    }

    /**
     * Distributed decryption with exactly one verified share per registered trustee (spec §6.2).
     *
     * <p>For a threshold context ({@code elgamal-jubjub-threshold-v1} §9), at least {@code t + 1}
     * verified shares from distinct qualified participants are required instead. Any extra
     * shares are checked against the interpolation of the first {@code t + 1}.
     *
     * @param maxPlaintext the caller's search limit; the ciphertext's bound must not exceed it
     * @throws IllegalArgumentException if a share is for another ciphertext, the share set is
     *         incomplete or repeated, or the bound exceeds {@code maxPlaintext}
     * @throws IllegalStateException if an extra threshold share disagrees with the
     *         interpolation, which cannot happen with honestly verified shares
     * @throws ElGamalDecryptionException if no plaintext in {@code [0, bound]} matches
     */
    public static long decrypt(
            ElGamalCiphertext ciphertext, Collection<VerifiedDecryptionShare> shares, long maxPlaintext) {
        return decrypt(ciphertext, shares, maxPlaintext, null);
    }

    /** As {@link #decrypt(ElGamalCiphertext, Collection, long)}, with a reusable search table. */
    public static long decrypt(
            ElGamalCiphertext ciphertext, Collection<VerifiedDecryptionShare> shares,
            long maxPlaintext, JubjubDiscreteLog table) {
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(shares, "shares");
        long bound = requireSearchable(ciphertext, maxPlaintext);
        JubjubDiscreteLog solver = solver(bound, table);
        if (ciphertext.context() instanceof ThresholdKeyContext threshold) {
            return search(thresholdUnmask(ciphertext, threshold, shares), bound, solver);
        }
        if (!(ciphertext.context() instanceof NOfNKeyContext context)) {
            throw new IllegalArgumentException("unsupported key context: " + ciphertext.context());
        }
        boolean[] seen = new boolean[context.size()];
        List<JubjubPoint> points = new ArrayList<>(shares.size());
        for (VerifiedDecryptionShare share : shares) {
            Objects.requireNonNull(share, "share");
            if (!share.ciphertext().sameCiphertext(ciphertext)) {
                throw new IllegalArgumentException("a decryption share is bound to a different ciphertext");
            }
            if (seen[share.trustee()]) {
                throw new IllegalArgumentException("more than one share from the same trustee");
            }
            seen[share.trustee()] = true;
            points.add(share.share());
        }
        if (points.size() != context.size()) {
            throw new IllegalArgumentException("a decryption share is required from every registered trustee ("
                    + context.size() + "), got " + points.size());
        }
        JubjubPoint unmasked = RawElGamalCiphertext.unmask(ciphertext.blinded(), points);
        return search(unmasked, bound, solver);
    }

    /**
     * Single-key decryption (spec §6.1). The secret's public key must equal the ciphertext's
     * joint key: a trustee's individual share is refused.
     *
     * @throws IllegalArgumentException if the secret does not match the joint key, or the bound
     *         exceeds {@code maxPlaintext}
     * @throws ElGamalDecryptionException if no plaintext in {@code [0, bound]} matches
     */
    public static long decryptWithSecret(
            ElGamalCiphertext ciphertext, ElGamalSecretKey secretKey, long maxPlaintext) {
        return decryptWithSecret(ciphertext, secretKey, maxPlaintext, null);
    }

    /** As {@link #decryptWithSecret(ElGamalCiphertext, ElGamalSecretKey, long)}, with a reusable table. */
    public static long decryptWithSecret(
            ElGamalCiphertext ciphertext, ElGamalSecretKey secretKey, long maxPlaintext,
            JubjubDiscreteLog table) {
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(secretKey, "secretKey");
        long bound = requireSearchable(ciphertext, maxPlaintext);
        JubjubDiscreteLog solver = solver(bound, table);
        if (!(ciphertext.context() instanceof NOfNKeyContext)) {
            throw new IllegalArgumentException("single-key decryption is not defined for this key context");
        }
        if (!secretKey.publicKey().equals(ciphertext.context().jointKey())) {
            throw new IllegalArgumentException(
                    "the secret's public key does not equal the ciphertext's joint key");
        }
        JubjubPoint mask = secretKey.multiply(ciphertext.handle());
        JubjubPoint unmasked = RawElGamalCiphertext.unmask(ciphertext.blinded(), List.of(mask));
        return search(unmasked, bound, solver);
    }

    // ---------------------------------------------------------------- helpers

    /** Spec §2: 64 bytes from {@code random}, read big-endian, reduced mod {@code l}; the buffer is wiped. */
    static BigInteger sample(SecureRandom random) {
        Objects.requireNonNull(random, "random");
        byte[] bytes = new byte[SAMPLE_BYTES];
        try {
            random.nextBytes(bytes);
            return new BigInteger(1, bytes).mod(SUBGROUP_ORDER);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    static void requireWidth(int width) {
        if (width < 1 || width > MAX_MESSAGE_BITS) {
            throw new IllegalArgumentException(
                    "message width must satisfy 1 <= w <= " + MAX_MESSAGE_BITS + ", got " + width);
        }
    }

    private static void requireMessage(BigInteger message, int width) {
        Objects.requireNonNull(message, "message");
        if (message.signum() < 0 || message.bitLength() > width) {
            throw new IllegalArgumentException("message must satisfy 0 <= m < 2^" + width);
        }
    }

    static BigInteger boundOf(int width) {
        return BigInteger.ONE.shiftLeft(width).subtract(BigInteger.ONE);
    }

    static long requireSearchable(ElGamalCiphertext ciphertext, long maxPlaintext) {
        if (maxPlaintext < 0) {
            throw new IllegalArgumentException("maxPlaintext must be non-negative");
        }
        if (ciphertext.bound().compareTo(BigInteger.valueOf(maxPlaintext)) > 0) {
            throw new IllegalArgumentException("the ciphertext's plaintext bound " + ciphertext.bound()
                    + " exceeds the search limit " + maxPlaintext);
        }
        return ciphertext.bound().longValueExact();
    }

    /**
     * {@code B − Σ_{j∈S} [λ_j]·D_j} over the {@code t + 1} smallest identifiers {@code S}, after
     * checking every extra share against the interpolation of {@code S}
     * ({@code elgamal-jubjub-threshold-v1} §9). All inputs are public.
     */
    private static JubjubPoint thresholdUnmask(ElGamalCiphertext ciphertext, ThresholdKeyContext context,
                                               Collection<VerifiedDecryptionShare> shares) {
        TreeMap<Integer, JubjubPoint> byId = new TreeMap<>();
        for (VerifiedDecryptionShare share : shares) {
            Objects.requireNonNull(share, "share");
            if (!share.ciphertext().sameCiphertext(ciphertext)) {
                throw new IllegalArgumentException("a decryption share is bound to a different ciphertext");
            }
            if (byId.put(share.trustee(), share.share()) != null) {
                throw new IllegalArgumentException("more than one share from participant " + share.trustee());
            }
        }
        int threshold = context.threshold();
        if (byId.size() < threshold + 1) {
            throw new IllegalArgumentException("threshold decryption needs at least t + 1 = " + (threshold + 1)
                    + " verified shares, got " + byId.size());
        }
        int[] subset = new int[threshold + 1];
        FastJubjubPoint[] chosen = new FastJubjubPoint[threshold + 1];
        int index = 0;
        for (var entry : byId.entrySet()) {
            if (index == threshold + 1) break;
            subset[index] = entry.getKey();
            chosen[index] = FastJubjubPoint.of(entry.getValue());
            index++;
        }
        BigInteger[] lambda = ThresholdMath.lagrangeAt(subset, 0);
        FastJubjubPoint combined = FastJubjubPoint.IDENTITY;
        for (int i = 0; i <= threshold; i++) {
            combined = combined.add(chosen[i].scalarMulPublic(lambda[i]));
        }
        for (var entry : byId.tailMap(subset[threshold], false).entrySet()) {
            BigInteger[] at = ThresholdMath.lagrangeAt(subset, entry.getKey());
            FastJubjubPoint expected = FastJubjubPoint.IDENTITY;
            for (int i = 0; i <= threshold; i++) {
                expected = expected.add(chosen[i].scalarMulPublic(at[i]));
            }
            if (!expected.projectiveEquals(FastJubjubPoint.of(entry.getValue()))) {
                throw new IllegalStateException("share of participant " + entry.getKey()
                        + " disagrees with the interpolation of the first t + 1 shares");
            }
        }
        return FastJubjubPoint.of(ciphertext.blinded()).subtract(combined).toJubjubPoint();
    }

    /** The search table, validated before any secret multiplication happens. */
    static JubjubDiscreteLog solver(long bound, JubjubDiscreteLog table) {
        if (table == null) {
            return JubjubDiscreteLog.forBound(bound);
        }
        if (bound > table.maxBound()) {
            throw new IllegalArgumentException("the search table reaches " + table.maxBound()
                    + ", below the ciphertext's bound " + bound);
        }
        return table;
    }

    static long search(JubjubPoint unmasked, long bound, JubjubDiscreteLog solver) {
        OptionalLong result = solver.solve(unmasked, bound);
        if (result.isEmpty()) {
            throw new ElGamalDecryptionException("no plaintext in [0, " + bound + "] matches");
        }
        return result.getAsLong();
    }
}
