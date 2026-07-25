package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Off-circuit EdDSA signature scheme over Jubjub, with Poseidon as the challenge hash.
 * Used by the in-circuit verifier as its cryptographic oracle, and by application code for
 * issuing, signing, and off-chain verification.
 *
 * <p>The normative specification is
 * <a href="../../../../../../../../../docs/specs/jubjub-eddsa-v1.md">docs/specs/jubjub-eddsa-v1.md</a>;
 * pinned constants live in {@link JubjubEdDSASuite}. Nonce and challenge are domain-separated
 * by distinct capacity-cell tags, so a value computed for one can never be reinterpreted as
 * the other.
 *
 * <h2>Scheme</h2>
 *
 * <h3>Key generation</h3>
 * {@code sk ∈ [1, l); pk = [sk]·G} where G is {@link JubjubPoint#SUBGROUP_GENERATOR} and
 * {@code l = } {@link JubjubCurve#SUBGROUP_ORDER}. Use
 * {@link #generateKeypair(SecureRandom)} rather than sampling {@code sk} yourself.
 *
 * <h3>Sign (sk, msg)</h3>
 * <ol>
 *   <li>{@code r = Poseidon_t3(NONCE_TAG; sk, msg) mod l} — deterministic nonce, no RNG.</li>
 *   <li>{@code R = [r]·G}.</li>
 *   <li>{@code k = Poseidon_t6(CHALLENGE_TAG; R.u, R.v, pk.u, pk.v, msg) mod l}.</li>
 *   <li>{@code S = (r + k·sk) mod l}.</li>
 *   <li>Signature = {@code (R, S)}.</li>
 * </ol>
 *
 * <h3>Verify (pk, msg, R, S)</h3>
 * <ol>
 *   <li>Reject if {@code pk} is the identity, or {@code pk}/{@code R} are outside the
 *       prime-order subgroup.</li>
 *   <li>Reject if {@code S ∉ [0, l)} — malleability.</li>
 *   <li>{@code k = Poseidon_t6(CHALLENGE_TAG; R.u, R.v, pk.u, pk.v, msg) mod l}.</li>
 *   <li>Check {@code [S]·G == R + [k]·pk}, cofactorless.</li>
 * </ol>
 *
 * <h2>Message encoding</h2>
 * {@code msg} is a field element in {@code [0, p)}, not a byte string, and values outside
 * that range are rejected rather than silently reduced. For byte-oriented messages use
 * {@link #hashToField(byte[])}.
 *
 * <h2>Deviation from RFC 8032</h2>
 * RFC 8032 uses SHA-512 for both nonce derivation and challenge, and derives the public key
 * through a hashed prefix rather than a plain scalar multiplication. This implementation uses
 * Poseidon so the verification equation can be emitted as a small number of constraints
 * inside a BLS12-381 SNARK. It is <b>not interoperable</b> with Ed25519 or Sapling-EdDSA.
 *
 * <h2>Not constant-time</h2>
 * {@link #sign} performs secret-dependent scalar multiplication over variable-time
 * {@link BigInteger}, and derives its nonce by feeding {@code sk} straight through Poseidon's
 * variable-time field arithmetic. Per ADR-0037 Decision 8 this signer is <b>not approved for
 * value-bearing issuance on shared or network-reachable infrastructure</b>; approved uses are
 * local/offline signing and test issuance. Verification handles only public data and is
 * unaffected.
 *
 * @see <a href="../../../../../../../../../docs/adr/0037-jubjub-soundness-and-hardening.md">ADR-0037</a>
 */
public final class EdDSAJubjub {

    private EdDSAJubjub() {}

    /** Domain tag for {@link #hashToField(byte[])}. Changing it is a breaking protocol change. */
    static final String HASH_TO_FIELD_DST = "ZeroJ-JubjubEdDSA-v1-hashToField";

    /**
     * A keypair: private scalar {@code sk} and public point {@code pk = [sk]·G}.
     *
     * <p>{@link #toString()} is overridden to redact {@code sk}. The record-generated version
     * printed the private key, so any log or debugger string of a keypair leaked it.
     */
    public record Keypair(BigInteger sk, JubjubPoint pk) {
        public Keypair {
            Objects.requireNonNull(sk, "sk");
            Objects.requireNonNull(pk, "pk");
        }

        @Override
        public String toString() {
            return "Keypair[sk=<redacted>, pk=" + pk + "]";
        }
    }

    /**
     * A signature: curve point {@code R} and scalar {@code S}. Both must be canonical
     * ({@code R} in the prime-order subgroup, {@code S ∈ [0, l)}) for verification to succeed.
     */
    public record Signature(JubjubPoint r, BigInteger s) {
        public Signature {
            Objects.requireNonNull(r, "r");
            Objects.requireNonNull(s, "s");
        }
    }

    // ------------------------------------------------------------------
    //  Key generation
    // ------------------------------------------------------------------

    /**
     * Generates a keypair with {@code sk} drawn uniformly from {@code [1, l)}.
     *
     * <p>Uses rejection sampling rather than {@code random mod l}: reducing a uniform
     * 256-bit value modulo {@code l} would bias the low residues. Candidates are drawn as
     * 252-bit values (matching {@code l}'s bit length) and re-drawn if they fall outside
     * {@code [1, l)}, which happens for roughly 1 draw in 10.
     *
     * @param random a cryptographically secure source; callers should pass
     *               {@code new SecureRandom()} or a platform-seeded instance
     */
    public static Keypair generateKeypair(SecureRandom random) {
        Objects.requireNonNull(random, "random");
        BigInteger l = JubjubCurve.SUBGROUP_ORDER;
        int byteLen = (l.bitLength() + 7) / 8;          // 32 for a 252-bit l
        int excessBits = byteLen * 8 - l.bitLength();   // 4
        byte[] buf = new byte[byteLen];
        while (true) {
            random.nextBytes(buf);
            if (excessBits > 0) {
                buf[0] &= (byte) (0xFF >>> excessBits); // never exceed l's bit length
            }
            BigInteger candidate = new BigInteger(1, buf);
            if (candidate.signum() > 0 && candidate.compareTo(l) < 0) {
                java.util.Arrays.fill(buf, (byte) 0);
                return keypairFromSecret(candidate);
            }
        }
    }

    /**
     * Derives a keypair from a given secret scalar.
     *
     * @param sk secret key scalar; must satisfy {@code 0 < sk < l}
     */
    public static Keypair keypairFromSecret(BigInteger sk) {
        requireScalarInRange(sk);
        JubjubPoint pk = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(sk);
        return new Keypair(sk, pk);
    }

    // ------------------------------------------------------------------
    //  Message encoding
    // ------------------------------------------------------------------

    /**
     * Maps an arbitrary byte string to a field element in {@code [0, p)}, suitable as the
     * {@code msg} argument to {@link #sign} and {@link #verify}.
     *
     * <p>Construction, fixed and versioned:
     * <pre>
     *   wide = SHA-512( len(DST) as 1 byte || DST || len(msg) as 8-byte big-endian || msg )
     *   out  = OS2IP(wide) mod p          // wide interpreted big-endian
     * </pre>
     * where {@code DST = "ZeroJ-JubjubEdDSA-v1-hashToField"} (UTF-8) and {@code p} is
     * {@link JubjubCurve#BASE_FIELD_PRIME}.
     *
     * <p>Both the domain tag and the message are length-prefixed, so no two distinct inputs
     * share a preimage. Reducing 512 bits into a 255-bit field leaves a modular bias of about
     * {@code 2^-257}, which is negligible; a bare 32-byte digest would have left a bias
     * around {@code 2^-1} for some residues.
     *
     * <p>This is deliberately <em>not</em> Poseidon: the input is a byte string of arbitrary
     * length, and a byte-oriented hash avoids inventing a padding scheme for the sponge.
     */
    public static BigInteger hashToField(byte[] message) {
        Objects.requireNonNull(message, "message");
        byte[] dst = HASH_TO_FIELD_DST.getBytes(StandardCharsets.UTF_8);
        if (dst.length > 255) throw new IllegalStateException("DST must be at most 255 bytes");

        ByteBuffer buf = ByteBuffer.allocate(1 + dst.length + 8 + message.length);
        buf.put((byte) dst.length);
        buf.put(dst);
        buf.putLong(message.length);
        buf.put(message);

        MessageDigest sha512;
        try {
            sha512 = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 is required but unavailable", e);
        }
        byte[] wide = sha512.digest(buf.array());
        return new BigInteger(1, wide).mod(JubjubCurve.BASE_FIELD_PRIME);
    }

    // ------------------------------------------------------------------
    //  Sign / verify
    // ------------------------------------------------------------------

    /**
     * Signs a message field element with secret key {@code sk}.
     *
     * @param sk  secret scalar, must satisfy {@code 0 < sk < l}
     * @param msg message as a field element in {@code [0, p)}; use
     *            {@link #hashToField(byte[])} for byte-oriented messages
     * @throws IllegalArgumentException if {@code sk} or {@code msg} is out of range
     */
    public static Signature sign(BigInteger sk, BigInteger msg) {
        requireScalarInRange(sk);
        requireFieldElement(msg);
        BigInteger l = JubjubCurve.SUBGROUP_ORDER;
        JubjubPoint pk = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(sk);
        // Deterministic nonce; no secure RNG required.
        //
        // Reducing the 255-bit Poseidon output mod l is very slightly biased, because
        // p = 8l + delta. The statistical distance from uniform is about delta/p, and delta
        // is 126 bits against a 255-bit p, so the bias is around 2^-129 -- negligible, with
        // no practical limit on signing volume. (An earlier revision of this comment claimed
        // "~2^-3 bias (p/l ~ 8)" and warned about signing volume; that was wrong. See
        // JubjubCurve.P_MINUS_EIGHT_L.)
        BigInteger r = PoseidonHash.spongeHash(
                JubjubEdDSASuite.nonceParams(), JubjubEdDSASuite.NONCE_TAG, sk, msg).mod(l);
        JubjubPoint rPoint = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(r);
        // The challenge binds (R, pk, msg); including pk defends against key-substitution
        // and duplicate-signature attacks, as in standard Ed25519 / Schnorr.
        BigInteger k = computeChallenge(rPoint, pk, msg);
        BigInteger s = r.add(k.multiply(sk)).mod(l);
        return new Signature(rPoint, s);
    }

    /**
     * Verifies a signature. Returns {@code false} for malformed or invalid signatures rather
     * than throwing, except for an out-of-range {@code msg}, which is a caller error.
     *
     * @param pk  public key; must be a non-identity point in the Jubjub prime-order subgroup
     * @param msg message field element in {@code [0, p)}
     * @param sig signature to verify
     * @throws IllegalArgumentException if {@code msg} is outside {@code [0, p)}
     */
    public static boolean verify(JubjubPoint pk, BigInteger msg, Signature sig) {
        Objects.requireNonNull(pk, "pk");
        Objects.requireNonNull(sig, "sig");
        requireFieldElement(msg);
        BigInteger l = JubjubCurve.SUBGROUP_ORDER;

        // 1. Reject the identity public key. It passes the subgroup check, but [k]·O = O
        //    makes the equation collapse to [S]·G == R, so anyone forges by choosing r,
        //    setting R = [r]·G and S = r. No secret key is involved at all.
        if (pk.isIdentity()) return false;
        // 2. Subgroup checks: small-subgroup / invalid-curve defenses.
        if (!pk.isInSubgroup()) return false;
        if (!sig.r.isInSubgroup()) return false;
        // 3. S ∈ [0, l) — rejects the S + l alias.
        if (sig.s.signum() < 0 || sig.s.compareTo(l) >= 0) return false;
        // 4. Recompute the challenge and check the equation, cofactorless.
        BigInteger k = computeChallenge(sig.r, pk, msg);
        JubjubPoint lhs = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(sig.s);
        JubjubPoint rhs = sig.r.add(pk.scalarMul(k));
        return lhs.projectiveEquals(rhs);
    }

    /**
     * Computes the challenge scalar {@code k = Poseidon(R.u, R.v, pk.u, pk.v, msg) mod l}.
     *
     * <p>Including {@code pk} is a standard defense against key-substitution attacks.
     * Exposed so in-circuit gadgets can compute {@code k} exactly as sign/verify do.
     */
    public static BigInteger computeChallenge(JubjubPoint r, JubjubPoint pk, BigInteger msg) {
        // Single t=6 permutation with the challenge tag in the capacity cell: rate 5 exactly
        // covers (R.u, R.v, pk.u, pk.v, msg). Coordinates are affine and canonical, so a
        // projective representative cannot be used to grind the challenge.
        return PoseidonHash.spongeHash(
                        JubjubEdDSASuite.challengeParams(), JubjubEdDSASuite.CHALLENGE_TAG,
                        r.affineU(), r.affineV(), pk.affineU(), pk.affineV(), msg)
                .mod(JubjubCurve.SUBGROUP_ORDER);
    }

    // ------------------------------------------------------------------
    //  Validation
    // ------------------------------------------------------------------

    private static void requireScalarInRange(BigInteger sk) {
        Objects.requireNonNull(sk, "sk");
        if (sk.signum() <= 0 || sk.compareTo(JubjubCurve.SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException(
                    "Secret key must satisfy 0 < sk < l (= Jubjub subgroup order)");
        }
    }

    /**
     * Rejects a message outside {@code [0, p)}.
     *
     * <p>Poseidon reduces its inputs internally, so without this check a signature over
     * {@code msg} would also verify for {@code msg + p} — two distinct application-level
     * messages sharing one signature. Rejecting is a caller error, not a verification
     * failure, because it means the message was never encoded correctly.
     */
    private static void requireFieldElement(BigInteger msg) {
        Objects.requireNonNull(msg, "msg");
        if (msg.signum() < 0 || msg.compareTo(JubjubCurve.BASE_FIELD_PRIME) >= 0) {
            throw new IllegalArgumentException(
                    "msg must be a field element in [0, p); got a value with bitLength "
                            + msg.bitLength() + ". Use hashToField(byte[]) for byte messages.");
        }
    }
}
