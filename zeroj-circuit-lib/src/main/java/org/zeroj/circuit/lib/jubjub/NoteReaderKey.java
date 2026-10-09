package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * A reader's public viewing key for {@code confidential-note-jubjub-v1}: {@code P = [sk]·G}
 * (ADR-0055 D2; spec §2.2). Deliveries are sealed to it.
 *
 * <p>Every instance is valid: a canonical encoding, in the prime-order subgroup and not the
 * identity. A sender therefore never encrypts to a key that fails the check (ADR-0055 I5).
 *
 * <p>A viewing key is used only by this profile (ADR-0055 I6). This type is distinct from
 * {@link ElGamalPublicKey} and from EdDSA and spending keys, and no conversion between them
 * exists.
 */
public final class NoteReaderKey {

    private final JubjubPoint point;
    private final byte[] encoding;

    private NoteReaderKey(JubjubPoint point) {
        this.point = point;
        this.encoding = point.toBytes();
    }

    /** A key derived locally from a secret held by the same party; {@code point} is already valid. */
    static NoteReaderKey ofValidated(JubjubPoint point) {
        return new NoteReaderKey(point);
    }

    /**
     * Decodes and validates a received reader key (spec §2.2).
     *
     * @throws IllegalArgumentException if it is not a canonical encoding of a non-identity
     *         point in the prime-order subgroup
     */
    public static NoteReaderKey decode(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        JubjubPoint point = SaplingNoteCrypto.decodeKey(encoded);
        if (point == null) {
            throw new IllegalArgumentException(
                    "a reader key must be a canonical, non-identity point of the prime-order subgroup");
        }
        return new NoteReaderKey(point);
    }

    /**
     * Decodes a reader key for an application registry, and checks its proof of possession: a
     * DLEQ statement of the {@code elgamal-jubjub-v1} §3.3 form, {@code X = G},
     * {@code P = D = key} (spec §2.2; ADR-0055 Q6). Possession is checked once, at registration.
     * It shows that <b>someone</b> knows the key's discrete logarithm, nothing more:
     * <ul>
     *   <li>the statement carries no context, so a published proof can be replayed to register the
     *       same key elsewhere, by anyone;</li>
     *   <li>it is the same statement as {@code elgamal-jubjub-v1} possession, so it does not show
     *       which profile the key is for.</li>
     * </ul>
     * A registry therefore binds each registration to its registrant and to this profile itself
     * (for example with the registrant's signature over the profile id, the key and the
     * registry), and decides which keys it admits.
     *
     * @throws IllegalArgumentException if the key is invalid or the verifier rejects the
     *         statement
     */
    public static NoteReaderKey verified(byte[] encoded, DleqStatementVerifier verifier) {
        Objects.requireNonNull(verifier, "verifier");
        NoteReaderKey key = decode(encoded);
        if (!verifier.verify(key.possessionStatement())) {
            throw new IllegalArgumentException("proof of possession rejected for reader key");
        }
        return key;
    }

    /** The possession statement for this key (spec §2.2). */
    public DleqStatement possessionStatement() {
        return DleqStatement.possession(point);
    }

    /** The 32-byte encoding (spec §2.2). */
    public byte[] encode() {
        return encoding.clone();
    }

    /** The affine {@code u}-coordinate. */
    public BigInteger affineU() {
        return point.affineU();
    }

    /** The affine {@code v}-coordinate. */
    public BigInteger affineV() {
        return point.affineV();
    }

    JubjubPoint point() {
        return point;
    }

    byte[] encodingRef() {
        return encoding;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof NoteReaderKey other && Arrays.equals(encoding, other.encoding);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoding);
    }

    @Override
    public String toString() {
        return "NoteReaderKey{" + HexFormat.of().formatHex(encoding) + "}";
    }
}
