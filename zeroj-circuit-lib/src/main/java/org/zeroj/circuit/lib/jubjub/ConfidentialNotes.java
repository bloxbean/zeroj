package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.IntFunction;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * {@code confidential-note-jubjub-v1} (ADR-0055): a note's opening, delivered on-chain to each
 * of its readers by Diffie–Hellman on Jubjub, with Zcash Sapling's key agreement, KDF and
 * symmetric encryption (spec §1).
 *
 * <pre>{@code
 * NoteOpening opening = NoteOpening.random(value, random);
 * JubjubPoint c = opening.commitment();                       // the note's datum commitment
 * List<byte[]> deliveries = ConfidentialNotes.seal(opening, List.of(owner, auditor), random);
 * // ... recipient:
 * Optional<NoteOpening> mine = NoteScanner.of(viewingKey).open(deliveries.get(0), c);
 * }</pre>
 *
 * <p><b>Rules the library enforces:</b> reader keys are valid (I5) and pairwise distinct; every
 * reader gets a fresh ephemeral key (D7, I2); the plaintext is fixed-length (D6). <b>Rules that
 * stay the application's:</b> the reader order (owner first, then auditors in registry order),
 * the note container and its validator checks (D8), and the owner-credential check on receipt
 * (spec §5).
 *
 * <p>Secret operations are compatibility/offline class (ADR-0039 §3.1). Sealing to {@code k}
 * readers costs two blinded scalar multiplications per reader.
 */
public final class ConfidentialNotes {

    /** The length of one delivery, {@code E ‖ ct} (spec §3.2). */
    public static final int DELIVERY_LENGTH = 89;
    /** The length of the plaintext (spec §3.1). */
    static final int PLAINTEXT_LENGTH = 41;
    static final int CIPHERTEXT_LENGTH = PLAINTEXT_LENGTH + Aead.TAG_LENGTH;
    static final byte VERSION = 0x01;

    private ConfidentialNotes() {
    }

    /**
     * Seals {@code opening} to every reader, in order (spec §4). Each reader gets its own fresh
     * ephemeral key. The result has one 89-byte delivery per reader, in the same order.
     *
     * @throws IllegalArgumentException if there are no readers or two readers have the same key
     * @throws IllegalStateException    if the platform's ChaCha20-Poly1305 fails its self-test
     */
    public static List<byte[]> seal(NoteOpening opening, List<NoteReaderKey> readers, SecureRandom random) {
        Objects.requireNonNull(random, "random");
        return seal(opening, readers, i -> sampleEphemeral(random));
    }

    /**
     * Test seam: {@link #seal} with the ephemeral secret for reader {@code i} supplied by
     * {@code ephemeral} (spec §9.1 test keys). Production code uses fresh randomness only.
     */
    static List<byte[]> seal(NoteOpening opening, List<NoteReaderKey> readers, IntFunction<BigInteger> ephemeral) {
        Objects.requireNonNull(opening, "opening");
        Objects.requireNonNull(readers, "readers");
        Objects.requireNonNull(ephemeral, "ephemeral");
        List<NoteReaderKey> ordered = List.copyOf(readers);
        if (ordered.isEmpty()) {
            throw new IllegalArgumentException("a note needs at least one reader");
        }
        Set<ByteBuffer> seen = new HashSet<>();
        for (NoteReaderKey reader : ordered) {
            if (!seen.add(ByteBuffer.wrap(reader.encodingRef()))) {
                throw new IllegalArgumentException("reader keys must be pairwise distinct");
            }
        }
        NoteAeadSelfTest.run();
        byte[] pt = plaintext(opening);
        try {
            List<byte[]> out = new ArrayList<>(ordered.size());
            for (int i = 0; i < ordered.size(); i++) {
                out.add(sealOne(pt, ordered.get(i), ephemeral.apply(i)));
            }
            return out;
        } finally {
            Arrays.fill(pt, (byte) 0);
        }
    }

    /** One delivery of {@code pt} to {@code reader} under the ephemeral secret {@code e} (spec §4 step 3). */
    static byte[] sealOne(byte[] pt, NoteReaderKey reader, BigInteger e) {
        Objects.requireNonNull(e, "ephemeral");
        byte[] ephemeralKey = SaplingNoteCrypto.derivePublic(e).toBytes();
        JubjubPoint shared = SaplingNoteCrypto.agree(e, reader.point());
        byte[] key = SaplingNoteCrypto.kdf(SaplingNoteCrypto.PERSONALIZATION, shared, ephemeralKey);
        try {
            byte[] ct = SaplingNoteCrypto.encrypt(key, pt);
            byte[] delivery = new byte[DELIVERY_LENGTH];
            System.arraycopy(ephemeralKey, 0, delivery, 0, SaplingNoteCrypto.POINT_LENGTH);
            System.arraycopy(ct, 0, delivery, SaplingNoteCrypto.POINT_LENGTH, CIPHERTEXT_LENGTH);
            return delivery;
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /** {@code 0x01 ‖ I2OSP(v, 8) ‖ I2OSP(r, 32)} (spec §3.1). */
    static byte[] plaintext(NoteOpening opening) {
        byte[] pt = new byte[PLAINTEXT_LENGTH];
        pt[0] = VERSION;
        long v = opening.value().longValue(); // the low 64 bits; value < 2^64
        for (int i = 0; i < 8; i++) {
            pt[8 - i] = (byte) (v >>> (8 * i));
        }
        byte[] r = DkgMessage.i2osp32(opening.blinding());
        System.arraycopy(r, 0, pt, 9, 32);
        Arrays.fill(r, (byte) 0);
        return pt;
    }

    /**
     * Parses a decrypted plaintext (spec §5 step 6): returns the opening, or {@code null} if the
     * length or version byte is wrong or {@code r ≥ l}.
     */
    static NoteOpening parsePlaintext(byte[] pt) {
        if (pt == null || pt.length != PLAINTEXT_LENGTH || pt[0] != VERSION) {
            return null;
        }
        byte[] vBytes = Arrays.copyOfRange(pt, 1, 9);
        byte[] rBytes = Arrays.copyOfRange(pt, 9, PLAINTEXT_LENGTH);
        try {
            BigInteger r = new BigInteger(1, rBytes);
            if (r.compareTo(SUBGROUP_ORDER) >= 0) {
                return null;
            }
            return NoteOpening.of(new BigInteger(1, vBytes), r);
        } finally {
            Arrays.fill(vBytes, (byte) 0);
            Arrays.fill(rBytes, (byte) 0);
        }
    }

    /** An ephemeral secret {@code e ∈ [1, l)} (spec §2.1). */
    private static BigInteger sampleEphemeral(SecureRandom random) {
        while (true) {
            BigInteger e = ElGamal.sample(random);
            if (e.signum() != 0) {
                return e;
            }
        }
    }
}
