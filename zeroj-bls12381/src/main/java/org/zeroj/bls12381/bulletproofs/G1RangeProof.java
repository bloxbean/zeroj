package org.zeroj.bls12381.bulletproofs;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.api.commitment.ProofProtocol;
import org.zeroj.api.commitment.ProofProtocols;
import org.zeroj.bls12381.ec.G1Point;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A {@code bulletproof-range-bls12-381-g1-v1} range proof: the NARG string of spec §6, of
 * {@code 48·(4 + 2k) + 160} octets (736, 832 or 928 for {@code n} = 16, 32, 64).
 *
 * <p>An instance is immutable and always well-formed for its width: every point is a strictly
 * decoded element of the prime-order subgroup other than the identity, and every scalar is in
 * {@code [0, q)}. It says nothing about validity: only {@link G1RangeVerifier} decides that, under
 * its own configured width and context.
 *
 * <p>Experimental: not approved for value-bearing or mainnet use.
 */
public final class G1RangeProof {

    /** The proof protocol this type implements. A constant is not admission (registry §2.3). */
    public static final ProofProtocol PROTOCOL = ProofProtocols.BULLETPROOF_RANGE_BLS12_381_G1_V1;

    private final int bits;
    private final byte[] encoding;
    private final G1Point a;
    private final G1Point s;
    private final G1Point t1;
    private final G1Point t2;
    private final BigInteger tHat;
    private final BigInteger tauX;
    private final BigInteger mu;
    private final G1Point[] l;
    private final G1Point[] r;
    private final BigInteger aFinal;
    private final BigInteger bFinal;

    private G1RangeProof(int bits, byte[] encoding, G1Point a, G1Point s, G1Point t1, G1Point t2, BigInteger tHat,
                         BigInteger tauX, BigInteger mu, G1Point[] l, G1Point[] r, BigInteger aFinal,
                         BigInteger bFinal) {
        this.bits = bits;
        this.encoding = encoding;
        this.a = a;
        this.s = s;
        this.t1 = t1;
        this.t2 = t2;
        this.tHat = tHat;
        this.tauX = tauX;
        this.mu = mu;
        this.l = l;
        this.r = r;
        this.aFinal = aFinal;
        this.bFinal = bFinal;
    }

    /** The proof length in octets for width {@code bits} ∈ {16, 32, 64} (spec §6). */
    public static int length(int bits) {
        requireBits(bits);
        return PointCodec.POINT_BYTES * (4 + 2 * RangeTranscript.rounds(bits)) + 5 * PointCodec.SCALAR_BYTES;
    }

    /**
     * Strictly decodes a proof for width {@code bits}, which must come from the verifier's
     * configuration, never from the proof (spec §8). Checks, in order (spec §8.1 steps 1–3):
     * {@code bits ∈ {16, 32, 64}} ({@code INVALID_CONFIGURATION}); the exact length, before any octet
     * is read ({@code MALFORMED_ENCODING}); then each field in proof order, reporting the first
     * failure: a point that is malformed or the identity ({@code MALFORMED_ENCODING}) or outside the
     * subgroup ({@code NOT_IN_SUBGROUP}), a scalar not below {@code q} ({@code NON_CANONICAL_SCALAR}).
     * The input is copied.
     *
     * @throws NullPointerException      if {@code proof} is null
     * @throws CommitmentFormatException with the class of the first failure
     */
    public static G1RangeProof decode(byte[] proof, int bits) {
        Objects.requireNonNull(proof, "proof");
        requireBits(bits);
        byte[] bytes = proof.clone();
        if (bytes.length != length(bits)) {
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING,
                    "a " + bits + "-bit range proof is " + length(bits) + " octets");
        }
        Reader in = new Reader(bytes);
        G1Point a = in.point();
        G1Point s = in.point();
        G1Point t1 = in.point();
        G1Point t2 = in.point();
        BigInteger tHat = in.scalar();
        BigInteger tauX = in.scalar();
        BigInteger mu = in.scalar();
        int k = RangeTranscript.rounds(bits);
        G1Point[] l = new G1Point[k];
        G1Point[] r = new G1Point[k];
        for (int j = 0; j < k; j++) {
            l[j] = in.point();
            r[j] = in.point();
        }
        BigInteger aFinal = in.scalar();
        BigInteger bFinal = in.scalar();
        return new G1RangeProof(bits, bytes, a, s, t1, t2, tHat, tauX, mu, l, r, aFinal, bFinal);
    }

    /** Assembles a proof from its parts (the prover), encoding them in spec §6 order. */
    static G1RangeProof of(int bits, G1Point a, G1Point s, G1Point t1, G1Point t2, BigInteger tHat, BigInteger tauX,
                           BigInteger mu, G1Point[] l, G1Point[] r, BigInteger aFinal, BigInteger bFinal) {
        byte[] out = new byte[length(bits)];
        int offset = 0;
        for (G1Point p : List.of(a, s, t1, t2)) {
            offset = writePoint(p, out, offset);
        }
        for (BigInteger x : List.of(tHat, tauX, mu)) {
            PointCodec.writeScalar(x, out, offset);
            offset += PointCodec.SCALAR_BYTES;
        }
        for (int j = 0; j < l.length; j++) {
            offset = writePoint(l[j], out, offset);
            offset = writePoint(r[j], out, offset);
        }
        PointCodec.writeScalar(aFinal, out, offset);
        PointCodec.writeScalar(bFinal, out, offset + PointCodec.SCALAR_BYTES);
        return new G1RangeProof(bits, out, a, s, t1, t2, tHat, tauX, mu, l.clone(), r.clone(), aFinal, bFinal);
    }

    /** The width this proof was decoded or produced for. */
    public int bits() {
        return bits;
    }

    /** A fresh copy of the proof octets. */
    public byte[] toBytes() {
        return encoding.clone();
    }

    G1Point a() { return a; }
    G1Point s() { return s; }
    G1Point t1() { return t1; }
    G1Point t2() { return t2; }
    BigInteger tHat() { return tHat; }
    BigInteger tauX() { return tauX; }
    BigInteger mu() { return mu; }
    G1Point l(int j) { return l[j]; }
    G1Point r(int j) { return r[j]; }
    BigInteger aFinal() { return aFinal; }
    BigInteger bFinal() { return bFinal; }

    @Override
    public boolean equals(Object other) {
        return other instanceof G1RangeProof that && bits == that.bits && Arrays.equals(encoding, that.encoding);
    }

    @Override
    public int hashCode() {
        return 31 * bits + Arrays.hashCode(encoding);
    }

    @Override
    public String toString() {
        return "G1RangeProof[" + PROTOCOL.id() + ", " + bits + " bits, " + encoding.length + " octets]";
    }

    static void requireBits(int bits) {
        if (bits != 16 && bits != 32 && bits != 64) {
            throw new CommitmentFormatException(CommitmentError.INVALID_CONFIGURATION, "bits must be 16, 32 or 64");
        }
    }

    private static int writePoint(G1Point p, byte[] out, int offset) {
        System.arraycopy(PointCodec.encode(p), 0, out, offset, PointCodec.POINT_BYTES);
        return offset + PointCodec.POINT_BYTES;
    }

    /** Reads fields front to back; the length was already checked. */
    private static final class Reader {
        private final byte[] bytes;
        private int offset;

        Reader(byte[] bytes) {
            this.bytes = bytes;
        }

        G1Point point() {
            G1Point p = PointCodec.decode(Arrays.copyOfRange(bytes, offset, offset + PointCodec.POINT_BYTES));
            offset += PointCodec.POINT_BYTES;
            return p;
        }

        BigInteger scalar() {
            BigInteger x = PointCodec.readScalar(bytes, offset);
            offset += PointCodec.SCALAR_BYTES;
            return x;
        }
    }
}
