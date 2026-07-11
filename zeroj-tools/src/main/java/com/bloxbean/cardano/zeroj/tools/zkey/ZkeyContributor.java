package com.bloxbean.cardano.zeroj.ceremony;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.poly.FrFFTFlat;
import org.bouncycastle.crypto.digests.Blake2bDigest;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * ZeroJ-native Groth16 phase-2 contributor (ADR-0031 M5, Option B) — a bit-compatible
 * reimplementation of {@code snarkjs zkey contribute}: reads a ceremony {@code .zkey}, applies a
 * fresh secret {@code k} (delta ← k·delta in the header; every L- and H-section point ← k⁻¹·point,
 * multi-core), and appends the BGM17 proof-of-knowledge record to the contributions section — in
 * the exact snarkjs byte format, so the resulting transcript still verifies with stock
 * {@code snarkjs zkey verify} and further snarkjs contributions can stack on top.
 *
 * <p>The challenge point is derived via {@link SnarkjsHashToG2} over the blake2b-512 transcript
 * (csHash ‖ prior contributions ‖ s-pair), mirroring snarkjs exactly. The contributor's secret
 * {@code k} and the s-pair base come from {@link SecureRandom} (no compatibility requirement —
 * only the challenge derivation must match).</p>
 */
public final class ZkeyContributor {

    private ZkeyContributor() {}

    private static final ValueLayout.OfInt U32 = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    private static final ValueLayout.OfLong U64 = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

    private static final BigInteger P = MontFp381.modulus();
    private static final BigInteger R_FR = MontFr381.modulus();
    private static final BigInteger MONT_R = BigInteger.ONE.shiftLeft(384).mod(P);
    private static final BigInteger MONT_R_INV = MONT_R.modInverse(P);

    // section-2 offsets (fixed layout, validated on read)
    private static final long H_DELTA1 = 676, H_DELTA2 = 772, HEADER_LEN = 964;

    /** @return the contribution hash (blake2b-512 of the new record's public key) — publish it. */
    public static byte[] contribute(Path in, Path out, String name) throws IOException {
        try (FileChannel inCh = FileChannel.open(in, StandardOpenOption.READ);
             Arena arena = Arena.ofShared()) {
            long inSize = inCh.size();
            MemorySegment z = inCh.map(FileChannel.MapMode.READ_ONLY, 0, inSize, arena);

            if (z.get(U32, 0) != 0x79656b7a) throw new IOException("Invalid .zkey magic");
            int nSections = z.get(U32, 8);
            Map<Integer, long[]> sec = new HashMap<>();
            long pos = 12;
            for (int i = 0; i < nSections; i++) {
                int type = z.get(U32, pos);
                long size = z.get(U64, pos + 4);
                pos += 12;
                sec.put(type, new long[]{pos, size});
                pos += size;
            }
            for (int s : new int[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
                if (!sec.containsKey(s)) throw new IOException("Missing .zkey section " + s);
            if (z.get(U32, sec.get(1)[0]) != 1) throw new IOException("Not a Groth16 .zkey");
            if (sec.get(2)[1] != HEADER_LEN) throw new IOException("Unexpected Groth16 header length");

            long h = sec.get(2)[0];
            if (z.get(U32, h) != 48 || z.get(U32, h + 52) != 32)
                throw new IOException("Not a BLS12-381 .zkey");

            AffineG1 delta1 = g1FromLem(z, h + H_DELTA1);
            AffineG2 delta2 = g2FromLem(z, h + H_DELTA2);

            // section 10: csHash + prior contribution records (raw for copy, parsed for hashing)
            long s10 = sec.get(10)[0];
            byte[] csHash = bytes(z, s10, 64);
            int nContrib = z.get(U32, s10 + 64);
            long rp = s10 + 68;
            List<byte[]> priorRaw = new ArrayList<>();
            List<Object[]> priors = new ArrayList<>(); // [deltaAfter, g1s, g1sx, g2spx, transcript]
            for (int i = 0; i < nContrib; i++) {
                long start = rp;
                AffineG1 deltaAfter = g1FromLem(z, rp);
                AffineG1 g1s = g1FromLem(z, rp + 96);
                AffineG1 g1sx = g1FromLem(z, rp + 192);
                AffineG2 g2spx = g2FromLem(z, rp + 288);
                byte[] transcript = bytes(z, rp + 480, 64);
                rp += 480 + 64 + 4;                      // + type
                long paramLen = Integer.toUnsignedLong(z.get(U32, rp));
                rp += 4 + paramLen;
                priorRaw.add(bytes(z, start, rp - start));
                priors.add(new Object[]{deltaAfter, g1s, g1sx, g2spx, transcript});
            }

            // fresh secret + s-pair
            SecureRandom rnd = new SecureRandom();
            BigInteger k = randScalar(rnd);
            BigInteger s = randScalar(rnd);
            AffineG1 g1s = JacobianG1BLS381.GENERATOR.scalarMul(s).toAffine();
            AffineG1 g1sx = JacobianG1BLS381.fromAffine(g1s.xBigInt(), g1s.yBigInt()).scalarMul(k).toAffine();

            // transcript = blake2b512(csHash ‖ RAW fields of every prior record ‖ unc(g1_s) ‖ unc(g1_sx))
            // — snarkjs streams each prior's components into ONE running hasher (hashPubKey(hasher, c)),
            // NOT the priors' sub-hashes. (The two coincide only with zero priors.)
            Blake2bDigest th = new Blake2bDigest(512);
            update(th, csHash);
            for (Object[] c : priors)
                hashPubKeyInto(th, (AffineG1) c[0], (AffineG1) c[1], (AffineG1) c[2], (AffineG2) c[3], (byte[]) c[4]);
            update(th, g1Unc(g1s));
            update(th, g1Unc(g1sx));
            byte[] transcript = digest(th);

            AffineG2 g2sp = SnarkjsHashToG2.hashToG2(transcript);
            AffineG2 g2spx = JacobianG2BLS381.fromAffine(g2sp.x(), g2sp.y()).scalarMul(k).toAffine();

            AffineG1 delta1New = JacobianG1BLS381.fromAffine(delta1.xBigInt(), delta1.yBigInt()).scalarMul(k).toAffine();
            AffineG2 delta2New = JacobianG2BLS381.fromAffine(delta2.x(), delta2.y()).scalarMul(k).toAffine();
            BigInteger kInv = k.modInverse(R_FR);

            // new contribution record
            byte[] nameBytes = name == null ? new byte[0]
                    : name.substring(0, Math.min(name.length(), 64)).getBytes(StandardCharsets.UTF_8);
            byte[] params = nameBytes.length == 0 ? new byte[0] : concat(new byte[]{1, (byte) nameBytes.length}, nameBytes);
            byte[] record = concat(
                    g1Lem(delta1New), g1Lem(g1s), g1Lem(g1sx), g2Lem(g2spx), transcript,
                    u32(0), u32(params.length), params);

            // ---- write the new zkey ----
            long s10NewSize = 64 + 4 + priorRaw.stream().mapToLong(b -> b.length).sum() + record.length;
            long total = 12
                    + 12 + sec.get(1)[1] + 12 + sec.get(2)[1]
                    + 12 + sec.get(3)[1] + 12 + sec.get(4)[1] + 12 + sec.get(5)[1]
                    + 12 + sec.get(6)[1] + 12 + sec.get(7)[1] + 12 + sec.get(8)[1]
                    + 12 + sec.get(9)[1] + 12 + s10NewSize;

            Files.deleteIfExists(out);
            try (FileChannel outCh = FileChannel.open(out, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                MemorySegment o = outCh.map(FileChannel.MapMode.READ_WRITE, 0, total, arena);
                long w = 0;
                o.set(U32, 0, 0x79656b7a); o.set(U32, 4, 1); o.set(U32, 8, 10);
                w = 12;
                w = section(o, w, 1, sec.get(1)[1]);
                o.set(U32, w, 1); w += sec.get(1)[1];                      // protocol groth16
                w = section(o, w, 2, sec.get(2)[1]);
                MemorySegment.copy(z, sec.get(2)[0], o, w, sec.get(2)[1]); // header, then patch deltas
                put(o, w + H_DELTA1, g1Lem(delta1New));
                put(o, w + H_DELTA2, g2Lem(delta2New));
                w += sec.get(2)[1];
                for (int t : new int[]{3, 4, 5, 6, 7}) {                   // unchanged sections
                    w = section(o, w, t, sec.get(t)[1]);
                    MemorySegment.copy(z, sec.get(t)[0], o, w, sec.get(t)[1]);
                    w += sec.get(t)[1];
                }
                for (int t : new int[]{8, 9}) {                            // L, H ← kInv·point
                    w = section(o, w, t, sec.get(t)[1]);
                    rescaleG1Section(z, sec.get(t)[0], o, w, (int) (sec.get(t)[1] / 96), kInv);
                    w += sec.get(t)[1];
                }
                w = section(o, w, 10, s10NewSize);
                put(o, w, csHash);
                o.set(U32, w + 64, nContrib + 1);
                long q = w + 68;
                for (byte[] raw : priorRaw) { put(o, q, raw); q += raw.length; }
                put(o, q, record);
            }

            Blake2bDigest ch = new Blake2bDigest(512);
            hashPubKeyInto(ch, delta1New, g1s, g1sx, g2spx, transcript);
            return digest(ch);
        }
    }

    // ---- L/H rescale (multi-core) ----

    private static void rescaleG1Section(MemorySegment in, long inOff, MemorySegment out, long outOff,
                                         int count, BigInteger kInv) {
        FrFFTFlat.parallelRange(count, (lo, hi) -> {
            for (int i = lo; i < hi; i++) {
                AffineG1 p = g1FromLem(in, inOff + i * 96L);
                AffineG1 r = p.isInfinity() ? p
                        : JacobianG1BLS381.fromAffine(p.xBigInt(), p.yBigInt()).scalarMul(kInv).toAffine();
                put(out, outOff + i * 96L, g1Lem(r));
            }
        });
    }

    // ---- point codecs (LEM = little-endian Montgomery; Unc = canonical big-endian) ----

    private static AffineG1 g1FromLem(MemorySegment z, long off) {
        BigInteger x = fromMontLE(z, off), y = fromMontLE(z, off + 48);
        if (x.signum() == 0 && y.signum() == 0) return AffineG1.INFINITY;
        return new AffineG1(MontFp381.fromBigInteger(x), MontFp381.fromBigInteger(y));
    }

    private static AffineG2 g2FromLem(MemorySegment z, long off) {
        return new AffineG2(
                MontFp2_381.of(fromMontLE(z, off), fromMontLE(z, off + 48)),
                MontFp2_381.of(fromMontLE(z, off + 96), fromMontLE(z, off + 144)));
    }

    private static byte[] g1Lem(AffineG1 p) {
        byte[] b = new byte[96];
        if (p.isInfinity()) return b;
        montLE(p.xBigInt(), b, 0);
        montLE(p.yBigInt(), b, 48);
        return b;
    }

    private static byte[] g2Lem(AffineG2 p) {
        byte[] b = new byte[192];
        if (p.isInfinity()) return b;
        montLE(p.x().reBigInt(), b, 0);
        montLE(p.x().imBigInt(), b, 48);
        montLE(p.y().reBigInt(), b, 96);
        montLE(p.y().imBigInt(), b, 144);
        return b;
    }

    private static byte[] g1Unc(AffineG1 p) {
        byte[] b = new byte[96];
        if (p.isInfinity()) return b;
        be48(p.xBigInt(), b, 0);
        be48(p.yBigInt(), b, 48);
        return b;
    }

    private static byte[] g2Unc(AffineG2 p) {
        byte[] b = new byte[192];
        if (p.isInfinity()) return b;
        be48(p.x().imBigInt(), b, 0);    // c1 first (byte-reverse of the LE c0‖c1 block)
        be48(p.x().reBigInt(), b, 48);
        be48(p.y().imBigInt(), b, 96);
        be48(p.y().reBigInt(), b, 144);
        return b;
    }

    /** snarkjs {@code hashPubKey(hasher, curve, c)}: stream the record's raw components into {@code d}. */
    private static void hashPubKeyInto(Blake2bDigest d, AffineG1 deltaAfter, AffineG1 g1s, AffineG1 g1sx,
                                       AffineG2 g2spx, byte[] transcript) {
        update(d, g1Unc(deltaAfter));
        update(d, g1Unc(g1s));
        update(d, g1Unc(g1sx));
        update(d, g2Unc(g2spx));
        update(d, transcript);
    }

    // ---- low-level helpers ----

    private static BigInteger fromMontLE(MemorySegment z, long off) {
        byte[] le = bytes(z, off, 48);
        byte[] be = new byte[48];
        for (int i = 0; i < 48; i++) be[i] = le[47 - i];
        return new BigInteger(1, be).multiply(MONT_R_INV).mod(P);
    }

    private static void montLE(BigInteger v, byte[] out, int off) {
        byte[] be = v.multiply(MONT_R).mod(P).toByteArray();
        int s = Math.max(0, be.length - 48), len = be.length - s;
        for (int i = 0; i < len; i++) out[off + i] = be[be.length - 1 - i];
    }

    private static void be48(BigInteger v, byte[] out, int off) {
        byte[] be = v.toByteArray();
        int s = Math.max(0, be.length - 48), len = be.length - s;
        System.arraycopy(be, s, out, off + 48 - len, len);
    }

    private static BigInteger randScalar(SecureRandom rnd) {
        BigInteger v;
        do { v = new BigInteger(512, rnd).mod(R_FR); } while (v.signum() == 0);
        return v;
    }

    private static byte[] bytes(MemorySegment z, long off, long len) {
        byte[] b = new byte[(int) len];
        MemorySegment.copy(z, off, MemorySegment.ofArray(b), 0, len);
        return b;
    }

    private static void put(MemorySegment o, long off, byte[] b) {
        MemorySegment.copy(MemorySegment.ofArray(b), 0, o, off, b.length);
    }

    private static long section(MemorySegment o, long w, int type, long size) {
        o.set(U32, w, type);
        o.set(U64, w + 4, size);
        return w + 12;
    }

    private static byte[] u32(int v) {
        return new byte[]{(byte) v, (byte) (v >>> 8), (byte) (v >>> 16), (byte) (v >>> 24)};
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) len += p.length;
        byte[] r = new byte[len];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, r, o, p.length); o += p.length; }
        return r;
    }

    private static void update(Blake2bDigest d, byte[] b) { d.update(b, 0, b.length); }

    private static byte[] digest(Blake2bDigest d) {
        byte[] out = new byte[64];
        d.doFinal(out, 0);
        return out;
    }
}
