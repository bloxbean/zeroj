package org.zeroj.bls12381.bulletproofs;

import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.ec.G1Point;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * TEST-ONLY: a small generic verifier for the linear-relation sigma protocols of
 * {@code draft-irtf-cfrg-sigma-protocols-03} §3–§5 over {@code sigma-proofs_Shake128_BLS12381}, used to
 * run the draft's Appendix A.3 vectors through this package's transcript and codecs (ADR-0061 I12,
 * spec §10). It reuses {@link DuplexSponge}, {@link FsCodec} and {@link PointCodec}, the code under
 * test; the linear-relation machinery is only what A.3 needs. Not product code.
 */
final class SigmaHarness {

    /** Where a verification ended. */
    enum Layer { ACCEPT, INSTANCE, LENGTH, DESERIALIZATION, VERIFICATION }

    record Result(Layer layer, BigInteger challenge) {
        boolean accepted() {
            return layer == Layer.ACCEPT;
        }
    }

    record Term(int scalarIndex, int elementIndex, BigInteger coeff) {
    }

    record ImageTerm(int elementIndex, BigInteger coeff) {
    }

    record Equation(List<ImageTerm> image, List<Term> terms) {
    }

    record Instance(List<G1Point> elements, List<Equation> equations, byte[] encoding) {
        int numScalars() {
            int max = -1;
            for (Equation e : equations) for (Term t : e.terms) max = Math.max(max, t.scalarIndex);
            return max + 1;
        }
    }

    private SigmaHarness() {
    }

    /**
     * Parses {@code SerializeLinearRelation} output (sigma-03 §3.6). Elements after index 0 are read
     * with the group deserializer, so an identity element fails here (A.3.2 E3 permits either
     * rejection point). Returns null on any parse failure.
     */
    static Instance parse(byte[] bytes) {
        try {
            int[] off = {0};
            int numEq = u32(bytes, off);
            List<Equation> eqs = new ArrayList<>();
            for (int i = 0; i < numEq; i++) {
                int nImage = u32(bytes, off);
                List<ImageTerm> image = new ArrayList<>();
                for (int t = 0; t < nImage; t++) image.add(new ImageTerm(u32(bytes, off), scalar(bytes, off)));
                int nTerms = u32(bytes, off);
                List<Term> terms = new ArrayList<>();
                for (int t = 0; t < nTerms; t++) {
                    int s = u32(bytes, off);
                    terms.add(new Term(s, u32(bytes, off), scalar(bytes, off)));
                }
                eqs.add(new Equation(image, terms));
            }
            int rest = bytes.length - off[0];
            if (rest < 0 || rest % PointCodec.POINT_BYTES != 0) return null;
            List<G1Point> elements = new ArrayList<>();
            elements.add(Bls12381Generators.G1);
            for (int p = off[0]; p < bytes.length; p += PointCodec.POINT_BYTES) {
                elements.add(PointCodec.decode(Arrays.copyOfRange(bytes, p, p + PointCodec.POINT_BYTES)));
            }
            return new Instance(elements, eqs, bytes.clone());
        } catch (CommitmentFormatException | IndexOutOfBoundsException e) {
            return null;
        }
    }

    /** {@code ValidateInstance} (sigma-03 §3.5), checks 1–10. */
    static boolean validate(Instance inst) {
        if (inst.equations.isEmpty() || inst.elements.isEmpty()) return false;            // 1, 7
        if (!inst.elements.get(0).equals(Bls12381Generators.G1)) return false;            // 7
        Set<Integer> usedElements = new HashSet<>();
        Set<Integer> usedScalars = new HashSet<>();
        for (Equation e : inst.equations) {
            if (e.image.isEmpty() || e.terms.isEmpty()) return false;                     // 2
            for (ImageTerm t : e.image) {
                if (t.elementIndex < 0 || t.elementIndex >= inst.elements.size()) return false; // 3, 4
                usedElements.add(t.elementIndex);
            }
            for (Term t : e.terms) {
                if (t.elementIndex < 0 || t.elementIndex >= inst.elements.size() || t.scalarIndex < 0) return false;
                usedElements.add(t.elementIndex);
                usedScalars.add(t.scalarIndex);
            }
        }
        for (int i = 1; i < inst.elements.size(); i++) if (!usedElements.contains(i)) return false; // 5
        for (int s = 0; s < inst.numScalars(); s++) if (!usedScalars.contains(s)) return false;     // 6
        for (G1Point p : inst.elements) if (p.isInfinity()) return false;                          // 8
        for (G1Point p : image(inst)) if (p.isInfinity()) return false;                            // 9
        for (int s = 0; s < inst.numScalars(); s++) {                                              // 10
            boolean nonZero = false;
            for (Equation e : inst.equations) {
                G1Point col = G1Point.INFINITY;
                for (Term t : e.terms) if (t.scalarIndex == s) col = col.add(inst.elements.get(t.elementIndex).scalarMul(t.coeff));
                if (!col.isInfinity()) nonZero = true;
            }
            if (!nonZero) return false;
        }
        return true;
    }

    static List<G1Point> map(Instance inst, BigInteger[] scalars) {
        List<G1Point> out = new ArrayList<>();
        for (Equation e : inst.equations) {
            G1Point acc = G1Point.INFINITY;
            for (Term t : e.terms) {
                acc = acc.add(inst.elements.get(t.elementIndex).scalarMul(RangeMath.mul(t.coeff, scalars[t.scalarIndex])));
            }
            out.add(acc);
        }
        return out;
    }

    static List<G1Point> image(Instance inst) {
        List<G1Point> out = new ArrayList<>();
        for (Equation e : inst.equations) {
            G1Point acc = G1Point.INFINITY;
            for (ImageTerm t : e.image) acc = acc.add(inst.elements.get(t.elementIndex).scalarMul(t.coeff));
            out.add(acc);
        }
        return out;
    }

    /** {@code DeriveChallenge} (sigma-03 §5.2). */
    static BigInteger deriveChallenge(byte[] tag, Instance inst, byte[] commitmentBytes) {
        DuplexSponge ds = DuplexSponge.init(DuplexSponge.deriveSessionId(tag));
        ds.absorb(inst.encoding);
        ds.absorb(commitmentBytes);
        return FsCodec.decodeUint(ds.squeeze(PointCodec.SCALAR_BYTES + 16), PointCodec.Q);
    }

    /** {@code VerifyBatchable} or {@code VerifyCompact} (sigma-03 §5.4, §5.5). */
    static Result verify(String flavor, String tag, byte[] instanceBytes, byte[] narg) {
        byte[] tagBytes = tag.getBytes(StandardCharsets.US_ASCII);
        Instance inst = parse(instanceBytes);
        if (inst == null || !validate(inst)) return new Result(Layer.INSTANCE, null);
        int ns = PointCodec.SCALAR_BYTES, ne = PointCodec.POINT_BYTES;
        int m = inst.equations.size(), s = inst.numScalars();
        try {
            if (flavor.equals("batchable")) {
                if (narg.length != ne * m + ns * s) return new Result(Layer.LENGTH, null);
                List<G1Point> commitment = new ArrayList<>();
                for (int i = 0; i < m; i++) commitment.add(PointCodec.decode(Arrays.copyOfRange(narg, i * ne, (i + 1) * ne)));
                BigInteger[] response = new BigInteger[s];
                for (int i = 0; i < s; i++) response[i] = PointCodec.readScalar(narg, m * ne + i * ns);
                BigInteger c = deriveChallenge(tagBytes, inst, Arrays.copyOf(narg, m * ne));
                List<G1Point> expected = map(inst, response);
                List<G1Point> img = image(inst);
                for (int i = 0; i < m; i++) {
                    if (!expected.get(i).equals(commitment.get(i).add(img.get(i).scalarMul(c)))) {
                        return new Result(Layer.VERIFICATION, c);
                    }
                }
                return new Result(Layer.ACCEPT, c);
            }
            if (!flavor.equals("compact")) throw new IllegalArgumentException(flavor);
            if (narg.length != ns + ns * s) return new Result(Layer.LENGTH, null);
            BigInteger c = PointCodec.readScalar(narg, 0);
            BigInteger[] response = new BigInteger[s];
            for (int i = 0; i < s; i++) response[i] = PointCodec.readScalar(narg, ns + i * ns);
            List<G1Point> mapped = map(inst, response);
            List<G1Point> img = image(inst);
            ByteArrayOutputStream commitmentBytes = new ByteArrayOutputStream();
            for (int i = 0; i < m; i++) {
                G1Point commitment = mapped.get(i).add(img.get(i).scalarMul(c).negate());
                if (commitment.isInfinity()) return new Result(Layer.VERIFICATION, null);
                commitmentBytes.writeBytes(PointCodec.encode(commitment));
            }
            BigInteger expected = deriveChallenge(tagBytes, inst, commitmentBytes.toByteArray());
            return new Result(expected.equals(c) ? Layer.ACCEPT : Layer.VERIFICATION, expected);
        } catch (CommitmentFormatException e) {
            return new Result(Layer.DESERIALIZATION, null);
        }
    }

    private static int u32(byte[] b, int[] off) {
        int o = off[0];
        long v = (b[o] & 0xFFL) | (b[o + 1] & 0xFFL) << 8 | (b[o + 2] & 0xFFL) << 16 | (b[o + 3] & 0xFFL) << 24;
        off[0] = o + 4;
        if (v > Integer.MAX_VALUE) throw new IndexOutOfBoundsException("index too large");
        return (int) v;
    }

    private static BigInteger scalar(byte[] b, int[] off) {
        BigInteger s = PointCodec.readScalar(b, off[0]);
        off[0] += PointCodec.SCALAR_BYTES;
        return s;
    }
}
