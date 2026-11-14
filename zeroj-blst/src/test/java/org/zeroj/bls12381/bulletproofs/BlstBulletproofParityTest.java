package org.zeroj.bls12381.bulletproofs;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.blst.BlstBls12381Provider;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 M2 provider parity (I7): the blst provider and the pure-Java provider give identical
 * proofs with fixed nonces and identical verdicts, on the independent Python vector file and on
 * adversarial inputs. In the zeroj-blst test source set, in the bulletproofs package, so it can build
 * transcript-consistent degenerate proofs. Adopts reviewer (b)'s M1 probes.
 */
class BlstBulletproofParityTest {

    private static final byte[] CTX = "https://example.com/zeroj/blst-parity/v1".getBytes(StandardCharsets.US_ASCII);
    private static final BlstBls12381Provider BLST = BlstBls12381Provider.createDefault();
    private static final G1RangeProver BLST_PROVER = G1RangeProver.withProvider(BLST);
    private static final G1RangeVerifier BLST_VERIFIER = G1RangeVerifier.withProvider(BLST);

    @Test
    @DisplayName("Every case of the vector file holds through blst, with outcomes identical to pure Java")
    void vectors() throws IOException {
        assertSame(BLST, BLST_PROVER.provider());
        assertTrue(BLST_PROVER.supportsProving(), "blst offers a secret-scalar G1 multiplication");
        JsonNode file = BulletproofVectorRunner.load();
        int cases = file.get("positive").size() + file.get("negative").size() + file.get("proverNegative").size();
        BulletproofVectorRunner.Report blst = BulletproofVectorRunner.run(file, BLST_PROVER, BLST_VERIFIER,
                G1Pedersen.withProvider(BLST));
        assertEquals(List.of(), blst.failures(), blst.failures().size() + " failing cases (blst)");
        assertEquals(cases, blst.executed());
        BulletproofVectorRunner.Report pure = BulletproofVectorRunner.run(file, G1RangeProver.pureJava(),
                G1RangeVerifier.pureJava(), G1Pedersen.pureJava());
        assertEquals(List.of(), pure.failures(), "pure Java");
        assertEquals(pure.outcomes(), blst.outcomes(), "provider outcomes differ");
    }

    @Test
    @DisplayName("Proofs made on either provider verify on both; fixed-nonce proofs are byte-identical across providers")
    void crossProvider() {
        for (int bits : new int[] {16, 32, 64}) {
            BigInteger v = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE);
            G1PedersenOpening o = G1PedersenOpening.of(v, BigInteger.valueOf(77));
            byte[] c = G1Pedersen.pureJava().commitScalar(v, BigInteger.valueOf(77)).toPointBytes();
            for (byte[] p : List.of(BLST_PROVER.prove(o, bits, CTX).toBytes(), G1RangeProver.pureJava().prove(o, bits, CTX).toBytes())) {
                assertTrue(G1RangeVerifier.pureJava().verify(c, p, bits, CTX), "pure verifies, n = " + bits);
                assertTrue(BLST_VERIFIER.verify(c, p, bits, CTX), "blst verifies, n = " + bits);
            }
            byte[] seed = new byte[32];
            seed[0] = (byte) bits;
            seed[31] = 0x42;
            assertArrayEquals(TestNonceProver.prove(G1RangeProver.pureJava(), o, bits, CTX, seed).toBytes(),
                    TestNonceProver.prove(BLST_PROVER, o, bits, CTX, seed).toBytes(), "n = " + bits);
        }
    }

    @Test
    @DisplayName("Transcript-consistent proofs whose check coefficients are zero mod q return false on both providers and never throw")
    void zeroCoefficients() {
        G1Point g = BulletproofGenerators.g();
        byte[] vBytes = G1Pedersen.pureJava().commitScalar(BigInteger.valueOf(5), BigInteger.valueOf(7)).toPointBytes();
        G1Point v = PointCodec.decode(vBytes);
        for (int bits : new int[] {16, 32, 64}) {
            int k = RangeTranscript.rounds(bits);
            for (int variant = 0; variant < 4; variant++) {
                G1Point a = g, s = g.negate(), t1 = v, t2 = v.negate();
                RangeTranscript t = RangeTranscript.start(bits, CTX, v);
                BigInteger y = t.absorbPointsSqueeze(a, s);
                BigInteger z = t.challenge();
                t.absorbPointsSqueeze(t1, t2);
                // Variants 0 and 2: t̂ = δ(y, z) with τ_x = μ = 0 gives an identity partial sum in check 1.
                BigInteger tHat = variant % 2 == 0 ? RangeMath.delta(y, z, bits) : BigInteger.ZERO;
                t.absorbScalars(tHat, BigInteger.ZERO, BigInteger.ZERO);
                t.challenge();
                G1Point[] l = new G1Point[k];
                G1Point[] r = new G1Point[k];
                for (int j = 0; j < k; j++) {
                    // Variants 2 and 3: repeated bases.
                    l[j] = variant >= 2 ? g : BulletproofGenerators.gVec(j);
                    r[j] = variant >= 2 ? g.negate() : BulletproofGenerators.hVec(j);
                    t.absorbPointsSqueeze(l[j], r[j]);
                }
                byte[] proof = G1RangeProof.of(bits, a, s, t1, t2, tHat, BigInteger.ZERO, BigInteger.ZERO, l, r,
                        BigInteger.ZERO, BigInteger.ZERO).toBytes();
                assertEquals("false", outcome(G1RangeVerifier.pureJava(), vBytes, proof, bits), "pure, variant " + variant);
                assertEquals("false", outcome(BLST_VERIFIER, vBytes, proof, bits), "blst, variant " + variant);
            }
        }
    }

    @Test
    @DisplayName("Fuzz (fixed seed): providers agree on every tampered proof or commitment, never accept one, and throw only CommitmentFormatException")
    void fuzz() {
        Random rnd = new Random(0xB0B);
        int bits = 16;
        BigInteger value = BigInteger.valueOf(4321), blind = BigInteger.valueOf(8765);
        byte[] c = G1Pedersen.pureJava().commitScalar(value, blind).toPointBytes();
        byte[] good = G1RangeProver.pureJava().prove(G1PedersenOpening.of(value, blind), bits, CTX).toBytes();
        byte[] identity = new byte[48];
        identity[0] = (byte) 0xC0;
        byte[] torsion = new byte[48];
        torsion[0] = (byte) 0x80;
        byte[] uncompressedFlag = Bls12381Codecs.g1ToCompressed(BulletproofGenerators.g());
        uncompressedFlag[0] &= 0x7F;
        byte[] xTooBig = new byte[48];
        Arrays.fill(xTooBig, (byte) 0xFF);
        xTooBig[0] = (byte) 0x9F;
        List<byte[]> points = List.of(identity, torsion, uncompressedFlag, xTooBig,
                Bls12381Codecs.g1ToCompressed(BulletproofGenerators.hVec(3)));
        byte[] ff = new byte[32];
        Arrays.fill(ff, (byte) 0xFF);
        List<byte[]> scalars = List.of(new byte[32], Bls12381Codecs.scalarToBigEndian32(PointCodec.Q.subtract(BigInteger.ONE)), ff);
        List<Integer> pointSlots = new ArrayList<>(List.of(0, 48, 96, 144));
        for (int j = 0; j < 2 * RangeTranscript.rounds(bits); j++) pointSlots.add(4 * 48 + 3 * 32 + 48 * j);
        List<Integer> scalarSlots = List.of(192, 224, 256, good.length - 64, good.length - 32);
        for (int it = 0; it < 200; it++) {
            byte[] p = good.clone();
            byte[] vv = c.clone();
            switch (rnd.nextInt(6)) {
                case 0 -> p[rnd.nextInt(p.length)] ^= (byte) (1 << rnd.nextInt(8));
                case 1 -> {
                    int off = rnd.nextInt(p.length - 4);
                    for (int i = 0; i < 4; i++) p[off + i] = (byte) rnd.nextInt(256);
                }
                case 2 -> System.arraycopy(points.get(rnd.nextInt(points.size())), 0, p, pointSlots.get(rnd.nextInt(pointSlots.size())), 48);
                case 3 -> System.arraycopy(scalars.get(rnd.nextInt(scalars.size())), 0, p, scalarSlots.get(rnd.nextInt(scalarSlots.size())), 32);
                case 4 -> vv = points.get(rnd.nextInt(points.size())).clone();
                default -> p = Arrays.copyOf(p, p.length + (rnd.nextBoolean() ? 1 : -1));
            }
            String pure = outcome(G1RangeVerifier.pureJava(), vv, p, bits);
            String blst = outcome(BLST_VERIFIER, vv, p, bits);
            assertEquals(pure, blst, "providers disagree at iteration " + it);
            assertFalse(pure.startsWith("OTHER"), pure);
            if (!(Arrays.equals(p, good) && Arrays.equals(vv, c))) {
                assertFalse(pure.equals("true"), "tampered input accepted at iteration " + it);
            }
        }
    }

    private static String outcome(G1RangeVerifier verifier, byte[] v, byte[] proof, int bits) {
        try {
            return String.valueOf(verifier.verify(v, proof, bits, CTX));
        } catch (CommitmentFormatException e) {
            return "CFE:" + e.reason();
        } catch (RuntimeException e) {
            return "OTHER:" + e;
        }
    }
}
