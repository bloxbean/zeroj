package com.bloxbean.cardano.zeroj.circuit.lib.ed25519;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Correctness tests for the {@link Ed25519Point} in-circuit gadget.
 *
 * <p>Two-layer oracle: {@link Ed25519Host} (which supplies the gadget's precomputed table) is
 * first validated against <b>BouncyCastle</b> Ed25519 (an authoritative RFC 8032 implementation);
 * the in-circuit gadget is then validated against the trusted host — point addition, encoding,
 * and fixed-base scalar multiplication over several scalars.</p>
 */
class Ed25519PointTest {

    private static final BigInteger P = Ed25519Host.P;
    private static final Random RND = new Random(0x8032L);

    // ------------------------------------------------------------------
    // Layer 1: host vs BouncyCastle (authoritative)
    // ------------------------------------------------------------------

    @Test
    void host_matchesBouncyCastle_overRandomSeeds() {
        for (int t = 0; t < 20; t++) {
            byte[] seed = new byte[32];
            RND.nextBytes(seed);
            byte[] bcPub = new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();

            byte[] h = sha512(seed);
            byte[] lower = new byte[32];
            System.arraycopy(h, 0, lower, 0, 32);
            BigInteger k = Ed25519Host.clampScalar(lower);
            byte[] hostPub = Ed25519Host.encode(Ed25519Host.scalarMulBase(k));

            assertArrayEquals(bcPub, hostPub, "host Ed25519 disagreed with BouncyCastle at seed " + t);
        }
    }

    // ------------------------------------------------------------------
    // Layer 2: circuit vs host
    // ------------------------------------------------------------------

    @Test
    void pointAdd_matchesHost() {
        Ed25519Host.Affine p1 = Ed25519Host.scalarMulBase(BigInteger.valueOf(7));
        Ed25519Host.Affine p2 = Ed25519Host.scalarMulBase(BigInteger.valueOf(13));
        Ed25519Host.Affine sum = Ed25519Host.add(p1, p2); // == 20·B
        BigInteger[] ex = Fe25519.toLimbValues(sum.x());
        BigInteger[] ey = Fe25519.toLimbValues(sum.y());

        var builder = CircuitBuilder.create("ed-add");
        for (int i = 0; i < 5; i++) builder.publicVar("x" + i);
        for (int i = 0; i < 5; i++) builder.publicVar("y" + i);
        builder.define(api -> {
            Ed25519Point r = Ed25519Point.constant(api, p1).add(Ed25519Point.constant(api, p2));
            Variable[] rx = r.affineX().limbs();
            Variable[] ry = r.affineY().limbs();
            for (int i = 0; i < 5; i++) api.assertEqual(rx[i], api.var("x" + i));
            for (int i = 0; i < 5; i++) api.assertEqual(ry[i], api.var("y" + i));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < 5; i++) in.put("x" + i, List.of(ex[i]));
        for (int i = 0; i < 5; i++) in.put("y" + i, List.of(ey[i]));
        assertDoesNotThrow(() -> builder.calculateWitness(in, CurveId.BN254));
    }

    @Test
    void encode_matchesHost() {
        Ed25519Host.Affine pt = Ed25519Host.scalarMulBase(BigInteger.valueOf(1234567));
        byte[] expected = Ed25519Host.encode(pt);
        assertEncodeCircuit(pt, expected);
    }

    @Test
    void scalarMul_smallScalars_matchHost() {
        for (long k : new long[]{1, 2, 5, 8, 255, 1023}) {
            assertScalarMulEncode(BigInteger.valueOf(k), 12);
        }
    }

    @Test
    void scalarMul_randomMediumScalar_matchesHost() {
        BigInteger k = new BigInteger(24, RND).max(BigInteger.ONE);
        assertScalarMulEncode(k, 24);
    }

    @Test
    void constraintCount_scalarMul_bitCost_reported() {
        // Cost of one conditional add (per scalar bit), to project full-scalar-mult size.
        var builder = CircuitBuilder.create("ed-add-cost");
        builder.define(api -> {
            Ed25519Point p = Ed25519Point.constant(api, Ed25519Host.B);
            p.add(Ed25519Point.constant(api, Ed25519Host.B));
        });
        int c = builder.compileR1CS(CurveId.BN254).numConstraints();
        System.out.println("[ADR-0027 M5] Ed25519 point-add constraints = " + c
                + "  (=> ~" + (c * 255L / 1_000_000) + "M for a 255-bit fixed-base scalar mult)");
        assertTrue(c > 0 && c < 200_000);
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /** circuit: encode(k·B) via scalarBits, assert == host encode. */
    private static void assertScalarMulEncode(BigInteger k, int nBits) {
        byte[] expected = Ed25519Host.encode(Ed25519Host.scalarMulBase(k));
        var builder = CircuitBuilder.create("ed-smul-" + k);
        for (int i = 0; i < nBits; i++) builder.secretVar("s" + i);
        for (int i = 0; i < 32; i++) builder.publicVar("e" + i);
        builder.define(api -> {
            Variable[] bits = new Variable[nBits];
            for (int i = 0; i < nBits; i++) bits[i] = api.var("s" + i);
            Variable[] enc = Ed25519Point.scalarMulFixedBaseB(api, bits).encode();
            for (int i = 0; i < 32; i++) api.assertEqual(enc[i], api.var("e" + i));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < nBits; i++) in.put("s" + i, List.of(k.testBit(i) ? BigInteger.ONE : BigInteger.ZERO));
        for (int i = 0; i < 32; i++) in.put("e" + i, List.of(BigInteger.valueOf(expected[i] & 0xff)));
        assertDoesNotThrow(() -> builder.calculateWitness(in, CurveId.BN254), "scalarMul encode mismatch for k=" + k);
    }

    private static void assertEncodeCircuit(Ed25519Host.Affine pt, byte[] expected) {
        var builder = CircuitBuilder.create("ed-encode");
        for (int i = 0; i < 32; i++) builder.publicVar("e" + i);
        builder.define(api -> {
            Variable[] enc = Ed25519Point.constant(api, pt).encode();
            for (int i = 0; i < 32; i++) api.assertEqual(enc[i], api.var("e" + i));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < 32; i++) in.put("e" + i, List.of(BigInteger.valueOf(expected[i] & 0xff)));
        assertDoesNotThrow(() -> builder.calculateWitness(in, CurveId.BN254));
    }

    private static byte[] sha512(byte[] in) {
        try { return MessageDigest.getInstance("SHA-512").digest(in); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
}
