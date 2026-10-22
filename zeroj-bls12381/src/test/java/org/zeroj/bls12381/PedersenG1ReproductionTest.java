package org.zeroj.bls12381;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.ec.G1Point;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0060 M0: the Java reproduction of the {@code pedersen-bls12-381-g1-v1} constants. The expected
 * values are the pinned values of {@code docs/specs/pedersen-bls12-381-g1-v1.md} §2.2 and §10, which
 * the independent Python reference ({@code src/test/resources/pedersen-g1-reference/}) produced
 * without reading this code; this test recomputes them from RFC 9380 primitives.
 */
class PedersenG1ReproductionTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] DST_B =
            "ZeroJ-pedersen-bls12-381-g1-basis-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] DST_S =
            "ZeroJ-pedersen-bls12-381-g1-bytes-v1-H2S-XMD:SHA-256".getBytes(StandardCharsets.US_ASCII);

    private static final String G =
            "80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e";
    private static final String H =
            "92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65";

    @Test
    @DisplayName("Tags are the pinned ASCII strings: 68 and 52 octets")
    void tags() {
        assertEquals(68, DST_B.length);
        assertEquals(52, DST_S.length);
        assertEquals("5a65726f4a2d706564657273656e2d626c7331322d3338312d67312d62617369732d76312d424c53313233383147315f584d443a5348412d3235365f535357555f524f5f",
                HEX.formatHex(DST_B));
        assertEquals("5a65726f4a2d706564657273656e2d626c7331322d3338312d67312d62797465732d76312d4832532d584d443a5348412d323536",
                HEX.formatHex(DST_S));
    }

    @Test
    @DisplayName("G and H are hash_to_curve(\"G\"/\"H\", DST_B), valid, not the identity, and G != ±H")
    void bases() {
        G1Point g = Bls12381Hash.hashToG1(new byte[] {0x47}, DST_B);
        G1Point h = Bls12381Hash.hashToG1(new byte[] {0x48}, DST_B);
        assertEquals(G, HEX.formatHex(Bls12381Codecs.g1ToCompressed(g)));
        assertEquals(H, HEX.formatHex(Bls12381Codecs.g1ToCompressed(h)));
        for (G1Point p : new G1Point[] {g, h}) {
            assertFalse(p.isInfinity());
            assertTrue(p.isOnCurve());
            assertTrue(p.isInSubgroup());
        }
        assertNotEquals(g, h);
        assertNotEquals(g, h.negate());
    }

    @Test
    @DisplayName("HashBytesToScalarG1 reproduces the §10.2 test values")
    void byteMapping() {
        String[][] cases = {
                {"0", "62afac35dff21f5a55ff2569ca3c589ef5401cfc94aafe1110981e7c11b89a13d931cede053d24094deda3524a53b80e",
                        "36315447437668222813564192209050807153821375512821708312164585800119004767398"},
                {"1", "8bf9523b8cfad53f2a64e7c124b637a4a7dc7665d60ccf16e2f3e260b04ddbf366a510869c7e787d331c35a9222f28cc",
                        "17446826573447758279414620354847772216162392386874241427805739007456445167270"},
                {"55", "e219c89968b49b2d930e377d427b7e56c65473ea36c92f6ce02e5efc83974e69fbba34909f18fe9c76d6147d1a65c7cc",
                        "4769885727161205208895793752532058125538937305946508790125793345496789763442"},
                {"56", "91f731ee2e033609f3f27e1fcfac8202c8d415cc5ac5597eee949f5a96dfb4965d739d0a583b4273d5dae005a9cc45e0",
                        "44447803342360626358699221713325796379764762051949152351159963802212607565535"},
                {"64", "d4acbd20d83ed5a47394b62c6e2301b5cdca43e1dabcbe10a0999adb71f7becdcc3fc44e845702440a04e54975607dfd",
                        "21158407019535989839516034496492483749423603674815396635618901986493989358291"},
                {"129", "90293fbe6622a3d8ed03f6f733dd36eba35919771d85be7e2dc88aac08c8c365a6eeaaee7a536bc38b40d5eac62c06df",
                        "10636700515201835153547363743684853122590858874478588016559740395075199699391"},
                {"1024", "d968d99d55ccb4300830c9ca5bf4a5e7e352e71f2b43a1e7357487eab5259b1b7a1540a8bb690e50009d8b4b2fa12797",
                        "51032631804351372587695208740820262018544153677477339797817422801122177762967"},
        };
        for (String[] c : cases) {
            int n = Integer.parseInt(c[0]);
            byte[] payload = new byte[n];
            for (int i = 0; i < n; i++) payload[i] = (byte) (131 * i + 17);
            assertMapping(payload, c[1], c[2]);
        }
        assertMapping("abc".getBytes(StandardCharsets.US_ASCII),
                "0648a88bce794163caa6686ba5d3bbf550c02d8e842a550642ef33832468ead60428b888e585dfe40c33f79db5f2b3e7",
                "425016933681726855004915202875618514367841089254790273686098534787449164925");
    }

    @Test
    @DisplayName("Commitments C(m, r) = [m]G + [r]H reproduce the §10.3 test values")
    void commitments() {
        G1Point g = Bls12381Codecs.g1FromCompressed(HEX.parseHex(G));
        G1Point h = Bls12381Codecs.g1FromCompressed(HEX.parseHex(H));
        BigInteger qMinus1 = G1Point.R.subtract(BigInteger.ONE);
        assertCommitment(g, h, BigInteger.ZERO, BigInteger.ZERO,
                "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        assertCommitment(g, h, BigInteger.ONE, BigInteger.ZERO, G);
        assertCommitment(g, h, BigInteger.ZERO, BigInteger.ONE, H);
        assertCommitment(g, h, qMinus1, qMinus1,
                "830c22c1792dae9774b23f9c31801a964094bef7734745f4012b4e5c133a5d608636f1e020d68cb2688ad276369b8650");
        assertCommitment(g, h, BigInteger.valueOf(12345), BigInteger.valueOf(67890),
                "8c5b1e42a3912ecf2a2fc27a26ef67afd30799614ebfbd5dc7a2cb00e43b063a60a4d516007352cddecd632d2b758fc4");
    }

    private static void assertMapping(byte[] payload, String uniformHex, String scalar) {
        byte[] msg = new byte[payload.length + 8];
        System.arraycopy(payload, 0, msg, 0, payload.length);
        long n = payload.length;
        for (int i = 0; i < 8; i++) msg[payload.length + i] = (byte) (n >>> (56 - 8 * i));
        byte[] uniform = Bls12381Hash.expandMessageXmdSha256(msg, DST_S, 48);
        assertEquals(uniformHex, HEX.formatHex(uniform), "n = " + n);
        assertEquals(new BigInteger(scalar), new BigInteger(1, uniform).mod(G1Point.R), "n = " + n);
    }

    private static void assertCommitment(G1Point g, G1Point h, BigInteger m, BigInteger r, String expected) {
        G1Point c = g.scalarMul(m).add(h.scalarMul(r));
        assertEquals(expected, HEX.formatHex(Bls12381Codecs.g1ToCompressed(c)));
    }
}
