package org.zeroj.bls12381.bulletproofs;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 I2, spec §5.1: the session tag for contexts with every kind of octet, at every width. The
 * expected tags are written out by hand from the spec; the expected session identifiers were computed
 * with the CFRG drafts' own proof-of-concept {@code fiat_shamir.py} at commit 91cc933 (not ZeroJ
 * code), so a context encoding that drops a leading zero or a high bit fails here even though prover
 * and verifier would agree with each other (reviewer (c), M1 F1).
 */
class TranscriptTagTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String PREFIX =
            "ZeroJ:bulletproof-range-bls12-381-g1-v1/DSFS-fiat-shamir-03-sigma-proofs_Shake128_BLS12381";

    @Test
    @DisplayName("A context with 0x00, 0x0f, 0x10, 0x7f, 0x80 and 0xff octets (n = 16)")
    void allOctetClasses() throws Exception {
        byte[] ctx = {0x00, 0x0f, 0x10, 0x7f, (byte) 0x80, (byte) 0xff};
        check(16, ctx, PREFIX + "/N016/A96S96.A96S48.A96S48.(A96S48)x4/CTX0006:000f107f80ff",
                "ecd4eac5075360be92a908f8eb9c0fca66a4754c278b54df672aa7b241c18724");
    }

    @Test
    @DisplayName("A 1-octet context 0xff (n = 32)")
    void oneOctet() throws Exception {
        check(32, new byte[] {(byte) 0xff}, PREFIX + "/N032/A96S96.A96S48.A96S48.(A96S48)x5/CTX0001:ff",
                "2f70126935e478d7ebed3ab003b470c560b7aaabca474bc635caea5ec63ca1ab");
    }

    @Test
    @DisplayName("A 1,024-octet context (7i + 1) mod 256 (n = 64): tag digest and session id")
    void maximumLength() throws Exception {
        byte[] ctx = new byte[1024];
        for (int i = 0; i < ctx.length; i++) ctx[i] = (byte) ((7 * i + 1) % 256);
        byte[] tag = RangeTranscript.tag(64, ctx);
        String text = new String(tag, StandardCharsets.US_ASCII);
        assertTrue(text.startsWith(PREFIX + "/N064/A96S96.A96S48.A96S48.(A96S48)x6/CTX1024:01080f16"), text.substring(0, 160));
        assertEquals(PREFIX.length() + "/N064/A96S96.A96S48.A96S48.(A96S48)x6/CTX1024:".length() + 2048, tag.length);
        assertEquals("be59acf461fa9622f9c7586933d64abda0a4bb23d25d5c305bef40703e7612ee",
                HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(tag)));
        assertEquals("f32fc9b66d783450476403a63c97cde09f1d99112c22edecec3ff0cd2ce86d0b",
                HEX.formatHex(DuplexSponge.deriveSessionId(tag)));
    }

    @Test
    @DisplayName("Contexts {01, 11} and {11, 01} have their pinned session ids, and a proof under one fails under the other")
    void orderedOctets() throws Exception {
        byte[] a = {0x01, 0x11};
        byte[] b = {0x11, 0x01};
        check(16, a, PREFIX + "/N016/A96S96.A96S48.A96S48.(A96S48)x4/CTX0002:0111",
                "9c593775d675eabdc869197c9648f16e19585cab8313ab4e71fdf916cf079a51");
        check(16, b, PREFIX + "/N016/A96S96.A96S48.A96S48.(A96S48)x4/CTX0002:1101",
                "726959aae487d31ad1688f177dcb770d67d46b3f0b7cde21a9429ccc136f7dc7");
        G1PedersenCommitment c = G1Pedersen.pureJava().commitScalar(BigInteger.TEN, BigInteger.TEN);
        G1RangeProof proof = G1RangeProver.pureJava().prove(G1PedersenOpening.of(BigInteger.TEN, BigInteger.TEN), 16, a);
        assertTrue(G1RangeVerifier.pureJava().verify(c, proof, 16, a));
        assertFalse(G1RangeVerifier.pureJava().verify(c, proof, 16, b));
    }

    private static void check(int bits, byte[] ctx, String expectedTag, String expectedSessionId) {
        byte[] tag = RangeTranscript.tag(bits, ctx);
        assertEquals(expectedTag, new String(tag, StandardCharsets.US_ASCII));
        assertEquals(expectedSessionId, HEX.formatHex(DuplexSponge.deriveSessionId(tag)));
    }
}
