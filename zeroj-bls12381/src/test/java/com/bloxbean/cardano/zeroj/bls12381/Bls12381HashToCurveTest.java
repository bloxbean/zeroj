package com.bloxbean.cardano.zeroj.bls12381;

import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class Bls12381HashToCurveTest {
    private static final byte[] G1_RO_DST =
            "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] G2_RO_DST =
            "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] G1_NU_DST =
            "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_NU_".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] G2_NU_DST =
            "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_NU_".getBytes(StandardCharsets.US_ASCII);

    @Test
    void hashToG1_matchesRfc9380EmptyMessageVector() {
        assertG1(
                Bls12381Hash.hashToG1(new byte[0], G1_RO_DST),
                "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
                "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265");
    }

    @Test
    void hashToG1_matchesRfc9380AbcVector() {
        assertG1(
                Bls12381Hash.hashToG1("abc".getBytes(StandardCharsets.US_ASCII), G1_RO_DST),
                "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
                "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d");
    }

    @Test
    void encodeToG1_matchesRfc9380AbcVector() {
        assertG1(
                Bls12381Hash.encodeToG1("abc".getBytes(StandardCharsets.US_ASCII), G1_NU_DST),
                "009769f3ab59bfd551d53a5f846b9984c59b97d6842b20a2c565baa167945e3d026a3755b6345df8ec7e6acb6868ae6d",
                "1532c00cf61aa3d0ce3e5aa20c3b531a2abd2c770a790a2613818303c6b830ffc0ecf6c357af3317b9575c567f11cd2c");
    }

    @Test
    void expandMessageXmd_allowsZeroLengthOutput() {
        assertArrayEquals(new byte[0],
                Bls12381Hash.expandMessageXmdSha256("abc".getBytes(StandardCharsets.US_ASCII), G1_RO_DST, 0));
    }

    @Test
    void expandMessageXmd_usesOversizeDstReduction() {
        byte[] msg = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] oversizedDst = ("QUUX-V01-CS02-with-expander-SHA256-128-long-DST-" + "1".repeat(256))
                .getBytes(StandardCharsets.US_ASCII);
        byte[] reducedDst = sha256(concat("H2C-OVERSIZE-DST-".getBytes(StandardCharsets.US_ASCII), oversizedDst));

        assertArrayEquals(
                Bls12381Hash.expandMessageXmdSha256(msg, reducedDst, 32),
                Bls12381Hash.expandMessageXmdSha256(msg, oversizedDst, 32));
    }

    @Test
    void expandMessageXofShake256_matchesRfc9380Vector() {
        byte[] msg = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] dst = "QUUX-V01-CS02-with-expander-SHAKE256".getBytes(StandardCharsets.US_ASCII);

        assertArrayEquals(
                hexToBytes("b39e493867e2767216792abce1f2676c197c0692aed061560ead251821808e07"),
                Bls12381Hash.expandMessageXofShake256(msg, dst, 32));
    }

    @Test
    void hashToScalarXofShake256_matchesOfficialBbsFixture() {
        byte[] message = hexToBytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        byte[] dst = hexToBytes("4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832475f484d32535f4832535f");

        assertEquals(
                new BigInteger("0500031f786fde5326aa9370dd7ffe9535ec7a52cf2b8f432cad5d9acfb73cd3", 16),
                Bls12381Hash.hashToScalarXofShake256(message, dst));
    }

    @Test
    void hashToG2_matchesRfc9380EmptyMessageVector() {
        assertG2(
                Bls12381Hash.hashToG2(new byte[0], G2_RO_DST),
                "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
                "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d",
                "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92",
                "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6");
    }

    @Test
    void hashToG2_matchesRfc9380AbcVector() {
        assertG2(
                Bls12381Hash.hashToG2("abc".getBytes(StandardCharsets.US_ASCII), G2_RO_DST),
                "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
                "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8",
                "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48",
                "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16");
    }

    @Test
    void encodeToG2_matchesRfc9380AbcVector() {
        assertG2(
                Bls12381Hash.encodeToG2("abc".getBytes(StandardCharsets.US_ASCII), G2_NU_DST),
                "108ed59fd9fae381abfd1d6bce2fd2fa220990f0f837fa30e0f27914ed6e1454db0d1ee957b219f61da6ff8be0d6441f",
                "0296238ea82c6d4adb3c838ee3cb2346049c90b96d602d7bb1b469b905c9228be25c627bffee872def773d5b2a2eb57d",
                "033f90f6057aadacae7963b0a0b379dd46750c1c94a6357c99b65f63b79e321ff50fe3053330911c56b6ceea08fee656",
                "153606c417e59fb331b7ae6bce4fbf7c5190c33ce9402b5ebe2b70e44fca614f3f1382a3625ed5493843d0b0a652fc3f");
    }

    private static void assertG1(G1Point point, String x, String y) {
        assertTrue(point.isValid());
        assertEquals(fp(x), point.x());
        assertEquals(fp(y), point.y());
    }

    private static void assertG2(G2Point point, String xc0, String xc1, String yc0, String yc1) {
        assertTrue(point.isValid());
        assertEquals(Fp2.of(fp(xc0), fp(xc1)), point.x());
        assertEquals(Fp2.of(fp(yc0), fp(yc1)), point.y());
    }

    private static Fp fp(String hex) {
        return Fp.of(new BigInteger(hex, 16));
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] out = Arrays.copyOf(left, left.length + right.length);
        System.arraycopy(right, 0, out, left.length, right.length);
        return out;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
