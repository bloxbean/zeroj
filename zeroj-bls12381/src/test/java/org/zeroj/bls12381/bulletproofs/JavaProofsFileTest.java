package org.zeroj.bls12381.bulletproofs;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * ADR-0061 M2, Java → Python: {@code bulletproof-g1-reference/java-proofs-v1.json} holds proofs made
 * by the Java prover with the spec §7.5 test nonces. The independent Python implementation checks
 * them ({@code verify_java_proofs.py}): it must accept every proof, reproduce every challenge, and
 * re-prove it byte for byte. This test keeps the committed file equal to what the Java code produces
 * now; on a mismatch it writes the current output to {@code build/java-proofs-v1.json} for review.
 */
class JavaProofsFileTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String RESOURCE = "/bulletproof-g1-reference/java-proofs-v1.json";

    private record Spec(String id, int bits, BigInteger value, BigInteger blinding, byte[] ctx) {
    }

    @Test
    @DisplayName("The committed Java proof file equals what the Java test-nonce prover produces now")
    void committedFileIsCurrent() throws IOException, NoSuchAlgorithmException {
        String current = render();
        String committed;
        try (InputStream in = getClass().getResourceAsStream(RESOURCE)) {
            assertNotNull(in, RESOURCE + " missing");
            committed = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        if (!current.equals(committed)) {
            Path out = Path.of("build", "java-proofs-v1.json");
            Files.createDirectories(out.getParent());
            Files.writeString(out, current, StandardCharsets.UTF_8);
        }
        assertEquals(committed, current, "regenerated file written to build/java-proofs-v1.json");
    }

    static String render() throws NoSuchAlgorithmException {
        byte[] ascii = "https://example.com/zeroj/java-proofs/v1".getBytes(StandardCharsets.US_ASCII);
        byte[] binary = {0x00, (byte) 0xff, 0x10, (byte) 0x80, 0x7f, 0x01};
        byte[] long1024 = new byte[1024];
        for (int i = 0; i < long1024.length; i++) long1024[i] = (byte) (255 - i % 251);
        List<Spec> specs = new ArrayList<>();
        BigInteger q1 = PointCodec.Q.subtract(BigInteger.ONE);
        for (int bits : new int[] {16, 32, 64}) {
            BigInteger max = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE);
            specs.add(new Spec("java-n" + bits + "-v0", bits, BigInteger.ZERO, BigInteger.valueOf(3), ascii));
            specs.add(new Spec("java-n" + bits + "-v1", bits, BigInteger.ONE, q1, binary));
            specs.add(new Spec("java-n" + bits + "-vmax", bits, max, BigInteger.valueOf(0xC0FFEE), long1024));
            specs.add(new Spec("java-n" + bits + "-vmid", bits, max.shiftRight(1).add(BigInteger.valueOf(12345)),
                    new BigInteger("1234567890123456789012345678901234567890"), new byte[] {(byte) bits}));
        }
        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"schema\": \"zeroj-java-range-proofs-v1\",\n");
        sb.append("  \"protocolId\": \"").append(G1RangeProof.PROTOCOL.id()).append("\",\n");
        sb.append("  \"seedRule\": \"SHA-256(\\\"zeroj-java-proofs-v1/\\\" || id)\",\n");
        sb.append("  \"cases\": [\n");
        for (int i = 0; i < specs.size(); i++) {
            Spec s = specs.get(i);
            byte[] seed = MessageDigest.getInstance("SHA-256")
                    .digest(("zeroj-java-proofs-v1/" + s.id()).getBytes(StandardCharsets.US_ASCII));
            byte[] proof = TestNonceProver.prove(G1RangeProver.pureJava(), G1PedersenOpening.of(s.value(), s.blinding()),
                    s.bits(), s.ctx(), seed).toBytes();
            byte[] commitment = G1Pedersen.pureJava().commitScalar(s.value(), s.blinding()).toPointBytes();
            sb.append("    {\"id\": \"").append(s.id()).append("\", \"bits\": \"").append(s.bits())
                    .append("\", \"value\": \"").append(s.value()).append("\", \"blinding\": \"").append(s.blinding())
                    .append("\", \"ctxHex\": \"").append(HEX.formatHex(s.ctx()))
                    .append("\", \"nonceSeedHex\": \"").append(HEX.formatHex(seed))
                    .append("\", \"commitmentHex\": \"").append(HEX.formatHex(commitment))
                    .append("\", \"proofHex\": \"").append(HEX.formatHex(proof)).append("\"}")
                    .append(i + 1 < specs.size() ? ",\n" : "\n");
        }
        sb.append("  ]\n}\n");
        return sb.toString();
    }
}
