package org.zeroj.circuit.lib.jubjub;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * ADR-0058 M2 GraalVM native-image probe (not a JUnit test). Prints {@code pedersen-jubjub-bytes-v1}
 * results that must be identical on the JVM, in a native image, and to the spec's §10 known
 * answers. Reproduce, from the repository root:
 * <pre>
 * ./gradlew :zeroj-circuit-lib:testClasses
 * CP=zeroj-circuit-lib/build/classes/java/main:zeroj-circuit-lib/build/classes/java/test
 * CP=$CP:zeroj-bls12381/build/classes/java/main:zeroj-circuit-dsl/build/classes/java/main
 * CP=$CP:zeroj-api/build/classes/java/main
 * java -cp $CP org.zeroj.circuit.lib.jubjub.PedersenBytesNativeProbe &gt; jvm.txt
 * native-image --no-fallback -cp $CP -o bytes-probe org.zeroj.circuit.lib.jubjub.PedersenBytesNativeProbe
 * ./bytes-probe &gt; native.txt &amp;&amp; diff jvm.txt native.txt
 * </pre>
 * No native-image configuration is needed: the profile uses only the JDK's SHA-256 and the
 * existing Jubjub arithmetic.
 */
public final class PedersenBytesNativeProbe {

    public static void main(String[] args) throws Exception {
        HexFormat h = HexFormat.of();
        BigInteger lMinus1 = JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE);
        byte[] text = "Hello, ZeroJ ✓".getBytes(StandardCharsets.UTF_8);
        byte[][] im = PedersenBytesHash.intermediatesForTesting(new byte[0]);
        System.out.println("empty_b0 " + h.formatHex(im[0]));
        System.out.println("empty_uniform " + h.formatHex(im[3]));
        System.out.println("empty_s " + PedersenBytesHash.hashToScalar(new byte[0]).toString(16));
        System.out.println("zero1_s " + PedersenBytesHash.hashToScalar(new byte[1]).toString(16));
        System.out.println("utf8_text_s " + PedersenBytesHash.hashToScalar(text).toString(16));
        System.out.println("c_empty_r0 " + h.formatHex(PedersenCommitment.commitBytes(new byte[0], BigInteger.ZERO).toPointBytes()));
        System.out.println("c_empty_lm1 " + h.formatHex(PedersenCommitment.commitBytes(new byte[0], lMinus1).toPointBytes()));
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(text, lMinus1);
        System.out.println("c_text_lm1 " + h.formatHex(c.toPointBytes()));
        byte[] big = new byte[3 * PedersenBytesHash.BUFFER_BYTES + 5];
        for (int i = 0; i < big.length; i++) big[i] = (byte) (131 * i + 17);
        System.out.println("pattern_24581_s " + PedersenBytesHash.hashToScalar(big).toString(16));
        System.out.println("stream_declared_eq " + PedersenBytesHash.hashToScalar(new ByteArrayInputStream(big), big.length, true)
                .equals(PedersenBytesHash.hashToScalar(big)));
        System.out.println("stream_to_end_eq " + PedersenBytesHash.hashToScalar(new ByteArrayInputStream(big), 1L << 40, false)
                .equals(PedersenBytesHash.hashToScalar(big)));
        System.out.println("verify_text " + PedersenCommitment.verifyBytes(PedersenBytesCommitment.decode(c.toPointBytes()), text, lMinus1));
        System.out.println("verify_wrong " + PedersenCommitment.verifyBytes(c, new byte[0], lMinus1));
    }
}
