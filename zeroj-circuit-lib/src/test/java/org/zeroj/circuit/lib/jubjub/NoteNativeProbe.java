package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * ADR-0055 M1 GraalVM native-image probe (not a JUnit test). Prints {@code confidential-note-jubjub-v1}
 * results that must be identical on the JVM and in a native image. Reproduce, from the repository
 * root:
 * <pre>
 * ./gradlew :zeroj-circuit-lib:testClasses
 * CP=zeroj-circuit-lib/build/classes/java/main:zeroj-circuit-lib/build/classes/java/test
 * java -cp $CP org.zeroj.circuit.lib.jubjub.NoteNativeProbe &gt; jvm.txt
 * native-image --no-fallback -cp $CP -o note-probe org.zeroj.circuit.lib.jubjub.NoteNativeProbe
 * ./note-probe &gt; native.txt &amp;&amp; diff jvm.txt native.txt   # all but the last (random) line
 * </pre>
 * The first lines reproduce the first Zcash Sapling note-encryption vector (zcash-test-vectors
 * {@code 78321be}): the shared secret from both sides, {@code k_enc} and the ciphertext.
 */
public final class NoteNativeProbe {
    private static final String ESK = "81c7b2171ff4415250cac01f5982fd8f49619d61ad78f6830b3c606145962a0e";
    private static final String IVK = "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204";
    private static final String PK_D = "db4cd2b0aac4f7eb8ca131f16567c445a9555126d3c29f14e3d776e841ae7415";
    private static final String EPK = "ded68f05c658fcae5ae218646ff844406f84426784040d0bef2b09cb3848c4dc";

    public static void main(String[] args) throws Exception {
        HexFormat h = HexFormat.of();
        NoteAeadSelfTest.run();
        System.out.println("aead_self_test ok");
        BigInteger esk = littleEndian(h.parseHex(ESK));
        BigInteger ivk = littleEndian(h.parseHex(IVK));
        byte[] epk = h.parseHex(EPK);
        JubjubPoint pkd = SaplingNoteCrypto.decodeKey(h.parseHex(PK_D));
        JubjubPoint epkPoint = SaplingNoteCrypto.decodeKey(epk);
        System.out.println("shared_esk " + h.formatHex(SaplingNoteCrypto.agree(esk, pkd).toBytes()));
        JubjubPoint shared = SaplingNoteCrypto.agree(ivk, epkPoint);
        System.out.println("shared_ivk " + h.formatHex(shared.toBytes()));
        byte[] kEnc = SaplingNoteCrypto.kdf(SaplingNoteCrypto.ZCASH_PERSONALIZATION, shared, epk);
        System.out.println("k_enc " + h.formatHex(kEnc));
        System.out.println("k_zeroj " + h.formatHex(SaplingNoteCrypto.kdf(SaplingNoteCrypto.PERSONALIZATION, shared, epk)));
        System.out.println("blake2b256_pers_abc " + h.formatHex(Blake2bDigest.digest(
                "abc".getBytes(StandardCharsets.US_ASCII), 32, SaplingNoteCrypto.PERSONALIZATION)));
        // A deterministic delivery: fixed reader secret, opening and ephemeral.
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        BigInteger sk = new BigInteger(1, sha.digest("probe.reader".getBytes(StandardCharsets.US_ASCII))).mod(JubjubCurve.SUBGROUP_ORDER);
        BigInteger r = new BigInteger(1, sha.digest("probe.blinding".getBytes(StandardCharsets.US_ASCII))).mod(JubjubCurve.SUBGROUP_ORDER);
        BigInteger e = new BigInteger(1, sha.digest("probe.ephemeral".getBytes(StandardCharsets.US_ASCII))).mod(JubjubCurve.SUBGROUP_ORDER);
        NoteViewingKey key = NoteViewingKey.fromSecret(sk);
        NoteOpening opening = NoteOpening.of(BigInteger.valueOf(123456789L), r);
        JubjubPoint c = opening.commitment();
        byte[] delivery = ConfidentialNotes.seal(opening, List.of(key.readerKey()), i -> e).get(0);
        System.out.println("reader_key " + h.formatHex(key.readerKey().encode()));
        System.out.println("commitment " + h.formatHex(c.toBytes()));
        System.out.println("delivery " + h.formatHex(delivery));
        Optional<NoteOpening> opened = NoteScanner.of(key).open(delivery, c);
        System.out.println("opened " + opened.map(o -> o.value() + "," + o.blinding().toString(16)).orElse("none"));
        byte[] tampered = delivery.clone();
        tampered[50] ^= 1;
        System.out.println("tampered " + NoteScanner.of(key).open(tampered, c).isPresent());
        NoteViewingKey fresh = NoteViewingKey.generate(new SecureRandom());
        NoteOpening random = NoteOpening.random(BigInteger.TEN, new SecureRandom());
        byte[] freshDelivery = ConfidentialNotes.seal(random, List.of(fresh.readerKey()), new SecureRandom()).get(0);
        System.out.println("random_roundtrip " + NoteScanner.of(fresh).open(freshDelivery, random.commitment()).map(o -> o.value()).orElse(null));
    }

    private static BigInteger littleEndian(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) be[i] = le[le.length - 1 - i];
        return new BigInteger(1, be);
    }
}
