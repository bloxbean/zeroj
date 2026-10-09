package org.zeroj.circuit.lib.jubjub;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * ADR-0054 M1 GraalVM native-image probe (not a JUnit test). Prints HPKE results that must be
 * identical on the JVM and in a native image. Reproduce, from the repository root:
 * <pre>
 * ./gradlew :zeroj-circuit-lib:testClasses
 * CP=zeroj-circuit-lib/build/classes/java/main:zeroj-circuit-lib/build/classes/java/test
 * java -cp $CP org.zeroj.circuit.lib.jubjub.HpkeNativeProbe &gt; jvm.txt
 * native-image --no-fallback -cp $CP -o hpke-probe org.zeroj.circuit.lib.jubjub.HpkeNativeProbe
 * ./hpke-probe &gt; native.txt &amp;&amp; diff jvm.txt native.txt   # all but the last (random) line
 * </pre>
 * The first lines reproduce RFC 9180 A.2.1 ({@code skEm}, {@code skRm}, {@code pkRm}, {@code enc},
 * {@code key}, {@code base_nonce}, the sequence-0 ciphertext).
 */
public final class HpkeNativeProbe {
    public static void main(String[] args) throws Exception {
        HexFormat h = HexFormat.of();
        // RFC 9180 A.2.1 inputs.
        byte[] skE = Hpke.deriveKeyPair(h.parseHex("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b"));
        byte[] skR = Hpke.deriveKeyPair(h.parseHex("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df"));
        byte[] pkR = X25519Bytes.publicFromPrivate(skR);
        byte[] info = h.parseHex("4f6465206f6e2061204772656369616e2055726e");
        System.out.println("skEm " + h.formatHex(skE));
        System.out.println("skRm " + h.formatHex(skR));
        System.out.println("pkRm " + h.formatHex(pkR));
        byte[][] enc = new byte[1][];
        Hpke.Context ctx = Hpke.setupBaseSWithEphemeral(skE, pkR, info, enc);
        System.out.println("enc " + h.formatHex(enc[0]));
        System.out.println("key " + h.formatHex(ctx.key()));
        System.out.println("base_nonce " + h.formatHex(ctx.baseNonce()));
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        byte[] pt = h.parseHex("4265617574792069732074727574682c20747275746820626561757479");
        for (int seq = 0; seq <= 256; seq++) {
            ctx.setSequence(seq);
            d.update(ctx.seal(("Count-" + seq).getBytes(StandardCharsets.US_ASCII), pt));
        }
        System.out.println("ct_digest " + h.formatHex(d.digest()));
        Hpke.Sealed s = Hpke.sealBaseWithEphemeral(skE, pkR, info, "Count-0".getBytes(StandardCharsets.US_ASCII), pt);
        System.out.println("single_ct " + h.formatHex(s.ct()));
        System.out.println("open " + h.formatHex(Hpke.openBase(s.enc(), skR, info, "Count-0".getBytes(StandardCharsets.US_ASCII), s.ct())));
        // RFC 7748 §6.1 and the small-order probe.
        System.out.println("x25519_alice_pk " + h.formatHex(X25519Bytes.publicFromPrivate(h.parseHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))));
        System.out.println("probe_base " + X25519Bytes.passesSmallOrderProbe(X25519Bytes.BASE_POINT));
        System.out.println("probe_zero " + X25519Bytes.passesSmallOrderProbe(new byte[32]));
        try {
            Hpke.openBase(new byte[32], skR, info, new byte[0], s.ct());
            System.out.println("small_order_enc accepted");
        } catch (Hpke.HpkeException e) {
            System.out.println("small_order_enc refused");
        }
        System.out.println("open_private_key " + h.formatHex(Hpke.openBase(s.enc(), X25519Bytes.privateKey(skR), pkR, info,
                "Count-0".getBytes(StandardCharsets.US_ASCII), s.ct())));
        Hpke.Sealed fresh = Hpke.sealBase(pkR, info, new byte[0], pt, new SecureRandom());
        System.out.println("random_roundtrip " + h.formatHex(Hpke.openBase(fresh.enc(), skR, info, new byte[0], fresh.ct())));
    }
}
