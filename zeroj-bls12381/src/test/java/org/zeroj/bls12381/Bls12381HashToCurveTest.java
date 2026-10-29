package org.zeroj.bls12381;

import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;

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
    void expandMessageXofShake256_matchesRfc9380Vector() {
        byte[] msg = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] dst = "QUUX-V01-CS02-with-expander-SHAKE256".getBytes(StandardCharsets.US_ASCII);

        assertArrayEquals(
                hexToBytes("b39e493867e2767216792abce1f2676c197c0692aed061560ead251821808e07"),
                Bls12381Hash.expandMessageXofShake256(msg, dst, 32));
    }

    /**
     * ADR-0062 PR review: known answers for the RFC 9380 §5.3.3 oversize-DST reduction on the XOF
     * path ({@code k = 128}, so the DST is reduced to {@code SHAKE256("H2C-OVERSIZE-DST-" ‖ DST, 32)}).
     * Computed independently with Python {@code hashlib.shake_256} (standard library only); the
     * 255-byte case pins that the reduction starts at 256 bytes.
     */
    @Test
    void expandMessageXofShake256_oversizeDstMatchesIndependentHashlib() {
        byte[] dst = new byte[296];
        for (int i = 0; i < dst.length; i++) {
            dst[i] = (byte) (7 * i + 3);
        }
        byte[] abc = "abc".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(hexToBytes("d39556b6208583a8649771c980f70e2e6fb5e024f3338b507226c638d0143e8c"
                        + "32529088d67f610170a4111603c874fadd9c882ba69cb4aaf14ba28df9ac8a4281ed35e98268727401848cb058924081"),
                Bls12381Hash.expandMessageXofShake256(abc, dst, 80));
        assertArrayEquals(hexToBytes("0f1ff7361831120b28b8eba31b2e6792507aa30a7a590c669b01abf2bf024af1"
                        + "5fd5d822399ff75aefc3b9eb0779388207dbd86365e241f72b7cede8a66bb6f8ee3aea45d150ccfe2218258940860bf1"),
                Bls12381Hash.expandMessageXofShake256(new byte[0], dst, 80));
        assertArrayEquals(hexToBytes("51ee5e7fb19df4f3039f6ddb6dd7dbda4c16865c1d8aef63013f91883abf07bb"),
                Bls12381Hash.expandMessageXofShake256(abc, Arrays.copyOf(dst, 255), 32));
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

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    // ---- ADR-0060 M2: RFC 9380 known-answer tests missing above ----
    //
    // Expected values are copied verbatim from RFC 9380 (August 2023) Appendix J.9.1
    // (BLS12381G1_XMD:SHA-256_SSWU_RO_), Appendix K.1 (expand_message_xmd(SHA-256)) and
    // Appendix K.2 (expand_message_xmd(SHA-256), long DST). The J.9.1 P vectors for the messages
    // "" and "abc" are already covered by hashToG1_matchesRfc9380EmptyMessageVector and
    // hashToG1_matchesRfc9380AbcVector; the remaining three are added here, plus u[0] and u[1] of
    // all five. Messages are named as in the RFC: "q128_" followed by 128 'q', "a512_" followed by
    // 512 'a'.

    private static final byte[] K1_DST =
            "QUUX-V01-CS02-with-expander-SHA256-128".getBytes(StandardCharsets.US_ASCII);

    /** RFC 9380 K.2: 256 octets, so expand_message_xmd must first reduce it (RFC 9380 §5.3.3). */
    private static final byte[] K2_LONG_DST =
            ("QUUX-V01-CS02-with-expander-SHA256-128-long-DST-" + "1".repeat(208))
                    .getBytes(StandardCharsets.US_ASCII);

    @ParameterizedTest(name = "J.9.1 P msg={0}")
    @MethodSource("rfc9380J91RemainingPointVectors")
    void hashToG1_matchesRfc9380J91Vector(String message, String px, String py) {
        assertG1(Bls12381Hash.hashToG1(rfcMessage(message), G1_RO_DST), px, py);
    }

    static Stream<Arguments> rfc9380J91RemainingPointVectors() {
        return Stream.of(
                Arguments.of("ABCDEF",
                        "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
                        "03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709"),
                Arguments.of("Q128",
                        "15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488",
                        "1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38"),
                Arguments.of("A512",
                        "082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe",
                        "05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8"));
    }

    /**
     * RFC 9380 J.9.1 u[0], u[1]: hash_to_field(msg, 2) into GF(p) with L = 64. Uses the
     * package-private {@code Bls12381Hash.hashToFp}, which is what the RO suite feeds to map_to_curve.
     */
    @ParameterizedTest(name = "J.9.1 u msg={0}")
    @MethodSource("rfc9380J91FieldVectors")
    void hashToField_matchesRfc9380J91Vector(String message, String u0, String u1) {
        BigInteger[] u = Bls12381Hash.hashToFp(rfcMessage(message), G1_RO_DST, 2);
        assertEquals(2, u.length);
        assertEquals(new BigInteger(u0, 16), u[0]);
        assertEquals(new BigInteger(u1, 16), u[1]);
    }

    static Stream<Arguments> rfc9380J91FieldVectors() {
        return Stream.of(
                Arguments.of("EMPTY",
                        "0ba14bd907ad64a016293ee7c2d276b8eae71f25a4b941eece7b0d89f17f75cb3ae5438a614fb61d6835ad59f29c564f",
                        "019b9bd7979f12657976de2884c7cce192b82c177c80e0ec604436a7f538d231552f0d96d9f7babe5fa3b19b3ff25ac9"),
                Arguments.of("ABC",
                        "0d921c33f2bad966478a03ca35d05719bdf92d347557ea166e5bba579eea9b83e9afa5c088573c2281410369fbd32951",
                        "003574a00b109ada2f26a37a91f9d1e740dffd8d69ec0c35e1e9f4652c7dba61123e9dd2e76c655d956e2b3462611139"),
                Arguments.of("ABCDEF",
                        "062d1865eb80ebfa73dcfc45db1ad4266b9f3a93219976a3790ab8d52d3e5f1e62f3b01795e36834b17b70e7b76246d4",
                        "0cdc3e2f271f29c4ff75020857ce6c5d36008c9b48385ea2f2bf6f96f428a3deb798aa033cd482d1cdc8b30178b08e3a"),
                Arguments.of("Q128",
                        "010476f6a060453c0b1ad0b628f3e57c23039ee16eea5e71bb87c3b5419b1255dc0e5883322e563b84a29543823c0e86",
                        "0b1a912064fb0554b180e07af7e787f1f883a0470759c03c1b6509eb8ce980d1670305ae7b928226bb58fdc0a419f46e"),
                Arguments.of("A512",
                        "0a8ffa7447f6be1c5a2ea4b959c9454b431e29ccc0802bc052413a9c5b4f9aac67a93431bd480d15be1e057c8a08e8c6",
                        "05d487032f602c90fa7625dbafe0f4a49ef4a6b0b33d7bb349ff4cf5410d297fd6241876e3e77b651cfc8191e40a68b7"));
    }

    @ParameterizedTest(name = "K.1 msg={0} len_in_bytes={1}")
    @MethodSource("rfc9380K1Vectors")
    void expandMessageXmd_matchesRfc9380K1Vector(String message, int lenInBytes, String uniformBytes) {
        assertArrayEquals(hexToBytes(uniformBytes),
                Bls12381Hash.expandMessageXmdSha256(rfcMessage(message), K1_DST, lenInBytes));
    }

    static Stream<Arguments> rfc9380K1Vectors() {
        return Stream.of(
                Arguments.of("EMPTY", 0x20, "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"),
                Arguments.of("ABC", 0x20, "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"),
                Arguments.of("ABCDEF", 0x20, "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1"),
                Arguments.of("Q128", 0x20, "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9"),
                Arguments.of("A512", 0x20, "4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c"),
                Arguments.of("EMPTY", 0x80, "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"),
                Arguments.of("ABC", 0x80, "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"),
                Arguments.of("ABCDEF", 0x80, "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df"),
                Arguments.of("Q128", 0x80, "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a"),
                Arguments.of("A512", 0x80, "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487"));
    }

    @ParameterizedTest(name = "K.2 long DST msg={0} len_in_bytes={1}")
    @MethodSource("rfc9380K2LongDstVectors")
    void expandMessageXmd_matchesRfc9380K2LongDstVector(String message, int lenInBytes, String uniformBytes) {
        assertEquals(256, K2_LONG_DST.length);
        assertArrayEquals(hexToBytes(uniformBytes),
                Bls12381Hash.expandMessageXmdSha256(rfcMessage(message), K2_LONG_DST, lenInBytes));
    }

    static Stream<Arguments> rfc9380K2LongDstVectors() {
        return Stream.of(
                Arguments.of("EMPTY", 0x20, "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3"),
                Arguments.of("ABC", 0x20, "52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12"),
                Arguments.of("ABCDEF", 0x20, "35387dcf22618f3728e6c686490f8b431f76550b0b2c61cbc1ce7001536f4521"),
                Arguments.of("Q128", 0x20, "01b637612bb18e840028be900a833a74414140dde0c4754c198532c3a0ba42bc"),
                Arguments.of("A512", 0x20, "20cce7033cabc5460743180be6fa8aac5a103f56d481cf369a8accc0c374431b"),
                Arguments.of("EMPTY", 0x80, "14604d85432c68b757e485c8894db3117992fc57e0e136f71ad987f789a0abc287c47876978e2388a02af86b1e8d1342e5ce4f7aaa07a87321e691f6fba7e0072eecc1218aebb89fb14a0662322d5edbd873f0eb35260145cd4e64f748c5dfe60567e126604bcab1a3ee2dc0778102ae8a5cfd1429ebc0fa6bf1a53c36f55dfc"),
                Arguments.of("ABC", 0x80, "1a30a5e36fbdb87077552b9d18b9f0aee16e80181d5b951d0471d55b66684914aef87dbb3626eaabf5ded8cd0686567e503853e5c84c259ba0efc37f71c839da2129fe81afdaec7fbdc0ccd4c794727a17c0d20ff0ea55e1389d6982d1241cb8d165762dbc39fb0cee4474d2cbbd468a835ae5b2f20e4f959f56ab24cd6fe267"),
                Arguments.of("ABCDEF", 0x80, "d2ecef3635d2397f34a9f86438d772db19ffe9924e28a1caf6f1c8f15603d4028f40891044e5c7e39ebb9b31339979ff33a4249206f67d4a1e7c765410bcd249ad78d407e303675918f20f26ce6d7027ed3774512ef5b00d816e51bfcc96c3539601fa48ef1c07e494bdc37054ba96ecb9dbd666417e3de289d4f424f502a982"),
                Arguments.of("Q128", 0x80, "ed6e8c036df90111410431431a232d41a32c86e296c05d426e5f44e75b9a50d335b2412bc6c91e0a6dc131de09c43110d9180d0a70f0d6289cb4e43b05f7ee5e9b3f42a1fad0f31bac6a625b3b5c50e3a83316783b649e5ecc9d3b1d9471cb5024b7ccf40d41d1751a04ca0356548bc6e703fca02ab521b505e8e45600508d32"),
                Arguments.of("A512", 0x80, "78b53f2413f3c688f07732c10e5ced29a17c6a16f717179ffbe38d92d6c9ec296502eb9889af83a1928cd162e845b0d3c5424e83280fed3d10cffb2f8431f14e7a23f4c68819d40617589e4c41169d0b56e0e3535be1fd71fbb08bb70c5b5ffed953d6c14bf7618b35fc1f4c4b30538236b4b08c9fbf90462447a8ada60be495"));
    }

    /** The RFC 9380 Appendix J/K test messages (ASCII). */
    private static byte[] rfcMessage(String name) {
        String message = switch (name) {
            case "EMPTY" -> "";
            case "ABC" -> "abc";
            case "ABCDEF" -> "abcdef0123456789";
            case "Q128" -> "q128_" + "q".repeat(128);
            case "A512" -> "a512_" + "a".repeat(512);
            default -> throw new IllegalArgumentException(name);
        };
        return message.getBytes(StandardCharsets.US_ASCII);
    }
}
