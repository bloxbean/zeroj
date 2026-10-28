package org.zeroj.bls12381.pedersen;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.PureJavaBls12381Provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0060 M2: the provider binding of {@link G1Pedersen} ({@code pedersen-bls12-381-g1-v1} §7, §8).
 *
 * <p>Uses test-only stub providers built with {@link Proxy} over {@link Bls12381Provider}, so that
 * every provider method call (including interface default methods) is recorded, delegating to
 * {@link PureJavaBls12381Provider#INSTANCE} unless a test overrides {@code g1SecretScalarMul}.
 *
 * <p>Expected values ({@code G}, {@code H}, {@code q}, the §10.2 scalar of {@code "abc"} and the
 * §10.3 commitments) are copied from the spec, never computed by the code under test.
 */
class G1PedersenProviderTest {

    private static final HexFormat HEX = HexFormat.of();

    // Spec §1.
    private static final BigInteger Q =
            new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    // Spec §5: MAX_PAYLOAD_BYTES = 2^61 − 256.
    private static final long MAX_PAYLOAD_BYTES = 2305843009213693696L;

    // Spec §2.2 pinned compressed encodings, decoded with the general codec (not the Pedersen classes).
    private static final String G_HEX =
            "80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e";
    private static final String H_HEX =
            "92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65";
    private static final G1Point G = Bls12381Codecs.g1FromCompressed(HEX.parseHex(G_HEX));
    private static final G1Point H = Bls12381Codecs.g1FromCompressed(HEX.parseHex(H_HEX));

    // Spec §10.3: (m, r, C(m, r)).
    private static final String C_12345_67890 =
            "8c5b1e42a3912ecf2a2fc27a26ef67afd30799614ebfbd5dc7a2cb00e43b063a60a4d516007352cddecd632d2b758fc4";
    private static final Object[][] SPEC_COMMITMENTS = {
            {BigInteger.ZERO, BigInteger.ZERO,
                    "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
            {BigInteger.ONE, BigInteger.ZERO, G_HEX},
            {BigInteger.ZERO, BigInteger.ONE, H_HEX},
            {Q.subtract(BigInteger.ONE), Q.subtract(BigInteger.ONE),
                    "830c22c1792dae9774b23f9c31801a964094bef7734745f4012b4e5c133a5d608636f1e020d68cb2688ad276369b8650"},
            {BigInteger.valueOf(12345), BigInteger.valueOf(67890), C_12345_67890},
    };

    // Spec §10.2: HashBytesToScalarG1("abc").
    private static final byte[] ABC = "abc".getBytes(StandardCharsets.US_ASCII);
    private static final BigInteger S_ABC =
            new BigInteger("425016933681726855004915202875618514367841089254790273686098534787449164925");

    // Spec §10.4: G + (0, 2), a curve point of mixed order (not in G1).
    private static final String MIXED_ORDER_HEX =
            "b6ee2defa35097e6bbaea5ab251479b37157dedfcbc4b319181bf28298f048a66eb93dc0230190c18ae135644c2d3df4";

    private static final String SECRET_MUL = "g1SecretScalarMul";
    private static final String PUBLIC_MUL = "g1ScalarMul";

    // ---------------------------------------------------------------------------------------------
    // pureJava() and withProvider(null)
    // ---------------------------------------------------------------------------------------------

    @Test
    void pureJava_supportsGenerationAndUsesThePureJavaProvider() {
        G1Pedersen pedersen = G1Pedersen.pureJava();
        assertTrue(pedersen.supportsGeneration());
        assertSame(PureJavaBls12381Provider.INSTANCE, pedersen.provider());
        assertSame(pedersen, G1Pedersen.pureJava());
    }

    @Test
    void withProvider_rejectsNull() {
        assertThrows(NullPointerException.class, () -> G1Pedersen.withProvider(null));
    }

    // ---------------------------------------------------------------------------------------------
    // Capability probe (spec §8 "Capability, decided on public data")
    // ---------------------------------------------------------------------------------------------

    @Test
    void probe_isCalledExactlyOnceWithGAndOne() {
        Stub stub = Stub.delegating();
        G1Pedersen pedersen = G1Pedersen.withProvider(stub.provider);

        assertTrue(pedersen.supportsGeneration());
        assertSame(stub.provider, pedersen.provider());
        assertEquals(1, stub.calls.size(), "provider calls during withProvider: " + stub.names());
        Call probe = stub.calls.get(0);
        assertEquals(SECRET_MUL, probe.method());
        assertEquals(G, probe.args()[0], "probe point must be G of spec §2.2");
        assertEquals(BigInteger.ONE, probe.args()[1]);
        assertSame(BigInteger.class, probe.args()[1].getClass());
    }

    @Test
    void probe_resultOtherThanG_isIllegalState() {
        Map<String, G1Point> wrong = new LinkedHashMap<>();
        wrong.put("H", H);
        wrong.put("2G", G.add(G));
        wrong.put("-G", G.negate());
        wrong.put("identity", G1Point.INFINITY);
        wrong.put("off-curve (1, 1)", new G1Point(Fp.of(1), Fp.of(1)));
        wrong.put("mixed order G + (0, 2)", Bls12381Codecs.g1FromCompressedUnchecked(HEX.parseHex(MIXED_ORDER_HEX)));
        wrong.put("null", null);
        for (Map.Entry<String, G1Point> entry : wrong.entrySet()) {
            G1Point answer = entry.getValue();
            Stub stub = Stub.withSecret((index, point, scalar) -> answer);
            assertThrows(IllegalStateException.class, () -> G1Pedersen.withProvider(stub.provider), entry.getKey());
            assertEquals(List.of(SECRET_MUL), stub.names(), entry.getKey());
        }
    }

    @Test
    void probe_otherRuntimeExceptionPropagatesUnchanged() {
        RuntimeException boom = new IllegalArgumentException("probe failure");
        Stub stub = Stub.withSecret((index, point, scalar) -> {
            throw boom;
        });
        RuntimeException thrown = assertThrows(RuntimeException.class, () -> G1Pedersen.withProvider(stub.provider));
        assertSame(boom, thrown);
        assertEquals(List.of(SECRET_MUL), stub.names());

        IllegalStateException ise = new IllegalStateException("provider-internal");
        Stub stub2 = Stub.withSecret((index, point, scalar) -> {
            throw ise;
        });
        assertSame(ise, assertThrows(IllegalStateException.class, () -> G1Pedersen.withProvider(stub2.provider)));
    }

    @Test
    void probe_unsupportedOperation_meansNoGeneration() {
        // The interface default of g1SecretScalarMul throws UnsupportedOperationException.
        Stub stub = Stub.unsupported();
        G1Pedersen pedersen = G1Pedersen.withProvider(stub.provider);
        assertFalse(pedersen.supportsGeneration());
        assertSame(stub.provider, pedersen.provider());
        assertEquals(List.of(SECRET_MUL), stub.names());
        Call probe = stub.calls.get(0);
        assertEquals(G, probe.args()[0]);
        assertEquals(BigInteger.ONE, probe.args()[1]);

        // An explicitly thrown UnsupportedOperationException in the probe has the same meaning.
        Stub explicit = Stub.withSecret((index, point, scalar) -> {
            throw new UnsupportedOperationException("no secret path");
        });
        assertFalse(G1Pedersen.withProvider(explicit.provider).supportsGeneration());
    }

    // ---------------------------------------------------------------------------------------------
    // An instance without generation (spec §8: UOE right after the null checks)
    // ---------------------------------------------------------------------------------------------

    @Test
    void noGeneration_everyGenerationMethodThrowsUnsupportedOperation() {
        Stub stub = Stub.unsupported();
        G1Pedersen pedersen = G1Pedersen.withProvider(stub.provider);
        int afterProbe = stub.calls.size();

        assertThrows(UnsupportedOperationException.class,
                () -> pedersen.commitScalar(BigInteger.ONE, BigInteger.TWO));
        assertThrows(UnsupportedOperationException.class,
                () -> pedersen.commitBytes(ABC, BigInteger.TWO));
        assertThrows(UnsupportedOperationException.class,
                () -> pedersen.commitBytes(new ByteArrayInputStream(ABC), ABC.length, BigInteger.TWO));
        assertThrows(UnsupportedOperationException.class,
                () -> pedersen.commitBytesToEnd(new ByteArrayInputStream(ABC), ABC.length, BigInteger.TWO));
        assertEquals(afterProbe, stub.calls.size(), "no provider call after the probe: " + stub.names());
    }

    @Test
    void noGeneration_nullArgumentsStillThrowNullPointerFirst() {
        G1Pedersen pedersen = G1Pedersen.withProvider(Stub.unsupported().provider);
        InputStream in = new ByteArrayInputStream(ABC);
        assertThrows(NullPointerException.class, () -> pedersen.commitScalar(null, BigInteger.ONE));
        assertThrows(NullPointerException.class, () -> pedersen.commitScalar(BigInteger.ONE, null));
        assertThrows(NullPointerException.class, () -> pedersen.commitBytes((byte[]) null, BigInteger.ONE));
        assertThrows(NullPointerException.class, () -> pedersen.commitBytes(ABC, null));
        assertThrows(NullPointerException.class, () -> pedersen.commitBytes((InputStream) null, 3, BigInteger.ONE));
        assertThrows(NullPointerException.class, () -> pedersen.commitBytes(in, 3, null));
        assertThrows(NullPointerException.class, () -> pedersen.commitBytesToEnd(null, 3, BigInteger.ONE));
        assertThrows(NullPointerException.class, () -> pedersen.commitBytesToEnd(in, 3, null));
        // Nulls win over invalid non-null arguments too.
        assertThrows(NullPointerException.class, () -> pedersen.commitScalar(Q, null));
        assertThrows(NullPointerException.class, () -> pedersen.commitBytes((InputStream) null, -1, Q));
    }

    @Test
    void noGeneration_unsupportedBeforeAnyCheck() {
        G1Pedersen pedersen = G1Pedersen.withProvider(Stub.unsupported().provider);
        BigInteger minusOne = BigInteger.ONE.negate();
        // Out-of-range scalars would be NON_CANONICAL_SCALAR, bad bounds LENGTH_OUT_OF_RANGE.
        assertThrows(UnsupportedOperationException.class, () -> pedersen.commitScalar(Q, BigInteger.ONE));
        assertThrows(UnsupportedOperationException.class, () -> pedersen.commitScalar(BigInteger.ONE, Q));
        assertThrows(UnsupportedOperationException.class, () -> pedersen.commitScalar(minusOne, minusOne));
        assertThrows(UnsupportedOperationException.class, () -> pedersen.commitBytes(ABC, Q));
        assertThrows(UnsupportedOperationException.class,
                () -> pedersen.commitBytes(new ByteArrayInputStream(ABC), 3, Q));
        assertThrows(UnsupportedOperationException.class,
                () -> pedersen.commitBytes(new ByteArrayInputStream(ABC), -1, BigInteger.ONE));
        assertThrows(UnsupportedOperationException.class,
                () -> pedersen.commitBytes(new ByteArrayInputStream(ABC), MAX_PAYLOAD_BYTES + 1, minusOne));
        assertThrows(UnsupportedOperationException.class,
                () -> pedersen.commitBytesToEnd(new ByteArrayInputStream(ABC), -1, Q));
        assertThrows(UnsupportedOperationException.class,
                () -> pedersen.commitBytesToEnd(new ByteArrayInputStream(ABC), MAX_PAYLOAD_BYTES + 1, BigInteger.ONE));
    }

    @Test
    void noGeneration_unsupportedBeforeTheSnapshot() {
        G1Pedersen pedersen = G1Pedersen.withProvider(Stub.unsupported().provider);
        List<String> touched = new ArrayList<>();
        BigInteger value = new RecordingBigInteger(BigInteger.valueOf(5), touched);
        BigInteger blinding = new RecordingBigInteger(BigInteger.valueOf(7), touched);

        assertThrows(UnsupportedOperationException.class, () -> pedersen.commitScalar(value, blinding));
        assertThrows(UnsupportedOperationException.class, () -> pedersen.commitBytes(ABC, blinding));
        assertThrows(UnsupportedOperationException.class,
                () -> pedersen.commitBytes(new ByteArrayInputStream(ABC), 3, blinding));
        assertThrows(UnsupportedOperationException.class,
                () -> pedersen.commitBytesToEnd(new ByteArrayInputStream(ABC), 3, blinding));
        assertEquals(List.of(), touched, "no BigInteger method may run before the generation check");

        // Positive control: on an instance with generation the snapshot does read the subclass.
        G1Pedersen.pureJava().commitScalar(value, blinding);
        assertFalse(touched.isEmpty(), "control: the recording subclass must observe the snapshot");
    }

    @Test
    void noGeneration_unsupportedBeforeAnyDigestAcquisition() {
        G1Pedersen pedersen = G1Pedersen.withProvider(Stub.unsupported().provider);
        int[] digests = {0};
        G1PedersenBytesHash.installDigestObserverForTesting(() -> digests[0]++);
        try {
            assertThrows(UnsupportedOperationException.class, () -> pedersen.commitBytes(ABC, BigInteger.ONE));
            assertThrows(UnsupportedOperationException.class,
                    () -> pedersen.commitBytes(new ByteArrayInputStream(ABC), 3, BigInteger.ONE));
            assertThrows(UnsupportedOperationException.class,
                    () -> pedersen.commitBytesToEnd(new ByteArrayInputStream(ABC), 3, BigInteger.ONE));
            assertEquals(0, digests[0], "no digest may be acquired");

            // Positive control: the observer does see a real acquisition.
            G1Pedersen.pureJava().commitBytes(ABC, BigInteger.ONE);
            assertEquals(1, digests[0], "control: one digest per byte commitment");
        } finally {
            G1PedersenBytesHash.clearDigestObserverForTesting();
        }
    }

    @Test
    void noGeneration_unsupportedBeforeAnyStreamAccess() throws IOException {
        G1Pedersen pedersen = G1Pedersen.withProvider(Stub.unsupported().provider);
        UntouchableStream stream = new UntouchableStream();
        assertThrows(UnsupportedOperationException.class, () -> pedersen.commitBytes(stream, 3, BigInteger.ONE));
        assertThrows(UnsupportedOperationException.class, () -> pedersen.commitBytesToEnd(stream, 3, BigInteger.ONE));
        assertThrows(UnsupportedOperationException.class, () -> pedersen.commitBytes(stream, 0, BigInteger.ONE));
        assertThrows(UnsupportedOperationException.class, () -> pedersen.commitBytesToEnd(stream, 0, BigInteger.ONE));
        assertFalse(stream.touched, "the stream must not be touched");

        // Positive control: the same stream does fail when a method reads it.
        G1PedersenBytesCommitment c = G1Pedersen.pureJava().commitBytes(ABC, BigInteger.ONE);
        assertThrows(AssertionError.class, () -> pedersen.verifyBytes(c, stream, 3, BigInteger.ONE));
        assertTrue(stream.touched);
    }

    @Test
    void noGeneration_verificationWorksWithTheSameVerdictsAsPureJava() {
        Stub stub = Stub.unsupported();
        G1Pedersen noGen = G1Pedersen.withProvider(stub.provider);
        G1Pedersen pure = G1Pedersen.pureJava();
        assertFalse(noGen.supportsGeneration());

        Map<String, Verification> cases = verificationCases();
        for (Map.Entry<String, Verification> entry : cases.entrySet()) {
            String expected = entry.getValue().expected();
            assertEquals(expected, outcome(pure, entry.getValue().op()), "pureJava: " + entry.getKey());
            assertEquals(expected, outcome(noGen, entry.getValue().op()), "no-generation: " + entry.getKey());
        }
        assertEquals(0, stub.count(SECRET_MUL) - 1, "verification must never use the secret multiplication");
        assertTrue(stub.count(PUBLIC_MUL) > 0, "control: verification used the stub's public multiplication");
    }

    // ---------------------------------------------------------------------------------------------
    // Operation schedule: generation only through g1SecretScalarMul, verification only public ops
    // ---------------------------------------------------------------------------------------------

    @Test
    void commitScalar_usesThreeSecretMultiplicationsWithTheValueSplit() {
        Stub stub = Stub.delegating();
        G1Pedersen pedersen = G1Pedersen.withProvider(stub.provider);
        stub.calls.clear();

        G1PedersenCommitment c = pedersen.commitScalar(BigInteger.valueOf(12345), BigInteger.valueOf(67890));

        assertEquals(C_12345_67890, HEX.formatHex(c.toPointBytes()));
        assertEquals(List.of(SECRET_MUL, SECRET_MUL, SECRET_MUL), stub.names());
        assertBaseScalars(stub.calls, BigInteger.valueOf(12345), BigInteger.valueOf(67890));
    }

    @Test
    void commitBytes_usesThreeSecretMultiplicationsForEverySource() throws Exception {
        BigInteger r = BigInteger.valueOf(67890);
        // Spec §3: a bytes commitment is the scalar commitment to s with the same r.
        byte[] expected = G1Pedersen.pureJava().commitScalar(S_ABC, r).toPointBytes();
        List<Generation> sources = List.of(
                p -> p.commitBytes(ABC, r).toPointBytes(),
                p -> p.commitBytes(new ByteArrayInputStream(ABC), ABC.length, r).toPointBytes(),
                p -> p.commitBytesToEnd(new ByteArrayInputStream(ABC), 1024, r).toPointBytes());
        for (Generation source : sources) {
            Stub stub = Stub.delegating();
            G1Pedersen pedersen = G1Pedersen.withProvider(stub.provider);
            stub.calls.clear();

            assertArrayEquals(expected, source.run(pedersen));
            assertEquals(List.of(SECRET_MUL, SECRET_MUL, SECRET_MUL), stub.names());
            assertBaseScalars(stub.calls, S_ABC, r);
        }
    }

    @Test
    void verification_usesTwoPublicMultiplicationsAndNoSecretOne() {
        BigInteger m = BigInteger.valueOf(12345);
        BigInteger r = BigInteger.valueOf(67890);
        G1PedersenCommitment c = G1PedersenCommitment.decode(HEX.parseHex(C_12345_67890));
        G1PedersenBytesCommitment b = G1Pedersen.pureJava().commitBytes(ABC, r);
        Map<String, Verification> ops = new LinkedHashMap<>();
        ops.put("verifyScalar 3 match", new Verification("true", p -> p.verifyScalar(c, m, r)));
        ops.put("verifyScalar 3 mismatch", new Verification("false", p -> p.verifyScalar(c, m.add(BigInteger.ONE), r)));
        ops.put("verifyScalar 4 match", new Verification("true", p -> p.verifyScalar(c, m, r, 14)));
        ops.put("verifyScalar 4 mismatch", new Verification("false", p -> p.verifyScalar(c, m, r.add(BigInteger.ONE), 14)));
        ops.put("verifyBytes array", new Verification("true", p -> p.verifyBytes(b, ABC, r)));
        ops.put("verifyBytes array mismatch", new Verification("false", p -> p.verifyBytes(b, new byte[]{'a', 'b'}, r)));
        ops.put("verifyBytes stream", new Verification("true",
                p -> p.verifyBytes(b, new ByteArrayInputStream(ABC), ABC.length, r)));
        ops.put("verifyBytesToEnd stream", new Verification("true",
                p -> p.verifyBytesToEnd(b, new ByteArrayInputStream(ABC), 64, r)));
        for (Map.Entry<String, Verification> entry : ops.entrySet()) {
            Stub stub = Stub.delegating();
            G1Pedersen pedersen = G1Pedersen.withProvider(stub.provider);
            stub.calls.clear();

            assertEquals(entry.getValue().expected(), outcome(pedersen, entry.getValue().op()), entry.getKey());
            assertEquals(List.of(PUBLIC_MUL, PUBLIC_MUL), stub.names(), entry.getKey());
            assertEquals(1, stub.calls.stream().filter(call -> G.equals(call.args()[0])).count(), entry.getKey());
            assertEquals(1, stub.calls.stream().filter(call -> H.equals(call.args()[0])).count(), entry.getKey());
        }
    }

    @Test
    void rejectedCalls_makeNoProviderCallBeyondTheProbe() {
        Stub stub = Stub.delegating();
        G1Pedersen p = G1Pedersen.withProvider(stub.provider);
        assertEquals(1, stub.calls.size());
        G1PedersenCommitment c = G1PedersenCommitment.decode(HEX.parseHex(C_12345_67890));
        G1PedersenBytesCommitment b = G1PedersenBytesCommitment.decode(HEX.parseHex(C_12345_67890));
        BigInteger minusOne = BigInteger.ONE.negate();
        UntouchableStream stream = new UntouchableStream();

        Map<String, Rejection> rejections = new LinkedHashMap<>();
        CommitmentError ncs = CommitmentError.NON_CANONICAL_SCALAR;
        CommitmentError len = CommitmentError.LENGTH_OUT_OF_RANGE;
        CommitmentError cfg = CommitmentError.INVALID_CONFIGURATION;
        CommitmentError oor = CommitmentError.OUT_OF_RANGE;
        rejections.put("commitScalar value = q", new Rejection(ncs, () -> p.commitScalar(Q, BigInteger.ONE)));
        rejections.put("commitScalar value = -1", new Rejection(ncs, () -> p.commitScalar(minusOne, BigInteger.ONE)));
        rejections.put("commitScalar blinding = q", new Rejection(ncs, () -> p.commitScalar(BigInteger.ONE, Q)));
        rejections.put("commitScalar blinding = q + 1",
                new Rejection(ncs, () -> p.commitScalar(BigInteger.ONE, Q.add(BigInteger.ONE))));
        rejections.put("verifyScalar value = q", new Rejection(ncs, () -> p.verifyScalar(c, Q, BigInteger.ONE)));
        rejections.put("verifyScalar blinding = -1", new Rejection(ncs, () -> p.verifyScalar(c, BigInteger.ONE, minusOne)));
        rejections.put("verifyScalar4 amountBits = 0",
                new Rejection(cfg, () -> p.verifyScalar(c, BigInteger.ONE, BigInteger.ONE, 0)));
        rejections.put("verifyScalar4 amountBits = 255",
                new Rejection(cfg, () -> p.verifyScalar(c, BigInteger.ONE, BigInteger.ONE, 255)));
        rejections.put("verifyScalar4 value = 2^8, amountBits = 8",
                new Rejection(oor, () -> p.verifyScalar(c, BigInteger.valueOf(256), BigInteger.ONE, 8)));
        rejections.put("verifyScalar4 value = q", new Rejection(ncs, () -> p.verifyScalar(c, Q, BigInteger.ONE, 254)));
        rejections.put("withPublicDelta deltaBits = 0", new Rejection(cfg, () -> c.withPublicDelta(BigInteger.ONE, 0)));
        rejections.put("withPublicDelta deltaBits = 255", new Rejection(cfg, () -> c.withPublicDelta(BigInteger.ONE, 255)));
        rejections.put("withPublicDelta delta = -2^8, deltaBits = 8",
                new Rejection(oor, () -> c.withPublicDelta(BigInteger.valueOf(-256), 8)));
        rejections.put("commitBytes array blinding = q", new Rejection(ncs, () -> p.commitBytes(ABC, Q)));
        rejections.put("commitBytes length = -1", new Rejection(len, () -> p.commitBytes(stream, -1, BigInteger.ONE)));
        rejections.put("commitBytes length = MAX + 1",
                new Rejection(len, () -> p.commitBytes(stream, MAX_PAYLOAD_BYTES + 1, BigInteger.ONE)));
        rejections.put("commitBytes stream blinding = q", new Rejection(ncs, () -> p.commitBytes(stream, 3, Q)));
        rejections.put("commitBytesToEnd maxBytes = -1",
                new Rejection(len, () -> p.commitBytesToEnd(stream, -1, BigInteger.ONE)));
        rejections.put("commitBytesToEnd maxBytes = MAX + 1",
                new Rejection(len, () -> p.commitBytesToEnd(stream, MAX_PAYLOAD_BYTES + 1, BigInteger.ONE)));
        rejections.put("verifyBytes array blinding = -1", new Rejection(ncs, () -> p.verifyBytes(b, ABC, minusOne)));
        rejections.put("verifyBytes length = -1", new Rejection(len, () -> p.verifyBytes(b, stream, -1, BigInteger.ONE)));
        rejections.put("verifyBytes length = MAX + 1",
                new Rejection(len, () -> p.verifyBytes(b, stream, MAX_PAYLOAD_BYTES + 1, BigInteger.ONE)));
        rejections.put("verifyBytesToEnd maxBytes = -1",
                new Rejection(len, () -> p.verifyBytesToEnd(b, stream, -1, BigInteger.ONE)));
        rejections.put("verifyBytesToEnd maxBytes = MAX + 1",
                new Rejection(len, () -> p.verifyBytesToEnd(b, stream, MAX_PAYLOAD_BYTES + 1, BigInteger.ONE)));
        rejections.put("verifyBytesToEnd blinding = q", new Rejection(ncs, () -> p.verifyBytesToEnd(b, stream, 3, Q)));

        for (Map.Entry<String, Rejection> entry : rejections.entrySet()) {
            CommitmentFormatException e = assertThrows(CommitmentFormatException.class,
                    entry.getValue().call(), entry.getKey());
            assertEquals(entry.getValue().reason(), e.reason(), entry.getKey());
            assertEquals(1, stub.calls.size(), entry.getKey() + ": provider calls " + stub.names());
        }
        assertFalse(stream.touched, "no rejected call may read the stream");
    }

    @Test
    void providerExceptionDuringGeneration_propagatesUnchangedWithoutFallback() {
        for (int failingCall : new int[]{1, 2}) {
            RuntimeException boom = new IllegalArgumentException("provider failure");
            UnsupportedOperationException late = new UnsupportedOperationException("late unsupported");
            for (RuntimeException failure : List.of(boom, late)) {
                for (Generation generation : allGenerations()) {
                    Stub stub = Stub.withSecret((index, point, scalar) -> {
                        if (index == failingCall) {
                            throw failure;
                        }
                        return PureJavaBls12381Provider.INSTANCE.g1SecretScalarMul(point, scalar);
                    });
                    G1Pedersen pedersen = G1Pedersen.withProvider(stub.provider);
                    assertTrue(pedersen.supportsGeneration());
                    RuntimeException thrown = assertThrows(RuntimeException.class, () -> generation.run(pedersen));
                    assertSame(failure, thrown, "call " + failingCall);
                    assertEquals(0, stub.count(PUBLIC_MUL), "no fallback to the public multiplication");
                    assertEquals(1 + failingCall, stub.count(SECRET_MUL));
                }
            }
        }
    }

    @Test
    void providerReturningNullOrInvalidPointDuringGeneration_isIllegalState() {
        Map<String, G1Point> bad = new LinkedHashMap<>();
        bad.put("null", null);
        bad.put("off-curve (1, 1)", new G1Point(Fp.of(1), Fp.of(1)));
        bad.put("mixed order G + (0, 2)", Bls12381Codecs.g1FromCompressedUnchecked(HEX.parseHex(MIXED_ORDER_HEX)));
        for (int badCall : new int[]{1, 2}) {
            for (Map.Entry<String, G1Point> entry : bad.entrySet()) {
                for (Generation generation : allGenerations()) {
                    String label = entry.getKey() + " at call " + badCall;
                    G1Point answer = entry.getValue();
                    Stub stub = Stub.withSecret((index, point, scalar) -> index == badCall
                            ? answer
                            : PureJavaBls12381Provider.INSTANCE.g1SecretScalarMul(point, scalar));
                    G1Pedersen pedersen = G1Pedersen.withProvider(stub.provider);
                    assertThrows(IllegalStateException.class, () -> generation.run(pedersen), label);
                    assertEquals(0, stub.count(PUBLIC_MUL), label + ": no fallback to the public multiplication");
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Provider-independence of generation
    // ---------------------------------------------------------------------------------------------

    @Test
    void commitments_areIdenticalForPureJavaAndADelegatingStub() throws IOException {
        G1Pedersen pure = G1Pedersen.pureJava();
        Stub stub = Stub.delegating();
        G1Pedersen viaStub = G1Pedersen.withProvider(stub.provider);

        for (Object[] row : SPEC_COMMITMENTS) {
            BigInteger m = (BigInteger) row[0];
            BigInteger r = (BigInteger) row[1];
            String expected = (String) row[2];
            assertEquals(expected, HEX.formatHex(pure.commitScalar(m, r).toPointBytes()), "pureJava " + m);
            assertEquals(expected, HEX.formatHex(viaStub.commitScalar(m, r).toPointBytes()), "stub " + m);
        }

        Random random = new Random(0x600_02L);
        for (int i = 0; i < 24; i++) {
            BigInteger m = randomScalar(random);
            BigInteger r = randomScalar(random);
            assertEquals(pure.commitScalar(m, r), viaStub.commitScalar(m, r));
        }
        for (int length : new int[]{0, 1, 55, 56, 64, 129, 1024}) {
            byte[] payload = new byte[length];
            random.nextBytes(payload);
            BigInteger r = randomScalar(random);
            G1PedersenBytesCommitment expected = pure.commitBytes(payload, r);
            assertEquals(expected, viaStub.commitBytes(payload, r));
            assertEquals(expected, viaStub.commitBytes(new ByteArrayInputStream(payload), length, r));
            assertEquals(expected, viaStub.commitBytesToEnd(new ByteArrayInputStream(payload), length, r));
        }
        assertEquals(0, stub.count(PUBLIC_MUL));
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------

    private static Map<String, Verification> verificationCases() {
        Map<String, Verification> cases = new LinkedHashMap<>();
        for (Object[] row : SPEC_COMMITMENTS) {
            BigInteger m = (BigInteger) row[0];
            BigInteger r = (BigInteger) row[1];
            G1PedersenCommitment c = G1PedersenCommitment.decode(HEX.parseHex((String) row[2]));
            String id = "C(" + m.toString(16) + ", " + r.toString(16) + ")";
            BigInteger otherM = m.signum() == 0 ? BigInteger.ONE : m.subtract(BigInteger.ONE);
            cases.put(id + " match", new Verification("true", p -> p.verifyScalar(c, m, r)));
            cases.put(id + " wrong value", new Verification("false", p -> p.verifyScalar(c, otherM, r)));
            cases.put(id + " swapped", new Verification(m.equals(r) ? "true" : "false", p -> p.verifyScalar(c, r, m)));
            // Check 2 with k = 254: q − 1 ≥ 2^254, so it is OUT_OF_RANGE there.
            cases.put(id + " amountBits 254", new Verification(
                    m.bitLength() <= 254 ? "true" : "reject:OUT_OF_RANGE", p -> p.verifyScalar(c, m, r, 254)));
            cases.put(id + " value = q", new Verification("reject:NON_CANONICAL_SCALAR", p -> p.verifyScalar(c, Q, r)));
            cases.put(id + " blinding = q + 1",
                    new Verification("reject:NON_CANONICAL_SCALAR", p -> p.verifyScalar(c, m, Q.add(BigInteger.ONE))));
            cases.put(id + " amountBits 0", new Verification("reject:INVALID_CONFIGURATION", p -> p.verifyScalar(c, m, r, 0)));
        }
        G1PedersenCommitment c = G1PedersenCommitment.decode(HEX.parseHex(C_12345_67890));
        BigInteger m = BigInteger.valueOf(12345);
        BigInteger r = BigInteger.valueOf(67890);
        // 12345 < 2^14 but not < 2^13.
        cases.put("check 2 passes at 14 bits", new Verification("true", p -> p.verifyScalar(c, m, r, 14)));
        cases.put("check 2 fails at 13 bits", new Verification("reject:OUT_OF_RANGE", p -> p.verifyScalar(c, m, r, 13)));

        // Bytes: the point of C(S_ABC, r) is the bytes commitment to "abc" with blinding r (spec §3).
        G1PedersenBytesCommitment b = G1PedersenBytesCommitment.decode(
                G1Pedersen.pureJava().commitScalar(S_ABC, r).toPointBytes());
        cases.put("bytes array match", new Verification("true", p -> p.verifyBytes(b, ABC, r)));
        cases.put("bytes array tampered", new Verification("false", p -> p.verifyBytes(b, "abd".getBytes(StandardCharsets.US_ASCII), r)));
        cases.put("bytes array wrong blinding", new Verification("false", p -> p.verifyBytes(b, ABC, r.add(BigInteger.ONE))));
        cases.put("bytes stream match", new Verification("true",
                p -> p.verifyBytes(b, new ByteArrayInputStream(ABC), 3, r)));
        cases.put("bytes stream truncated", new Verification("error:IOException",
                p -> p.verifyBytes(b, new ByteArrayInputStream(ABC), 4, r)));
        cases.put("bytes stream excess", new Verification("error:IOException",
                p -> p.verifyBytes(b, new ByteArrayInputStream(ABC), 2, r)));
        cases.put("bytes toEnd match", new Verification("true",
                p -> p.verifyBytesToEnd(b, new ByteArrayInputStream(ABC), 3, r)));
        cases.put("bytes toEnd over max", new Verification("error:IOException",
                p -> p.verifyBytesToEnd(b, new ByteArrayInputStream(ABC), 2, r)));
        cases.put("bytes blinding = q", new Verification("reject:NON_CANONICAL_SCALAR", p -> p.verifyBytes(b, ABC, Q)));
        cases.put("bytes length = -1", new Verification("reject:LENGTH_OUT_OF_RANGE",
                p -> p.verifyBytes(b, new ByteArrayInputStream(ABC), -1, r)));
        return cases;
    }

    private static String outcome(G1Pedersen pedersen, VerifyOp op) {
        try {
            return Boolean.toString(op.run(pedersen));
        } catch (CommitmentFormatException e) {
            return "reject:" + e.reason();
        } catch (Exception e) {
            return "error:" + e.getClass().getSimpleName();
        }
    }

    private static List<Generation> allGenerations() {
        BigInteger m = BigInteger.valueOf(12345);
        BigInteger r = BigInteger.valueOf(67890);
        return List.of(
                p -> p.commitScalar(m, r).toPointBytes(),
                p -> p.commitBytes(ABC, r).toPointBytes(),
                p -> p.commitBytes(new ByteArrayInputStream(ABC), ABC.length, r).toPointBytes(),
                p -> p.commitBytesToEnd(new ByteArrayInputStream(ABC), 16, r).toPointBytes());
    }

    /** Exactly two calls, in either order: one {@code (G, x)} and one {@code (H, r)}. */
    /**
     * ADR-0062 D1 r4: generation splits the value, {@code C = [x − t]·G + [r]·H + [t]·G} with a fresh
     * uniform {@code t}, so the calls are (G, x − t), (H, r), (G, t) and the two G scalars sum to x.
     */
    private static void assertBaseScalars(List<Call> calls, BigInteger x, BigInteger r) {
        assertEquals(3, calls.size());
        assertEquals(G, calls.get(0).args()[0], "first multiplication on G (spec §2.2)");
        assertEquals(H, calls.get(1).args()[0], "second multiplication on H (spec §2.2)");
        assertEquals(G, calls.get(2).args()[0], "third multiplication on G");
        assertEquals(r, calls.get(1).args()[1], "scalar on H");
        BigInteger xMinusT = (BigInteger) calls.get(0).args()[1];
        BigInteger t = (BigInteger) calls.get(2).args()[1];
        assertEquals(x.mod(Q), xMinusT.add(t).mod(Q), "the two scalars on G must sum to the value");
        assertTrue(xMinusT.signum() >= 0 && xMinusT.compareTo(Q) < 0 && t.signum() >= 0 && t.compareTo(Q) < 0,
                "both shares canonical");
        assertNotEquals(x, xMinusT, "the value must not reach the provider unsplit");
    }

    private static BigInteger randomScalar(Random random) {
        BigInteger x;
        do {
            x = new BigInteger(255, random);
        } while (x.compareTo(Q) >= 0);
        return x;
    }

    @FunctionalInterface
    private interface VerifyOp {
        boolean run(G1Pedersen pedersen) throws Exception;
    }

    @FunctionalInterface
    private interface Generation {
        byte[] run(G1Pedersen pedersen) throws Exception;
    }

    private record Verification(String expected, VerifyOp op) {
    }

    private record Rejection(CommitmentError reason, Executable call) {
    }

    @FunctionalInterface
    private interface SecretMul {
        /** {@code index} counts g1SecretScalarMul calls on this stub; 0 is the capability probe. */
        G1Point apply(int index, G1Point point, BigInteger scalar);
    }

    private record Call(String method, Object[] args) {
    }

    /**
     * A recording {@link Bls12381Provider}. Every method except {@code id()} is recorded, including
     * interface default methods. Calls delegate to the pure-Java provider, except
     * {@code g1SecretScalarMul}, which may be replaced ({@link #withSecret}) or left to the interface
     * default that throws {@link UnsupportedOperationException} ({@link #unsupported()}).
     */
    private static final class Stub implements InvocationHandler {
        final List<Call> calls = new ArrayList<>();
        final Bls12381Provider provider;
        private final SecretMul secretMul;
        private final boolean unsupported;
        private int secretIndex;

        private Stub(SecretMul secretMul, boolean unsupported) {
            this.secretMul = secretMul;
            this.unsupported = unsupported;
            this.provider = (Bls12381Provider) Proxy.newProxyInstance(
                    Bls12381Provider.class.getClassLoader(), new Class<?>[]{Bls12381Provider.class}, this);
        }

        static Stub delegating() {
            return new Stub(null, false);
        }

        static Stub withSecret(SecretMul secretMul) {
            return new Stub(secretMul, false);
        }

        static Stub unsupported() {
            return new Stub(null, true);
        }

        List<String> names() {
            return calls.stream().map(Call::method).toList();
        }

        long count(String method) {
            return calls.stream().filter(call -> call.method().equals(method)).count();
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                    case "equals" -> proxy == args[0];
                    case "hashCode" -> System.identityHashCode(proxy);
                    default -> "G1PedersenProviderTest.Stub";
                };
            }
            if (method.getName().equals("id")) {
                return "g1-pedersen-test-stub";
            }
            calls.add(new Call(method.getName(), args == null ? new Object[0] : args.clone()));
            if (method.getName().equals(SECRET_MUL)) {
                int index = secretIndex++;
                if (unsupported) {
                    assertTrue(method.isDefault());
                    return InvocationHandler.invokeDefault(proxy, method, args);
                }
                if (secretMul != null) {
                    return secretMul.apply(index, (G1Point) args[0], (BigInteger) args[1]);
                }
            }
            try {
                return method.invoke(PureJavaBls12381Provider.INSTANCE, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        }
    }

    /** A {@link BigInteger} subclass that records every overridden method call. */
    private static final class RecordingBigInteger extends BigInteger {
        private final transient List<String> calls;

        RecordingBigInteger(BigInteger value, List<String> calls) {
            super(value.toByteArray());
            this.calls = calls;
        }

        private void note(String method) {
            calls.add(method);
        }

        @Override public byte[] toByteArray() { note("toByteArray"); return super.toByteArray(); }
        @Override public int signum() { note("signum"); return super.signum(); }
        @Override public int compareTo(BigInteger val) { note("compareTo"); return super.compareTo(val); }
        @Override public int bitLength() { note("bitLength"); return super.bitLength(); }
        @Override public int bitCount() { note("bitCount"); return super.bitCount(); }
        @Override public boolean testBit(int n) { note("testBit"); return super.testBit(n); }
        @Override public int getLowestSetBit() { note("getLowestSetBit"); return super.getLowestSetBit(); }
        @Override public BigInteger abs() { note("abs"); return super.abs(); }
        @Override public BigInteger negate() { note("negate"); return super.negate(); }
        @Override public BigInteger mod(BigInteger m) { note("mod"); return super.mod(m); }
        @Override public BigInteger remainder(BigInteger val) { note("remainder"); return super.remainder(val); }
        @Override public BigInteger add(BigInteger val) { note("add"); return super.add(val); }
        @Override public BigInteger subtract(BigInteger val) { note("subtract"); return super.subtract(val); }
        @Override public BigInteger multiply(BigInteger val) { note("multiply"); return super.multiply(val); }
        @Override public BigInteger divide(BigInteger val) { note("divide"); return super.divide(val); }
        @Override public BigInteger shiftLeft(int n) { note("shiftLeft"); return super.shiftLeft(n); }
        @Override public BigInteger shiftRight(int n) { note("shiftRight"); return super.shiftRight(n); }
        @Override public BigInteger and(BigInteger val) { note("and"); return super.and(val); }
        @Override public BigInteger or(BigInteger val) { note("or"); return super.or(val); }
        @Override public BigInteger xor(BigInteger val) { note("xor"); return super.xor(val); }
        @Override public BigInteger min(BigInteger val) { note("min"); return super.min(val); }
        @Override public BigInteger max(BigInteger val) { note("max"); return super.max(val); }
        @Override public BigInteger modPow(BigInteger e, BigInteger m) { note("modPow"); return super.modPow(e, m); }
        @Override public BigInteger modInverse(BigInteger m) { note("modInverse"); return super.modInverse(m); }
        @Override public int intValue() { note("intValue"); return super.intValue(); }
        @Override public long longValue() { note("longValue"); return super.longValue(); }
        @Override public double doubleValue() { note("doubleValue"); return super.doubleValue(); }
        @Override public float floatValue() { note("floatValue"); return super.floatValue(); }
        @Override public boolean equals(Object x) { note("equals"); return super.equals(x); }
        @Override public int hashCode() { note("hashCode"); return super.hashCode(); }
        @Override public String toString() { note("toString"); return super.toString(); }
        @Override public String toString(int radix) { note("toString"); return super.toString(radix); }
    }

    /** An {@link InputStream} that fails, and remembers, any use. */
    private static final class UntouchableStream extends InputStream {
        boolean touched;

        private AssertionError touch(String method) {
            touched = true;
            return new AssertionError("stream method called: " + method);
        }

        @Override public int read() { throw touch("read()"); }
        @Override public int read(byte[] b) { throw touch("read(byte[])"); }
        @Override public int read(byte[] b, int off, int len) { throw touch("read(byte[], int, int)"); }
        @Override public byte[] readAllBytes() { throw touch("readAllBytes"); }
        @Override public byte[] readNBytes(int len) { throw touch("readNBytes(int)"); }
        @Override public int readNBytes(byte[] b, int off, int len) { throw touch("readNBytes(byte[], int, int)"); }
        @Override public long skip(long n) { throw touch("skip"); }
        @Override public void skipNBytes(long n) { throw touch("skipNBytes"); }
        @Override public int available() { throw touch("available"); }
        @Override public void close() { throw touch("close"); }
        @Override public void mark(int limit) { throw touch("mark"); }
        @Override public void reset() { throw touch("reset"); }
        @Override public boolean markSupported() { throw touch("markSupported"); }
        @Override public long transferTo(OutputStream out) { throw touch("transferTo"); }
    }

    @Test
    void stubSelfCheck_recordsDefaultMethodsAndDelegates() {
        // Guards the harness: a default method (g1Add) is recorded, and results equal the delegate's.
        Stub stub = Stub.delegating();
        G1Point sum = stub.provider.g1Add(G, H);
        assertNotNull(sum);
        assertEquals(PureJavaBls12381Provider.INSTANCE.g1Add(G, H), sum);
        assertEquals(List.of("g1Add"), stub.names());
        assertEquals("g1-pedersen-test-stub", stub.provider.id());
        assertEquals(List.of("g1Add"), stub.names());
        assertTrue(Arrays.equals(new Object[]{G, H}, stub.calls.get(0).args()));
    }

    /**
     * Regression for an M2 review finding: each provider result is validated, not only the sum. Two
     * off-curve results that cancel ({@code (1, 1)} and {@code (1, −1)}) would otherwise sum to the
     * valid identity and yield the commitment {@code O}.
     */
    @Test
    void providerReturningCancellingOffCurvePoints_isIllegalState() {
        G1Point offCurve = new G1Point(Fp.of(1), Fp.of(1));
        G1Point offCurveNegated = offCurve.negate();
        Stub stub = Stub.withSecret((index, point, scalar) -> switch (index) {
            case 0 -> PureJavaBls12381Provider.INSTANCE.g1SecretScalarMul(point, scalar);
            case 1 -> offCurve;
            default -> offCurveNegated;
        });
        G1Pedersen pedersen = G1Pedersen.withProvider(stub.provider);
        assertThrows(IllegalStateException.class,
                () -> pedersen.commitScalar(BigInteger.valueOf(12345), BigInteger.valueOf(67890)));
    }
}
