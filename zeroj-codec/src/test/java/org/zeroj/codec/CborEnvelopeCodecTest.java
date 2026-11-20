package org.zeroj.codec;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.UnsignedInteger;
import co.nstant.in.cbor.model.UnicodeString;
import org.zeroj.api.*;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CborEnvelopeCodecTest {

    @Test
    void roundTripWithByHashRef() {
        var original = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("multiplier"))
                .proofBytes(new byte[]{1, 2, 3, 4, 5})
                .publicInputs(new PublicInputs(List.of(
                        BigInteger.valueOf(33),
                        BigInteger.valueOf(3))))
                .vkRef(new VerificationKeyRef.ByHash(new byte[32]))
                .build();

        byte[] cbor = CborEnvelopeCodec.encode(original);
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);

        var decoded = CborEnvelopeCodec.decode(cbor);
        assertEquals(original.proofSystem(), decoded.proofSystem());
        assertEquals(original.curve(), decoded.curve());
        assertEquals(original.circuitId(), decoded.circuitId());
        assertArrayEquals(original.proofBytes(), decoded.proofBytes());
        assertEquals(original.publicInputs(), decoded.publicInputs());
        assertEquals(original.version(), decoded.version());
    }

    @Test
    void roundTripWithByIdRef() {
        var original = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("transfer-v2"))
                .proofBytes(new byte[]{10, 20, 30})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk-transfer-v2"))
                .build();

        byte[] cbor = CborEnvelopeCodec.encode(original);
        var decoded = CborEnvelopeCodec.decode(cbor);

        assertInstanceOf(VerificationKeyRef.ById.class, decoded.vkRef());
        assertEquals("vk-transfer-v2", ((VerificationKeyRef.ById) decoded.vkRef()).id());
    }

    @Test
    void roundTripLargePublicInputs() {
        // BN254 field-size numbers
        var fieldOrder = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
        var original = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of(
                        fieldOrder.subtract(BigInteger.ONE),
                        BigInteger.ZERO,
                        BigInteger.valueOf(42))))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .build();

        var decoded = CborEnvelopeCodec.decode(CborEnvelopeCodec.encode(original));
        assertEquals(3, decoded.publicInputs().size());
        assertEquals(fieldOrder.subtract(BigInteger.ONE), decoded.publicInputs().get(0));
        assertEquals(BigInteger.ZERO, decoded.publicInputs().get(1));
        assertEquals(BigInteger.valueOf(42), decoded.publicInputs().get(2));
    }

    @Test
    void roundTripFromRealSnarkjsVectors() {
        var proof = SnarkjsJsonCodec.parseProof(
                getClass().getResourceAsStream("/test-vectors/groth16-bn254/proof.json"));
        var vk = SnarkjsJsonCodec.parseVerificationKey(
                getClass().getResourceAsStream("/test-vectors/groth16-bn254/verification_key.json"));
        var inputs = SnarkjsJsonCodec.parsePublicInputs(
                getClass().getResourceAsStream("/test-vectors/groth16-bn254/public.json"));

        var envelope = SnarkjsJsonCodec.toEnvelope(proof, vk, inputs, new CircuitId("multiplier"));

        byte[] cbor = CborEnvelopeCodec.encode(envelope);
        var decoded = CborEnvelopeCodec.decode(cbor);

        assertEquals(envelope.proofSystem(), decoded.proofSystem());
        assertEquals(envelope.curve(), decoded.curve());
        assertEquals(envelope.circuitId(), decoded.circuitId());
        assertArrayEquals(envelope.proofBytes(), decoded.proofBytes());
        assertEquals(envelope.publicInputs(), decoded.publicInputs());
    }

    @Test
    void decodeMalformedCborThrows() {
        assertThrows(CodecException.class, () ->
                CborEnvelopeCodec.decode(new byte[]{0x00, 0x01, 0x02}));
    }

    @Test
    void decodeRejectsNonSha256VkHashRef() throws Exception {
        var publicInputs = new co.nstant.in.cbor.model.Array();
        publicInputs.add(new ByteString(BigInteger.ONE.toByteArray()));
        var vkRef = new co.nstant.in.cbor.model.Array();
        vkRef.add(new UnsignedInteger(1));
        vkRef.add(new ByteString(new byte[16]));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(new CborBuilder()
                .addMap()
                .put(new UnsignedInteger(1), new UnsignedInteger(1))
                .put(new UnsignedInteger(2), new UnicodeString("groth16"))
                .put(new UnsignedInteger(3), new UnicodeString("bls12-381"))
                .put(new UnsignedInteger(4), new UnicodeString("bad-vk-ref"))
                .put(new UnsignedInteger(5), new ByteString(new byte[]{1}))
                .put(new UnsignedInteger(6), publicInputs)
                .put(new UnsignedInteger(7), vkRef)
                .end()
                .build());

        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(baos.toByteArray()));
    }

    @Test
    void roundTripPreservesDomainTagMetadataAndProofFormat() {
        var original = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.PLONK)
                .curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("cardano-plonk-circuit"))
                .proofBytes(new byte[]{7, 8, 9})
                .publicInputs(new PublicInputs(List.of(BigInteger.ZERO, BigInteger.valueOf(42))))
                .vkRef(new VerificationKeyRef.ById("vk-plonk"))
                .domainTag("cardano-preprod")
                .metadata(java.util.Map.of("zebra", "last", "a", "short", "bb", "mid"))
                .proofFormat("cardano-plonk-v1")
                .build();

        byte[] cbor = CborEnvelopeCodec.encode(original);
        var decoded = CborEnvelopeCodec.decode(cbor);

        assertEquals(original, decoded);
        assertEquals("cardano-preprod", decoded.domainTag());
        assertEquals(java.util.Map.of("zebra", "last", "a", "short", "bb", "mid"), decoded.metadata());
        assertEquals("cardano-plonk-v1", decoded.proofFormat().orElse(null));
    }

    @Test
    void decodeRejectsUnknownDuplicateNonCanonicalAndPaddedCbor() throws Exception {
        // Build a valid minimal 7-key envelope bytes reference
        var base = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("c"))
                .proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk"))
                .build();
        byte[] valid = CborEnvelopeCodec.encode(base);
        assertEquals(base, CborEnvelopeCodec.decode(valid));

        // 1. Indefinite-length map (0xBF ... 0xFF) instead of 0xA7 ...
        byte[] indefiniteMap = new byte[valid.length + 1];
        indefiniteMap[0] = (byte) 0xBF;
        System.arraycopy(valid, 1, indefiniteMap, 1, valid.length - 1);
        indefiniteMap[indefiniteMap.length - 1] = (byte) 0xFF;
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(indefiniteMap));

        // 2. Unknown map key (11)
        var publicInputs = new co.nstant.in.cbor.model.Array();
        publicInputs.add(new ByteString(BigInteger.ONE.toByteArray()));
        var vkRef = new co.nstant.in.cbor.model.Array();
        vkRef.add(new UnsignedInteger(2));
        vkRef.add(new UnicodeString("vk"));
        ByteArrayOutputStream unknownKeyOut = new ByteArrayOutputStream();
        new CborEncoder(unknownKeyOut).encode(new CborBuilder()
                .addMap()
                .put(new UnsignedInteger(1), new UnsignedInteger(1))
                .put(new UnsignedInteger(2), new UnicodeString("groth16"))
                .put(new UnsignedInteger(3), new UnicodeString("bls12-381"))
                .put(new UnsignedInteger(4), new UnicodeString("c"))
                .put(new UnsignedInteger(5), new ByteString(new byte[]{1}))
                .put(new UnsignedInteger(6), publicInputs)
                .put(new UnsignedInteger(7), vkRef)
                .put(new UnsignedInteger(11), new UnicodeString("extra"))
                .end().build());
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(unknownKeyOut.toByteArray()));

        // 3. Out-of-order keys (2 before 1)
        ByteArrayOutputStream outOfOrderOut = new ByteArrayOutputStream();
        new CborEncoder(outOfOrderOut).encode(new CborBuilder()
                .addMap()
                .put(new UnsignedInteger(2), new UnicodeString("groth16"))
                .put(new UnsignedInteger(1), new UnsignedInteger(1))
                .put(new UnsignedInteger(3), new UnicodeString("bls12-381"))
                .put(new UnsignedInteger(4), new UnicodeString("c"))
                .put(new UnsignedInteger(5), new ByteString(new byte[]{1}))
                .put(new UnsignedInteger(6), publicInputs)
                .put(new UnsignedInteger(7), vkRef)
                .end().build());
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(outOfOrderOut.toByteArray()));

        // 4. Non-minimal BigInteger encoding ([0x00, 0x01] instead of [0x01])
        var paddedInputs = new co.nstant.in.cbor.model.Array();
        paddedInputs.add(new ByteString(new byte[]{0x00, 0x01}));
        ByteArrayOutputStream paddedOut = new ByteArrayOutputStream();
        new CborEncoder(paddedOut).encode(new CborBuilder()
                .addMap()
                .put(new UnsignedInteger(1), new UnsignedInteger(1))
                .put(new UnsignedInteger(2), new UnicodeString("groth16"))
                .put(new UnsignedInteger(3), new UnicodeString("bls12-381"))
                .put(new UnsignedInteger(4), new UnicodeString("c"))
                .put(new UnsignedInteger(5), new ByteString(new byte[]{1}))
                .put(new UnsignedInteger(6), paddedInputs)
                .put(new UnsignedInteger(7), vkRef)
                .end().build());
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(paddedOut.toByteArray()));

        // 5. Unsupported version (2)
        ByteArrayOutputStream badVersionOut = new ByteArrayOutputStream();
        new CborEncoder(badVersionOut).encode(new CborBuilder()
                .addMap()
                .put(new UnsignedInteger(1), new UnsignedInteger(2))
                .put(new UnsignedInteger(2), new UnicodeString("groth16"))
                .put(new UnsignedInteger(3), new UnicodeString("bls12-381"))
                .put(new UnsignedInteger(4), new UnicodeString("c"))
                .put(new UnsignedInteger(5), new ByteString(new byte[]{1}))
                .put(new UnsignedInteger(6), publicInputs)
                .put(new UnsignedInteger(7), vkRef)
                .end().build());
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(badVersionOut.toByteArray()));

        // 6. Explicitly encoded empty optional domainTag (key 8 = "")
        ByteArrayOutputStream emptyDomainOut = new ByteArrayOutputStream();
        new CborEncoder(emptyDomainOut).encode(new CborBuilder()
                .addMap()
                .put(new UnsignedInteger(1), new UnsignedInteger(1))
                .put(new UnsignedInteger(2), new UnicodeString("groth16"))
                .put(new UnsignedInteger(3), new UnicodeString("bls12-381"))
                .put(new UnsignedInteger(4), new UnicodeString("c"))
                .put(new UnsignedInteger(5), new ByteString(new byte[]{1}))
                .put(new UnsignedInteger(6), publicInputs)
                .put(new UnsignedInteger(7), vkRef)
                .put(new UnsignedInteger(8), new UnicodeString(""))
                .end().build());
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(emptyDomainOut.toByteArray()));

        // 7. Non-minimal uint encoding for key 1 value (0x18 0x01 instead of 0x01)
        // valid starts with: 0xA7 (map 7), 0x01 (key 1), 0x01 (val 1), ...
        assertEquals((byte) 0xA7, valid[0]);
        assertEquals((byte) 0x01, valid[1]);
        assertEquals((byte) 0x01, valid[2]);
        byte[] nonMinimalInt = new byte[valid.length + 1];
        nonMinimalInt[0] = valid[0];
        nonMinimalInt[1] = valid[1];
        nonMinimalInt[2] = 0x18;
        nonMinimalInt[3] = 0x01;
        System.arraycopy(valid, 3, nonMinimalInt, 4, valid.length - 3);
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(nonMinimalInt));

        // 8. Duplicate key (key 1 repeated inside 8-entry map)
        byte[] dupKey = new byte[valid.length + 2];
        dupKey[0] = (byte) 0xA8;
        dupKey[1] = 0x01;
        dupKey[2] = 0x01;
        System.arraycopy(valid, 1, dupKey, 3, valid.length - 1);
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(dupKey));

        // 9. Trailing CBOR item appended to a valid canonical envelope
        byte[] trailing = new byte[valid.length + 1];
        System.arraycopy(valid, 0, trailing, 0, valid.length);
        trailing[valid.length] = 0x00;
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(trailing));
    }

    @Test
    void metadataUsesRfc8949UnsignedUtf8OrderAndRejectsMalformedUtf16() {
        // RFC 8949 §4.2.1: "aa" = UTF-8 0x61 0x61 (len 2), "é" = UTF-8 0xC3 0xA9 (len 2),
        // "😀" = UTF-8 0xF0 0x9F 0x98 0x80 (len 4). Unsigned bytewise order is "aa" < "é" < "😀".
        var mapOrder1 = new java.util.LinkedHashMap<String, String>();
        mapOrder1.put("é", "2");
        mapOrder1.put("😀", "3");
        mapOrder1.put("aa", "1");

        var mapOrder2 = new java.util.LinkedHashMap<String, String>();
        mapOrder2.put("aa", "1");
        mapOrder2.put("é", "2");
        mapOrder2.put("😀", "3");

        var env1 = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16).curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("c")).proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ById("v"))
                .metadata(mapOrder1).build();
        var env2 = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16).curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("c")).proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ById("v"))
                .metadata(mapOrder2).build();

        byte[] cbor1 = CborEnvelopeCodec.encode(env1);
        byte[] cbor2 = CborEnvelopeCodec.encode(env2);
        assertArrayEquals(cbor1, cbor2, "Metadata insertion order must not affect canonical CBOR");

        // Independent RFC 8949 §4.2.1 expected wire suffix for key 9 (metadata):
        // 09 A3 62 61 61 61 31 62 C3 A9 61 32 64 F0 9F 98 80 61 33
        byte[] expectedMetaSuffix = new byte[]{
                0x09, (byte) 0xA3,
                0x62, 0x61, 0x61, 0x61, 0x31,
                0x62, (byte) 0xC3, (byte) 0xA9, 0x61, 0x32,
                0x64, (byte) 0xF0, (byte) 0x9F, (byte) 0x98, (byte) 0x80, 0x61, 0x33
        };
        byte[] actualSuffix = java.util.Arrays.copyOfRange(
                cbor1, cbor1.length - expectedMetaSuffix.length, cbor1.length);
        assertArrayEquals(expectedMetaSuffix, actualSuffix,
                "Metadata map bytes must match RFC 8949 §4.2.1 unsigned UTF-8 bytewise ordering");

        var decoded = CborEnvelopeCodec.decode(cbor1);
        assertEquals(mapOrder2, decoded.metadata());

        // Swapping "é" before "aa" on the wire must be rejected
        byte[] wrongOrder = cbor1.clone();
        byte[] swappedSuffix = new byte[]{
                0x09, (byte) 0xA3,
                0x62, (byte) 0xC3, (byte) 0xA9, 0x61, 0x32,
                0x62, 0x61, 0x61, 0x61, 0x31,
                0x64, (byte) 0xF0, (byte) 0x9F, (byte) 0x98, (byte) 0x80, 0x61, 0x33
        };
        System.arraycopy(swappedSuffix, 0, wrongOrder, wrongOrder.length - swappedSuffix.length, swappedSuffix.length);
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(wrongOrder));

        // Malformed UTF-16 (unpaired surrogates) must be rejected on encode
        String unpairedHigh = "bad\uD800key";
        String unpairedLow = "bad\uDC00val";
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.encode(ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16).curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("c")).proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ById("v"))
                .domainTag(unpairedHigh).build()));
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.encode(ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16).curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("c")).proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ById("v"))
                .metadata(java.util.Map.of(unpairedHigh, "ok")).build()));
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.encode(ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16).curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("c")).proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ById("v"))
                .metadata(java.util.Map.of("ok", unpairedLow)).build()));
    }

    @Test
    void decodeRejectsExcessiveNestingAndDeclaredCollectionLengthBeforeAllocation() {
        // 1. Deeply nested CBOR arrays (10,000 levels) must fail fast with CodecException, not StackOverflowError
        byte[] deepNesting = new byte[10_000];
        java.util.Arrays.fill(deepNesting, (byte) 0x81);
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(deepNesting));

        // 2. One level beyond schema: array inside publicInputs instead of byte string
        // Valid 7-key envelope with empty publicInputs: find key 6 (06 80) and replace with 06 81 80 ([[]])
        var base = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16).curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("c")).proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ById("v")).build();
        byte[] valid = CborEnvelopeCodec.encode(base);
        int key6Idx = -1;
        for (int i = 0; i < valid.length - 1; i++) {
            if (valid[i] == 0x06 && valid[i + 1] == (byte) 0x80) {
                key6Idx = i;
                break;
            }
        }
        assertTrue(key6Idx > 0);
        byte[] nestedPublicInput = new byte[valid.length + 1];
        System.arraycopy(valid, 0, nestedPublicInput, 0, key6Idx + 1);
        nestedPublicInput[key6Idx + 1] = (byte) 0x81; // array(1)
        nestedPublicInput[key6Idx + 2] = (byte) 0x80; // nested array(0) instead of bstr
        System.arraycopy(valid, key6Idx + 2, nestedPublicInput, key6Idx + 3, valid.length - key6Idx - 2);
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(nestedPublicInput));

        // 3. Excessive declared publicInputs length (1,000,000 elements) in tiny buffer must not OOM
        byte[] hugeDeclaredCount = new byte[key6Idx + 6];
        System.arraycopy(valid, 0, hugeDeclaredCount, 0, key6Idx + 1);
        hugeDeclaredCount[key6Idx + 1] = (byte) 0x9A; // array with 4-byte uint length
        hugeDeclaredCount[key6Idx + 2] = 0x00;
        hugeDeclaredCount[key6Idx + 3] = 0x0F;
        hugeDeclaredCount[key6Idx + 4] = 0x42;
        hugeDeclaredCount[key6Idx + 5] = 0x40; // 1,000,000
        assertThrows(CodecException.class, () -> CborEnvelopeCodec.decode(hugeDeclaredCount));
    }
}
