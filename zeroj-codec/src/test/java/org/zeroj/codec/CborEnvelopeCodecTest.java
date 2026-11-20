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
    }
}
