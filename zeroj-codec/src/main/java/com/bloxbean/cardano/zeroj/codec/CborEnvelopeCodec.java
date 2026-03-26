package com.bloxbean.cardano.zeroj.codec;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.*;
import co.nstant.in.cbor.model.Number;
import com.bloxbean.cardano.zeroj.api.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CBOR serialization and deserialization for {@link ZkProofEnvelope}.
 *
 * <p>Uses a deterministic CBOR map with integer keys for compact encoding:</p>
 * <pre>
 * 1: version (uint)
 * 2: proofSystem (text)
 * 3: curve (text)
 * 4: circuitId (text)
 * 5: proofBytes (bstr)
 * 6: publicInputs (array of bstr — BigInteger.toByteArray())
 * 7: vkRef (tagged: 0x01 + hash | 0x02 + id)
 * 8: domainTag (text, optional)
 * 9: metadata (map, optional)
 * 10: proofFormat (text, optional)
 * </pre>
 */
public final class CborEnvelopeCodec {

    private CborEnvelopeCodec() {}

    /**
     * Serialize a proof envelope to CBOR bytes.
     */
    public static byte[] encode(ZkProofEnvelope envelope) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            new CborEncoder(baos).encode(new CborBuilder()
                    .addMap()
                    .put(new UnsignedInteger(1), new UnsignedInteger(envelope.version()))
                    .put(new UnsignedInteger(2), new UnicodeString(envelope.proofSystem().value()))
                    .put(new UnsignedInteger(3), new UnicodeString(envelope.curve().value()))
                    .put(new UnsignedInteger(4), new UnicodeString(envelope.circuitId().value()))
                    .put(new UnsignedInteger(5), new ByteString(envelope.proofBytes()))
                    .put(new UnsignedInteger(6), encodePublicInputs(envelope.publicInputs()))
                    .put(new UnsignedInteger(7), encodeVkRef(envelope.vkRef()))
                    .end()
                    .build());
            return baos.toByteArray();
        } catch (CborException e) {
            throw new CodecException("Failed to encode envelope to CBOR", e);
        }
    }

    /**
     * Deserialize a proof envelope from CBOR bytes.
     */
    public static ZkProofEnvelope decode(byte[] cbor) {
        try {
            List<DataItem> items = CborDecoder.decode(cbor);
            if (items.isEmpty() || !(items.getFirst() instanceof co.nstant.in.cbor.model.Map map)) {
                throw new CodecException("CBOR envelope must be a map");
            }

            int version = getUint(map, 1);
            String proofSystem = getText(map, 2);
            String curve = getText(map, 3);
            String circuitId = getText(map, 4);
            byte[] proofBytes = getBytes(map, 5);
            PublicInputs publicInputs = decodePublicInputs(getArray(map, 6));
            VerificationKeyRef vkRef = decodeVkRef(getArray(map, 7));

            return ZkProofEnvelope.builder()
                    .version(version)
                    .proofSystem(ProofSystemId.fromValue(proofSystem))
                    .curve(CurveId.fromValue(curve))
                    .circuitId(new CircuitId(circuitId))
                    .proofBytes(proofBytes)
                    .publicInputs(publicInputs)
                    .vkRef(vkRef)
                    .build();
        } catch (CodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CodecException("Failed to decode CBOR envelope", e);
        }
    }

    // --- Encoding helpers ---

    private static Array encodePublicInputs(PublicInputs inputs) {
        Array array = new Array();
        for (BigInteger value : inputs.values()) {
            array.add(new ByteString(value.toByteArray()));
        }
        return array;
    }

    private static Array encodeVkRef(VerificationKeyRef ref) {
        Array array = new Array();
        switch (ref) {
            case VerificationKeyRef.ByHash h -> {
                array.add(new UnsignedInteger(1));
                array.add(new ByteString(h.hash()));
            }
            case VerificationKeyRef.ById id -> {
                array.add(new UnsignedInteger(2));
                array.add(new UnicodeString(id.id()));
            }
        }
        return array;
    }

    // --- Decoding helpers ---

    private static PublicInputs decodePublicInputs(Array array) {
        List<BigInteger> values = new ArrayList<>();
        for (DataItem item : array.getDataItems()) {
            if (item instanceof ByteString bs) {
                values.add(new BigInteger(bs.getBytes()));
            } else {
                throw new CodecException("Public input must be a byte string");
            }
        }
        return new PublicInputs(values);
    }

    private static VerificationKeyRef decodeVkRef(Array array) {
        List<DataItem> items = array.getDataItems();
        if (items.size() != 2) {
            throw new CodecException("VK ref must be a 2-element array");
        }
        int tag = ((Number) items.get(0)).getValue().intValue();
        return switch (tag) {
            case 1 -> new VerificationKeyRef.ByHash(((ByteString) items.get(1)).getBytes());
            case 2 -> new VerificationKeyRef.ById(((UnicodeString) items.get(1)).getString());
            default -> throw new CodecException("Unknown VK ref tag: " + tag);
        };
    }

    private static int getUint(co.nstant.in.cbor.model.Map map, int key) {
        DataItem item = map.get(new UnsignedInteger(key));
        if (item == null) throw new CodecException("Missing CBOR map key: " + key);
        return ((Number) item).getValue().intValue();
    }

    private static String getText(co.nstant.in.cbor.model.Map map, int key) {
        DataItem item = map.get(new UnsignedInteger(key));
        if (item == null) throw new CodecException("Missing CBOR map key: " + key);
        return ((UnicodeString) item).getString();
    }

    private static byte[] getBytes(co.nstant.in.cbor.model.Map map, int key) {
        DataItem item = map.get(new UnsignedInteger(key));
        if (item == null) throw new CodecException("Missing CBOR map key: " + key);
        return ((ByteString) item).getBytes();
    }

    private static Array getArray(co.nstant.in.cbor.model.Map map, int key) {
        DataItem item = map.get(new UnsignedInteger(key));
        if (item == null) throw new CodecException("Missing CBOR map key: " + key);
        return (Array) item;
    }
}
