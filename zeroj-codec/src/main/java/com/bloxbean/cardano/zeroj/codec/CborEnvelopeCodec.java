package com.bloxbean.cardano.zeroj.codec;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.*;
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

    private static final int MAX_CBOR_BYTES = 16 * 1024 * 1024;
    private static final int MAX_PROOF_BYTES = 8 * 1024 * 1024;
    private static final int MAX_PUBLIC_INPUTS = 1 << 20;
    private static final int MAX_PUBLIC_INPUT_BYTES = 128;
    private static final int SHA256_BYTES = 32;
    private static final int MAX_TEXT_BYTES = 256;

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
            if (cbor == null || cbor.length > MAX_CBOR_BYTES) {
                throw new CodecException("CBOR envelope is too large");
            }
            List<DataItem> items = CborDecoder.decode(cbor);
            if (items.size() != 1 || !(items.getFirst() instanceof co.nstant.in.cbor.model.Map map)) {
                throw new CodecException("CBOR envelope must be a map");
            }

            int version = getUint(map, 1);
            String proofSystem = getText(map, 2);
            String curve = getText(map, 3);
            String circuitId = getText(map, 4);
            byte[] proofBytes = getBytes(map, 5, MAX_PROOF_BYTES);
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
        if (array.getDataItems().size() > MAX_PUBLIC_INPUTS) {
            throw new CodecException("Too many public inputs in CBOR envelope");
        }
        List<BigInteger> values = new ArrayList<>();
        for (DataItem item : array.getDataItems()) {
            if (item instanceof ByteString bs) {
                byte[] bytes = bs.getBytes();
                if (bytes == null || bytes.length == 0 || bytes.length > MAX_PUBLIC_INPUT_BYTES) {
                    throw new CodecException("Invalid public input byte length");
                }
                BigInteger value = new BigInteger(bytes);
                if (value.signum() < 0) {
                    throw new CodecException("Public input must be non-negative");
                }
                values.add(value);
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
        if (!(items.get(0) instanceof UnsignedInteger tagItem)) {
            throw new CodecException("VK ref tag must be an unsigned integer");
        }
        int tag = tagItem.getValue().intValueExact();
        return switch (tag) {
            case 1 -> {
                if (!(items.get(1) instanceof ByteString hashItem)) {
                    throw new CodecException("VK hash ref must be a byte string");
                }
                byte[] hash = hashItem.getBytes();
                if (hash == null || hash.length != SHA256_BYTES) {
                    throw new CodecException("VK hash ref must be a SHA-256 hash");
                }
                yield new VerificationKeyRef.ByHash(hash);
            }
            case 2 -> {
                if (!(items.get(1) instanceof UnicodeString idItem)) {
                    throw new CodecException("VK id ref must be text");
                }
                String id = idItem.getString();
                if (id == null || id.isBlank() || id.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_TEXT_BYTES) {
                    throw new CodecException("Invalid VK id ref");
                }
                yield new VerificationKeyRef.ById(id);
            }
            default -> throw new CodecException("Unknown VK ref tag: " + tag);
        };
    }

    private static int getUint(co.nstant.in.cbor.model.Map map, int key) {
        DataItem item = map.get(new UnsignedInteger(key));
        if (item == null) throw new CodecException("Missing CBOR map key: " + key);
        if (!(item instanceof UnsignedInteger number)) {
            throw new CodecException("CBOR map key " + key + " must be an unsigned integer");
        }
        try {
            return number.getValue().intValueExact();
        } catch (ArithmeticException e) {
            throw new CodecException("CBOR map key " + key + " integer is too large", e);
        }
    }

    private static String getText(co.nstant.in.cbor.model.Map map, int key) {
        DataItem item = map.get(new UnsignedInteger(key));
        if (item == null) throw new CodecException("Missing CBOR map key: " + key);
        if (!(item instanceof UnicodeString textItem)) {
            throw new CodecException("CBOR map key " + key + " must be text");
        }
        String value = textItem.getString();
        if (value == null || value.isBlank()
                || value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_TEXT_BYTES) {
            throw new CodecException("Invalid CBOR text value for key: " + key);
        }
        return value;
    }

    private static byte[] getBytes(co.nstant.in.cbor.model.Map map, int key, int maxLength) {
        DataItem item = map.get(new UnsignedInteger(key));
        if (item == null) throw new CodecException("Missing CBOR map key: " + key);
        if (!(item instanceof ByteString bytesItem)) {
            throw new CodecException("CBOR map key " + key + " must be a byte string");
        }
        byte[] bytes = bytesItem.getBytes();
        if (bytes == null || bytes.length == 0 || bytes.length > maxLength) {
            throw new CodecException("Invalid CBOR byte string length for key: " + key);
        }
        return bytes;
    }

    private static Array getArray(co.nstant.in.cbor.model.Map map, int key) {
        DataItem item = map.get(new UnsignedInteger(key));
        if (item == null) throw new CodecException("Missing CBOR map key: " + key);
        if (!(item instanceof Array array)) {
            throw new CodecException("CBOR map key " + key + " must be an array");
        }
        return array;
    }
}
