package org.zeroj.codec;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.PublicInputs;
import org.zeroj.api.VerificationKeyRef;
import org.zeroj.api.ZkProofEnvelope;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Strict deterministic CBOR serialization and deserialization for {@link ZkProofEnvelope}
 * (ADR-0067, RFC 8949 §4.2).
 *
 * <p>Uses a deterministic CBOR map with ascending integer keys:</p>
 * <pre>
 * 1: version (uint, 1..currentVersion)
 * 2: proofSystem (text)
 * 3: curve (text)
 * 4: circuitId (text)
 * 5: proofBytes (bstr, non-empty)
 * 6: publicInputs (array of minimal non-negative BigInteger.toByteArray() bstr)
 * 7: vkRef (2-element array: [1, sha256-bstr] | [2, id-text])
 * 8: domainTag (text, optional — omitted when empty)
 * 9: metadata (map of text->text sorted in RFC 8949 canonical key order, optional — omitted when empty)
 * 10: proofFormat (text, optional — omitted when absent)
 * </pre>
 *
 * <p>Local non-wire fields ({@code proofUri}, {@code proofHash}, {@code createdAt},
 * {@code producerId}) are not carried in the CBOR wire encoding. Decoding fails closed on
 * duplicate keys, unknown keys, non-minimal integers, indefinite lengths, padded
 * {@link BigInteger} byte strings, explicitly encoded empty optional fields, or any other
 * non-canonical CBOR representation.</p>
 */
public final class CborEnvelopeCodec {

    private static final int MAX_CBOR_BYTES = 16 * 1024 * 1024;
    private static final int MAX_PROOF_BYTES = 8 * 1024 * 1024;
    private static final int MAX_PUBLIC_INPUTS = 1 << 20;
    private static final int MAX_PUBLIC_INPUT_BYTES = 128;
    private static final int SHA256_BYTES = 32;
    private static final int MAX_TEXT_BYTES = 256;
    private static final int MAX_METADATA_ENTRIES = 64;

    private static final Comparator<String> CANONICAL_TEXT_KEY_ORDER = (a, b) -> {
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        int lenCmp = Integer.compare(aBytes.length, bBytes.length);
        return lenCmp != 0 ? lenCmp : Arrays.compareUnsigned(aBytes, bBytes);
    };

    private CborEnvelopeCodec() {}

    /**
     * Serialize a proof envelope to canonical deterministic CBOR bytes.
     */
    public static byte[] encode(ZkProofEnvelope envelope) {
        Objects.requireNonNull(envelope, "envelope must not be null");
        try {
            if (envelope.version() < 1 || envelope.version() > ZkProofEnvelope.currentVersion()) {
                throw new CodecException("Unsupported envelope version: " + envelope.version());
            }
            String proofSystem = requireValidText(envelope.proofSystem().value(), "proofSystem");
            String curve = requireValidText(envelope.curve().value(), "curve");
            String circuitId = requireValidText(envelope.circuitId().value(), "circuitId");
            byte[] proofBytes = envelope.proofBytes();
            if (proofBytes.length == 0 || proofBytes.length > MAX_PROOF_BYTES) {
                throw new CodecException("Invalid proofBytes length: " + proofBytes.length);
            }

            co.nstant.in.cbor.model.Map map = new co.nstant.in.cbor.model.Map();
            map.put(new UnsignedInteger(1), new UnsignedInteger(envelope.version()));
            map.put(new UnsignedInteger(2), new UnicodeString(proofSystem));
            map.put(new UnsignedInteger(3), new UnicodeString(curve));
            map.put(new UnsignedInteger(4), new UnicodeString(circuitId));
            map.put(new UnsignedInteger(5), new ByteString(proofBytes));
            map.put(new UnsignedInteger(6), encodePublicInputs(envelope.publicInputs()));
            map.put(new UnsignedInteger(7), encodeVkRef(envelope.vkRef()));

            if (!envelope.domainTag().isEmpty()) {
                requireBoundedText(envelope.domainTag(), "domainTag");
                map.put(new UnsignedInteger(8), new UnicodeString(envelope.domainTag()));
            }
            if (!envelope.metadata().isEmpty()) {
                map.put(new UnsignedInteger(9), encodeMetadata(envelope.metadata()));
            }
            if (envelope.proofFormat().isPresent()) {
                String proofFormat = requireValidText(envelope.proofFormat().orElseThrow(), "proofFormat");
                map.put(new UnsignedInteger(10), new UnicodeString(proofFormat));
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            new CborEncoder(baos).encode(List.of(map));
            byte[] encoded = baos.toByteArray();
            if (encoded.length > MAX_CBOR_BYTES) {
                throw new CodecException("Encoded CBOR envelope exceeds maximum size");
            }
            return encoded;
        } catch (CodecException e) {
            throw e;
        } catch (CborException e) {
            throw new CodecException("Failed to encode envelope to CBOR", e);
        }
    }

    /**
     * Deserialize a strictly canonical CBOR proof envelope.
     */
    public static ZkProofEnvelope decode(byte[] cbor) {
        try {
            if (cbor == null || cbor.length == 0 || cbor.length > MAX_CBOR_BYTES) {
                throw new CodecException("Invalid CBOR envelope size");
            }
            CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(cbor));
            decoder.setRejectDuplicateKeys(true);
            decoder.setMaxPreallocationSize(MAX_CBOR_BYTES);
            List<DataItem> items = decoder.decode();
            if (items.size() != 1 || !(items.getFirst() instanceof co.nstant.in.cbor.model.Map map)) {
                throw new CodecException("CBOR envelope must be a single map");
            }
            validateAllowedKeys(map);

            int version = getUint(map, 1);
            if (version < 1 || version > ZkProofEnvelope.currentVersion()) {
                throw new CodecException("Unsupported CBOR envelope version: " + version);
            }
            String proofSystem = getText(map, 2);
            String curve = getText(map, 3);
            String circuitId = getText(map, 4);
            byte[] proofBytes = getBytes(map, 5, MAX_PROOF_BYTES);
            PublicInputs publicInputs = decodePublicInputs(getArray(map, 6));
            VerificationKeyRef vkRef = decodeVkRef(getArray(map, 7));

            ZkProofEnvelope.Builder builder = ZkProofEnvelope.builder()
                    .version(version)
                    .proofSystem(ProofSystemId.fromValue(proofSystem))
                    .curve(CurveId.fromValue(curve))
                    .circuitId(new CircuitId(circuitId))
                    .proofBytes(proofBytes)
                    .publicInputs(publicInputs)
                    .vkRef(vkRef);

            DataItem domainTagItem = map.get(new UnsignedInteger(8));
            if (domainTagItem != null) {
                builder.domainTag(decodeDomainTag(domainTagItem));
            }
            DataItem metadataItem = map.get(new UnsignedInteger(9));
            if (metadataItem != null) {
                builder.metadata(decodeMetadata(metadataItem));
            }
            DataItem proofFormatItem = map.get(new UnsignedInteger(10));
            if (proofFormatItem != null) {
                builder.proofFormat(decodeProofFormat(proofFormatItem));
            }

            ZkProofEnvelope envelope = builder.build();
            if (!Arrays.equals(cbor, encode(envelope))) {
                throw new CodecException("CBOR proof envelope is not canonically encoded");
            }
            return envelope;
        } catch (CodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CodecException("Failed to decode CBOR envelope", e);
        }
    }

    // --- Encoding helpers ---

    private static Array encodePublicInputs(PublicInputs inputs) {
        if (inputs.size() > MAX_PUBLIC_INPUTS) {
            throw new CodecException("Too many public inputs in CBOR envelope");
        }
        Array array = new Array();
        for (BigInteger value : inputs.values()) {
            if (value == null || value.signum() < 0) {
                throw new CodecException("Public input must be non-negative");
            }
            byte[] encoded = value.toByteArray();
            if (encoded.length > MAX_PUBLIC_INPUT_BYTES) {
                throw new CodecException("Public input exceeds maximum byte length");
            }
            array.add(new ByteString(encoded));
        }
        return array;
    }

    private static Array encodeVkRef(VerificationKeyRef ref) {
        Array array = new Array();
        switch (ref) {
            case VerificationKeyRef.ByHash h -> {
                byte[] hash = h.hash();
                if (hash.length != SHA256_BYTES) {
                    throw new CodecException("VK hash ref must be a SHA-256 hash");
                }
                array.add(new UnsignedInteger(1));
                array.add(new ByteString(hash));
            }
            case VerificationKeyRef.ById id -> {
                array.add(new UnsignedInteger(2));
                array.add(new UnicodeString(requireValidText(id.id(), "vkRef.id")));
            }
        }
        return array;
    }

    private static co.nstant.in.cbor.model.Map encodeMetadata(Map<String, String> metadata) {
        if (metadata.size() > MAX_METADATA_ENTRIES) {
            throw new CodecException("Too many metadata entries in CBOR envelope");
        }
        List<String> keys = new ArrayList<>(metadata.keySet());
        for (String key : keys) {
            requireValidText(key, "metadata key");
            String value = metadata.get(key);
            if (value == null) {
                throw new CodecException("Metadata value must not be null for key: " + key);
            }
            requireBoundedText(value, "metadata value");
        }
        keys.sort(CANONICAL_TEXT_KEY_ORDER);
        co.nstant.in.cbor.model.Map map = new co.nstant.in.cbor.model.Map();
        for (String key : keys) {
            map.put(new UnicodeString(key), new UnicodeString(metadata.get(key)));
        }
        return map;
    }

    // --- Decoding helpers ---

    private static void validateAllowedKeys(co.nstant.in.cbor.model.Map map) {
        for (DataItem key : map.getKeys()) {
            if (!(key instanceof UnsignedInteger uintKey)) {
                throw new CodecException("CBOR envelope map keys must be unsigned integers");
            }
            int k;
            try {
                k = uintKey.getValue().intValueExact();
            } catch (ArithmeticException e) {
                throw new CodecException("CBOR envelope map key out of range", e);
            }
            if (k < 1 || k > 10) {
                throw new CodecException("Unknown CBOR envelope map key: " + k);
            }
        }
    }

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
                if (!Arrays.equals(bytes, value.toByteArray())) {
                    throw new CodecException("Public input byte encoding must be minimal");
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
        int tag;
        try {
            tag = tagItem.getValue().intValueExact();
        } catch (ArithmeticException e) {
            throw new CodecException("VK ref tag out of range", e);
        }
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
                yield new VerificationKeyRef.ById(requireValidText(idItem.getString(), "vkRef.id"));
            }
            default -> throw new CodecException("Unknown VK ref tag: " + tag);
        };
    }

    private static String decodeDomainTag(DataItem item) {
        if (!(item instanceof UnicodeString textItem)) {
            throw new CodecException("CBOR map key 8 (domainTag) must be text");
        }
        String value = textItem.getString();
        if (value == null || value.isEmpty()) {
            throw new CodecException("CBOR map key 8 (domainTag) must not be empty when present");
        }
        requireBoundedText(value, "domainTag");
        return value;
    }

    private static Map<String, String> decodeMetadata(DataItem item) {
        if (!(item instanceof co.nstant.in.cbor.model.Map metaMap)) {
            throw new CodecException("CBOR map key 9 (metadata) must be a map");
        }
        if (metaMap.getKeys().isEmpty()) {
            throw new CodecException("CBOR map key 9 (metadata) must not be empty when present");
        }
        if (metaMap.getKeys().size() > MAX_METADATA_ENTRIES) {
            throw new CodecException("Too many metadata entries in CBOR envelope");
        }
        Map<String, String> result = new LinkedHashMap<>();
        for (DataItem keyItem : metaMap.getKeys()) {
            if (!(keyItem instanceof UnicodeString keyText)) {
                throw new CodecException("CBOR metadata keys must be text");
            }
            String key = requireValidText(keyText.getString(), "metadata key");
            DataItem valItem = metaMap.get(keyItem);
            if (!(valItem instanceof UnicodeString valText)) {
                throw new CodecException("CBOR metadata values must be text");
            }
            String value = valText.getString();
            if (value == null) {
                throw new CodecException("CBOR metadata value must not be null");
            }
            requireBoundedText(value, "metadata value");
            result.put(key, value);
        }
        return result;
    }

    private static String decodeProofFormat(DataItem item) {
        if (!(item instanceof UnicodeString textItem)) {
            throw new CodecException("CBOR map key 10 (proofFormat) must be text");
        }
        return requireValidText(textItem.getString(), "proofFormat");
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
        return requireValidText(textItem.getString(), "key " + key);
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

    private static String requireValidText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new CodecException("Invalid blank CBOR text value for " + label);
        }
        requireBoundedText(value, label);
        return value;
    }

    private static void requireBoundedText(String value, String label) {
        if (value.getBytes(StandardCharsets.UTF_8).length > MAX_TEXT_BYTES) {
            throw new CodecException("CBOR text value exceeds maximum length for " + label);
        }
    }
}
