package org.zeroj.codec;

import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.PublicInputs;
import org.zeroj.api.VerificationKeyRef;
import org.zeroj.api.ZkProofEnvelope;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Strict deterministic CBOR serialization and deserialization for {@link ZkProofEnvelope}
 * (ADR-0067, RFC 8949 §4.2 &amp; §10).
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
 * 9: metadata (map of text->text sorted in RFC 8949 §4.2.1 bytewise order, optional — omitted when empty)
 * 10: proofFormat (text, optional — omitted when absent)
 * </pre>
 *
 * <p>Local non-wire fields ({@code proofUri}, {@code proofHash}, {@code createdAt},
 * {@code producerId}) are not carried in the CBOR wire encoding. Encoding validates UTF-16 input
 * strictly (rejecting unpaired surrogates) and emits shortest-form definite-length CBOR directly in
 * RFC 8949 §4.2.1 unsigned bytewise key order. Decoding parses sequentially without recursion and
 * checks schema types, lengths, and collection counts against remaining input bytes before
 * allocating collections.</p>
 */
public final class CborEnvelopeCodec {

    private static final int MAX_CBOR_BYTES = 16 * 1024 * 1024;
    private static final int MAX_PROOF_BYTES = 8 * 1024 * 1024;
    private static final int MAX_PUBLIC_INPUTS = 1 << 20;
    private static final int MAX_PUBLIC_INPUT_BYTES = 128;
    private static final int SHA256_BYTES = 32;
    private static final int MAX_TEXT_BYTES = 256;
    private static final int MAX_METADATA_ENTRIES = 64;

    private static final int MAJOR_UINT = 0;
    private static final int MAJOR_BSTR = 2;
    private static final int MAJOR_TEXT = 3;
    private static final int MAJOR_ARRAY = 4;
    private static final int MAJOR_MAP = 5;

    private CborEnvelopeCodec() {}

    /**
     * Serialize a proof envelope to canonical deterministic CBOR bytes (RFC 8949 §4.2).
     */
    public static byte[] encode(ZkProofEnvelope envelope) {
        Objects.requireNonNull(envelope, "envelope must not be null");
        if (envelope.version() < 1 || envelope.version() > ZkProofEnvelope.currentVersion()) {
            throw new CodecException("Unsupported envelope version: " + envelope.version());
        }
        byte[] proofSystemBytes = encodeNonBlankUtf8(envelope.proofSystem().value(), "proofSystem");
        byte[] curveBytes = encodeNonBlankUtf8(envelope.curve().value(), "curve");
        byte[] circuitIdBytes = encodeNonBlankUtf8(envelope.circuitId().value(), "circuitId");
        byte[] proofBytes = envelope.proofBytes();
        if (proofBytes.length == 0 || proofBytes.length > MAX_PROOF_BYTES) {
            throw new CodecException("Invalid proofBytes length: " + proofBytes.length);
        }

        List<byte[]> publicInputBytes = encodePublicInputList(envelope.publicInputs());
        boolean hasDomainTag = !envelope.domainTag().isEmpty();
        byte[] domainTagBytes = hasDomainTag ? encodeStrictUtf8(envelope.domainTag(), "domainTag") : null;
        boolean hasMetadata = !envelope.metadata().isEmpty();
        List<MapEntryBytes> metadataEntries = hasMetadata ? encodeMetadataEntries(envelope.metadata()) : null;
        boolean hasProofFormat = envelope.proofFormat().isPresent();
        byte[] proofFormatBytes = hasProofFormat
                ? encodeNonBlankUtf8(envelope.proofFormat().orElseThrow(), "proofFormat")
                : null;

        int mapSize = 7 + (hasDomainTag ? 1 : 0) + (hasMetadata ? 1 : 0) + (hasProofFormat ? 1 : 0);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeHead(out, MAJOR_MAP, mapSize);

        // 1: version
        writeHead(out, MAJOR_UINT, 1);
        writeHead(out, MAJOR_UINT, envelope.version());

        // 2: proofSystem
        writeHead(out, MAJOR_UINT, 2);
        writeBytes(out, MAJOR_TEXT, proofSystemBytes);

        // 3: curve
        writeHead(out, MAJOR_UINT, 3);
        writeBytes(out, MAJOR_TEXT, curveBytes);

        // 4: circuitId
        writeHead(out, MAJOR_UINT, 4);
        writeBytes(out, MAJOR_TEXT, circuitIdBytes);

        // 5: proofBytes
        writeHead(out, MAJOR_UINT, 5);
        writeBytes(out, MAJOR_BSTR, proofBytes);

        // 6: publicInputs
        writeHead(out, MAJOR_UINT, 6);
        writeHead(out, MAJOR_ARRAY, publicInputBytes.size());
        for (byte[] input : publicInputBytes) {
            writeBytes(out, MAJOR_BSTR, input);
        }

        // 7: vkRef
        writeHead(out, MAJOR_UINT, 7);
        writeHead(out, MAJOR_ARRAY, 2);
        switch (envelope.vkRef()) {
            case VerificationKeyRef.ByHash h -> {
                byte[] hash = h.hash();
                if (hash.length != SHA256_BYTES) {
                    throw new CodecException("VK hash ref must be a SHA-256 hash");
                }
                writeHead(out, MAJOR_UINT, 1);
                writeBytes(out, MAJOR_BSTR, hash);
            }
            case VerificationKeyRef.ById id -> {
                byte[] idBytes = encodeNonBlankUtf8(id.id(), "vkRef.id");
                writeHead(out, MAJOR_UINT, 2);
                writeBytes(out, MAJOR_TEXT, idBytes);
            }
        }

        // 8: domainTag (optional)
        if (hasDomainTag) {
            writeHead(out, MAJOR_UINT, 8);
            writeBytes(out, MAJOR_TEXT, domainTagBytes);
        }

        // 9: metadata (optional, sorted by RFC 8949 §4.2.1 encoded key bytes)
        if (hasMetadata) {
            writeHead(out, MAJOR_UINT, 9);
            writeHead(out, MAJOR_MAP, metadataEntries.size());
            for (MapEntryBytes entry : metadataEntries) {
                writeBytes(out, MAJOR_TEXT, entry.keyUtf8());
                writeBytes(out, MAJOR_TEXT, entry.valueUtf8());
            }
        }

        // 10: proofFormat (optional)
        if (hasProofFormat) {
            writeHead(out, MAJOR_UINT, 10);
            writeBytes(out, MAJOR_TEXT, proofFormatBytes);
        }

        byte[] encoded = out.toByteArray();
        if (encoded.length > MAX_CBOR_BYTES) {
            throw new CodecException("Encoded CBOR envelope exceeds maximum size");
        }
        return encoded;
    }

    /**
     * Deserialize a strictly canonical CBOR proof envelope using bounded non-recursive parsing.
     */
    public static ZkProofEnvelope decode(byte[] cbor) {
        if (cbor == null || cbor.length == 0 || cbor.length > MAX_CBOR_BYTES) {
            throw new CodecException("Invalid CBOR envelope size");
        }
        try {
            Reader reader = new Reader(cbor);
            int mapSize = reader.readBoundedArg(MAJOR_MAP, 7, 10, "CBOR envelope map");

            int version = -1;
            String proofSystem = null;
            String curve = null;
            String circuitId = null;
            byte[] proofBytes = null;
            PublicInputs publicInputs = null;
            VerificationKeyRef vkRef = null;
            String domainTag = null;
            Map<String, String> metadata = null;
            String proofFormat = null;

            int prevKey = 0;
            int requiredMask = 0;
            for (int i = 0; i < mapSize; i++) {
                int key = reader.readBoundedArg(MAJOR_UINT, 1, 10, "CBOR envelope map key");
                if (key <= prevKey) {
                    throw new CodecException("CBOR envelope map keys must be strictly ascending without duplicates");
                }
                prevKey = key;
                switch (key) {
                    case 1 -> {
                        version = reader.readBoundedArg(
                                MAJOR_UINT, 1, ZkProofEnvelope.currentVersion(), "envelope version");
                        requiredMask |= 1 << 1;
                    }
                    case 2 -> {
                        proofSystem = requireNonBlank(reader.readStrictText(1, MAX_TEXT_BYTES, "proofSystem"), "proofSystem");
                        requiredMask |= 1 << 2;
                    }
                    case 3 -> {
                        curve = requireNonBlank(reader.readStrictText(1, MAX_TEXT_BYTES, "curve"), "curve");
                        requiredMask |= 1 << 3;
                    }
                    case 4 -> {
                        circuitId = requireNonBlank(reader.readStrictText(1, MAX_TEXT_BYTES, "circuitId"), "circuitId");
                        requiredMask |= 1 << 4;
                    }
                    case 5 -> {
                        proofBytes = reader.readByteString(1, MAX_PROOF_BYTES, "proofBytes");
                        requiredMask |= 1 << 5;
                    }
                    case 6 -> {
                        publicInputs = readPublicInputs(reader);
                        requiredMask |= 1 << 6;
                    }
                    case 7 -> {
                        vkRef = readVkRef(reader);
                        requiredMask |= 1 << 7;
                    }
                    case 8 -> domainTag = reader.readStrictText(1, MAX_TEXT_BYTES, "domainTag");
                    case 9 -> metadata = readMetadata(reader);
                    case 10 -> proofFormat = requireNonBlank(
                            reader.readStrictText(1, MAX_TEXT_BYTES, "proofFormat"), "proofFormat");
                    default -> throw new CodecException("Unknown CBOR envelope map key: " + key);
                }
            }

            if (requiredMask != 0b11111110) {
                throw new CodecException("Missing required CBOR envelope map key");
            }
            if (reader.remaining() != 0) {
                throw new CodecException("Trailing bytes after CBOR envelope: " + reader.remaining());
            }

            ZkProofEnvelope.Builder builder = ZkProofEnvelope.builder()
                    .version(version)
                    .proofSystem(ProofSystemId.fromValue(proofSystem))
                    .curve(CurveId.fromValue(curve))
                    .circuitId(new CircuitId(circuitId))
                    .proofBytes(proofBytes)
                    .publicInputs(publicInputs)
                    .vkRef(vkRef);
            if (domainTag != null) {
                builder.domainTag(domainTag);
            }
            if (metadata != null) {
                builder.metadata(metadata);
            }
            if (proofFormat != null) {
                builder.proofFormat(proofFormat);
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

    private static List<byte[]> encodePublicInputList(PublicInputs inputs) {
        if (inputs.size() > MAX_PUBLIC_INPUTS) {
            throw new CodecException("Too many public inputs in CBOR envelope");
        }
        List<byte[]> encoded = new ArrayList<>(inputs.size());
        for (BigInteger value : inputs.values()) {
            if (value == null || value.signum() < 0) {
                throw new CodecException("Public input must be non-negative");
            }
            byte[] bytes = value.toByteArray();
            if (bytes.length > MAX_PUBLIC_INPUT_BYTES) {
                throw new CodecException("Public input exceeds maximum byte length");
            }
            encoded.add(bytes);
        }
        return encoded;
    }

    private static List<MapEntryBytes> encodeMetadataEntries(Map<String, String> metadata) {
        if (metadata.size() > MAX_METADATA_ENTRIES) {
            throw new CodecException("Too many metadata entries in CBOR envelope");
        }
        List<MapEntryBytes> entries = new ArrayList<>(metadata.size());
        for (Map.Entry<String, String> entry : metadata.entrySet()) {
            byte[] keyUtf8 = encodeNonBlankUtf8(entry.getKey(), "metadata key");
            byte[] valueUtf8 = encodeStrictUtf8(entry.getValue(), "metadata value");
            entries.add(new MapEntryBytes(keyUtf8, valueUtf8));
        }
        // RFC 8949 §4.2.1 bytewise lexicographic order of encoded CBOR text keys:
        // shorter UTF-8 byte length has a smaller CBOR length head; equal lengths compare unsigned UTF-8 bytes.
        entries.sort((a, b) -> compareCanonicalTextBytes(a.keyUtf8(), b.keyUtf8()));
        return entries;
    }

    private static int compareCanonicalTextBytes(byte[] a, byte[] b) {
        int lenCmp = Integer.compare(a.length, b.length);
        return lenCmp != 0 ? lenCmp : Arrays.compareUnsigned(a, b);
    }

    private static byte[] encodeNonBlankUtf8(String text, String label) {
        if (text == null || text.isBlank()) {
            throw new CodecException("Invalid blank CBOR text value for " + label);
        }
        return encodeStrictUtf8(text, label);
    }

    private static byte[] encodeStrictUtf8(String text, String label) {
        if (text == null) {
            throw new CodecException("Null CBOR text value for " + label);
        }
        try {
            ByteBuffer bb = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(text));
            byte[] bytes = new byte[bb.remaining()];
            bb.get(bytes);
            if (bytes.length > MAX_TEXT_BYTES) {
                throw new CodecException("CBOR text value exceeds maximum length for " + label);
            }
            return bytes;
        } catch (CharacterCodingException e) {
            throw new CodecException("Malformed Unicode text for " + label, e);
        }
    }

    private static void writeHead(ByteArrayOutputStream out, int majorType, int arg) {
        if (arg < 0) {
            throw new CodecException("Negative CBOR argument: " + arg);
        }
        int prefix = majorType << 5;
        if (arg < 24) {
            out.write(prefix | arg);
        } else if (arg <= 0xFF) {
            out.write(prefix | 24);
            out.write(arg);
        } else if (arg <= 0xFFFF) {
            out.write(prefix | 25);
            out.write((arg >>> 8) & 0xFF);
            out.write(arg & 0xFF);
        } else {
            out.write(prefix | 26);
            out.write((arg >>> 24) & 0xFF);
            out.write((arg >>> 16) & 0xFF);
            out.write((arg >>> 8) & 0xFF);
            out.write(arg & 0xFF);
        }
    }

    private static void writeBytes(ByteArrayOutputStream out, int majorType, byte[] data) {
        writeHead(out, majorType, data.length);
        out.writeBytes(data);
    }

    // --- Bounded non-recursive decoding helpers ---

    private static PublicInputs readPublicInputs(Reader reader) {
        int count = reader.readBoundedArg(MAJOR_ARRAY, 0, MAX_PUBLIC_INPUTS, "publicInputs");
        // Each public input is a non-empty bstr (at least 2 bytes: 1-byte head + >=1 payload byte).
        if ((long) count * 2L > reader.remaining()) {
            throw new CodecException("Declared publicInputs count exceeds remaining CBOR bytes");
        }
        List<BigInteger> values = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            byte[] bytes = reader.readByteString(1, MAX_PUBLIC_INPUT_BYTES, "publicInputs[" + i + "]");
            BigInteger value = new BigInteger(bytes);
            if (value.signum() < 0) {
                throw new CodecException("Public input must be non-negative");
            }
            if (!Arrays.equals(bytes, value.toByteArray())) {
                throw new CodecException("Public input byte encoding must be minimal");
            }
            values.add(value);
        }
        return new PublicInputs(values);
    }

    private static VerificationKeyRef readVkRef(Reader reader) {
        reader.readBoundedArg(MAJOR_ARRAY, 2, 2, "vkRef");
        int tag = reader.readBoundedArg(MAJOR_UINT, 1, 2, "vkRef tag");
        return switch (tag) {
            case 1 -> new VerificationKeyRef.ByHash(
                    reader.readByteString(SHA256_BYTES, SHA256_BYTES, "vkRef hash"));
            case 2 -> new VerificationKeyRef.ById(
                    requireNonBlank(reader.readStrictText(1, MAX_TEXT_BYTES, "vkRef id"), "vkRef id"));
            default -> throw new CodecException("Unknown VK ref tag: " + tag);
        };
    }

    private static Map<String, String> readMetadata(Reader reader) {
        int count = reader.readBoundedArg(MAJOR_MAP, 1, MAX_METADATA_ENTRIES, "metadata");
        // Each metadata entry has a non-empty key (>= 2 bytes) and a text value (>= 1 byte).
        if ((long) count * 3L > reader.remaining()) {
            throw new CodecException("Declared metadata count exceeds remaining CBOR bytes");
        }
        Map<String, String> result = new LinkedHashMap<>(count);
        byte[] prevKeyBytes = null;
        for (int i = 0; i < count; i++) {
            byte[] keyBytes = reader.readTextBytes(1, MAX_TEXT_BYTES, "metadata key");
            if (prevKeyBytes != null && compareCanonicalTextBytes(keyBytes, prevKeyBytes) <= 0) {
                throw new CodecException("CBOR metadata keys must be strictly ascending in RFC 8949 canonical order");
            }
            prevKeyBytes = keyBytes;
            String key = requireNonBlank(decodeStrictUtf8(keyBytes, "metadata key"), "metadata key");
            String value = reader.readStrictText(0, MAX_TEXT_BYTES, "metadata value");
            result.put(key, value);
        }
        return result;
    }

    private static String requireNonBlank(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new CodecException("Invalid blank CBOR text value for " + label);
        }
        return value;
    }

    private static String decodeStrictUtf8(byte[] bytes, String label) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new CodecException("Invalid UTF-8 text in CBOR field: " + label, e);
        }
    }

    private record MapEntryBytes(byte[] keyUtf8, byte[] valueUtf8) {}

    /**
     * Minimal, non-recursive, shortest-form definite-length CBOR byte reader (RFC 8949 §4.2 &amp; §10).
     */
    private static final class Reader {
        private final byte[] data;
        private int pos;

        Reader(byte[] data) {
            this.data = data;
        }

        int remaining() {
            return data.length - pos;
        }

        int readBoundedArg(int expectedMajor, int min, int max, String label) {
            if (remaining() < 1) {
                throw new CodecException("Truncated CBOR while reading " + label);
            }
            int initial = data[pos++] & 0xFF;
            int major = initial >>> 5;
            int ai = initial & 0x1F;
            if (major != expectedMajor) {
                throw new CodecException("Unexpected CBOR major type " + major + " for " + label);
            }
            if (ai == 31) {
                throw new CodecException("Indefinite-length CBOR is forbidden for " + label);
            }
            long value;
            if (ai < 24) {
                value = ai;
            } else if (ai == 24) {
                if (remaining() < 1) {
                    throw new CodecException("Truncated 1-byte CBOR argument for " + label);
                }
                value = data[pos++] & 0xFFL;
                if (value < 24) {
                    throw new CodecException("Non-minimal CBOR integer encoding for " + label);
                }
            } else if (ai == 25) {
                if (remaining() < 2) {
                    throw new CodecException("Truncated 2-byte CBOR argument for " + label);
                }
                value = ((data[pos++] & 0xFFL) << 8) | (data[pos++] & 0xFFL);
                if (value < 256) {
                    throw new CodecException("Non-minimal CBOR integer encoding for " + label);
                }
            } else if (ai == 26) {
                if (remaining() < 4) {
                    throw new CodecException("Truncated 4-byte CBOR argument for " + label);
                }
                value = ((data[pos++] & 0xFFL) << 24)
                        | ((data[pos++] & 0xFFL) << 16)
                        | ((data[pos++] & 0xFFL) << 8)
                        | (data[pos++] & 0xFFL);
                if (value < 65536) {
                    throw new CodecException("Non-minimal CBOR integer encoding for " + label);
                }
            } else {
                throw new CodecException("Unsupported CBOR additional info " + ai + " for " + label);
            }
            if (value < min || value > max) {
                throw new CodecException("CBOR value " + value + " out of bounds [" + min + ", " + max + "] for " + label);
            }
            return (int) value;
        }

        byte[] readByteString(int minLen, int maxLen, String label) {
            int len = readBoundedArg(MAJOR_BSTR, minLen, maxLen, label);
            if (len > remaining()) {
                throw new CodecException("Declared byte string length exceeds remaining CBOR bytes for " + label);
            }
            byte[] slice = Arrays.copyOfRange(data, pos, pos + len);
            pos += len;
            return slice;
        }

        byte[] readTextBytes(int minLen, int maxLen, String label) {
            int len = readBoundedArg(MAJOR_TEXT, minLen, maxLen, label);
            if (len > remaining()) {
                throw new CodecException("Declared text string length exceeds remaining CBOR bytes for " + label);
            }
            byte[] slice = Arrays.copyOfRange(data, pos, pos + len);
            pos += len;
            return slice;
        }

        String readStrictText(int minLen, int maxLen, String label) {
            return decodeStrictUtf8(readTextBytes(minLen, maxLen, label), label);
        }
    }
}
