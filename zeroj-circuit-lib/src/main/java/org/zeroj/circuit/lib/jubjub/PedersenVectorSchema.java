package org.zeroj.circuit.lib.jubjub;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * What each index of a {@code pedersen-jubjub-vector-v1} commitment means
 * ({@code docs/specs/pedersen-jubjub-vector-v1.md} §4, ADR-0051 D5).
 *
 * <p>A vector commitment binds neither its length nor its schema, so the schema is bound
 * elsewhere: its {@link #digest() digest} is a constrained public input of every proof that
 * touches the commitment, checked by the verifier against a trusted registry, and received
 * commitments carry their schema only through authenticated issuance provenance (spec §5–§6).
 *
 * <p>Two schemas are equal iff their canonical encodings are equal.
 */
public final class PedersenVectorSchema {

    /** The tag that opens every canonical encoding. */
    static final byte[] TAG = "pedersen-jubjub-vector-v1".getBytes(StandardCharsets.US_ASCII);

    private static final Pattern ID = Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");
    private static final Pattern LABEL = Pattern.compile("[a-z0-9._-]{1,32}");

    /** One index of the schema: its meaning and the width its value is range-bounded to. */
    public record Entry(String label, int width) {
        public Entry {
            Objects.requireNonNull(label, "label");
            if (!LABEL.matcher(label).matches()) {
                throw new IllegalArgumentException(
                        "label must be 1-32 characters from [a-z0-9._-], got '" + label + "'");
            }
            if (width < 1 || width > 252) {
                throw new IllegalArgumentException("width must be in [1, 252], got " + width);
            }
        }
    }

    private final String id;
    private final int version;
    private final List<Entry> entries;
    private final byte[] encoding;
    private final BigInteger digest;

    private PedersenVectorSchema(String id, int version, List<Entry> entries) {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(entries, "entries");
        if (!ID.matcher(id).matches()) {
            throw new IllegalArgumentException(
                    "id must be 1-64 characters from [a-z0-9._-], starting with [a-z0-9]; got '" + id + "'");
        }
        if (version < 0 || version > 0xFFFF) {
            throw new IllegalArgumentException("version must be an unsigned 16-bit value, got " + version);
        }
        if (entries.isEmpty() || entries.size() > PedersenVectorBases.MAX_DIMENSION) {
            throw new IllegalArgumentException("dimension must be in [1, "
                    + PedersenVectorBases.MAX_DIMENSION + "], got " + entries.size());
        }
        Set<String> labels = new HashSet<>();
        for (Entry entry : entries) {
            Objects.requireNonNull(entry, "entry");
            if (!labels.add(entry.label())) {
                throw new IllegalArgumentException("duplicate label '" + entry.label() + "'");
            }
        }
        this.id = id;
        this.version = version;
        this.entries = List.copyOf(entries);
        this.encoding = encode(id, version, this.entries);
        this.digest = digestOf(encoding);
    }

    /** Creates a schema; validates every field of spec §4. */
    public static PedersenVectorSchema of(String id, int version, List<Entry> entries) {
        return new PedersenVectorSchema(id, version, entries);
    }

    /**
     * Decodes a canonical encoding (spec §4.1). Rejects anything that is not exactly that layout:
     * wrong tag, out-of-range or disallowed field, duplicate label, truncation or trailing bytes.
     */
    public static PedersenVectorSchema decode(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        var in = new Reader(encoded);
        byte[] tag = in.take(TAG.length);
        if (!Arrays.equals(tag, TAG) || in.u8() != 0) {
            throw new IllegalArgumentException("not a pedersen-jubjub-vector-v1 schema encoding");
        }
        String id = in.ascii(in.u8());
        int version = (in.u8() << 8) | in.u8();
        int n = in.u8();
        List<Entry> entries = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            int width = in.u8();
            entries.add(new Entry(in.ascii(in.u8()), width));
        }
        if (in.remaining() != 0) {
            throw new IllegalArgumentException("trailing bytes after schema encoding");
        }
        return new PedersenVectorSchema(id, version, entries);
    }

    public String id() {
        return id;
    }

    public int version() {
        return version;
    }

    public List<Entry> entries() {
        return entries;
    }

    public int dimension() {
        return entries.size();
    }

    /** The declared width of index {@code i}. */
    public int width(int i) {
        return entries.get(i).width();
    }

    /** Canonical encoding (spec §4.1). */
    public byte[] encode() {
        return encoding.clone();
    }

    /**
     * {@code σ = OS2IP(SHA-256(encode())) mod p} (spec §4.2): an element of the BLS12-381 scalar
     * field, used as a public input and compared for equality.
     */
    public BigInteger digest() {
        return digest;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof PedersenVectorSchema other && Arrays.equals(encoding, other.encoding);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoding);
    }

    @Override
    public String toString() {
        return "PedersenVectorSchema[" + id + " v" + version + ", " + entries + "]";
    }

    private static byte[] encode(String id, int version, List<Entry> entries) {
        var out = new ByteArrayOutputStream();
        out.writeBytes(TAG);
        out.write(0);
        byte[] idBytes = id.getBytes(StandardCharsets.US_ASCII);
        out.write(idBytes.length);
        out.writeBytes(idBytes);
        out.write(version >>> 8);
        out.write(version & 0xFF);
        out.write(entries.size());
        for (Entry entry : entries) {
            byte[] label = entry.label().getBytes(StandardCharsets.US_ASCII);
            out.write(entry.width());
            out.write(label.length);
            out.writeBytes(label);
        }
        return out.toByteArray();
    }

    private static BigInteger digestOf(byte[] encoding) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(encoding);
            return new BigInteger(1, hash).mod(JubjubCurve.BASE_FIELD_PRIME);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every Java platform", e);
        }
    }

    private static final class Reader {
        private final byte[] bytes;
        private int position;

        Reader(byte[] bytes) {
            this.bytes = bytes;
        }

        int u8() {
            if (position >= bytes.length) {
                throw new IllegalArgumentException("truncated schema encoding");
            }
            return bytes[position++] & 0xFF;
        }

        byte[] take(int length) {
            if (length > bytes.length - position) {
                throw new IllegalArgumentException("truncated schema encoding");
            }
            byte[] out = Arrays.copyOfRange(bytes, position, position + length);
            position += length;
            return out;
        }

        String ascii(int length) {
            byte[] raw = take(length);
            for (byte b : raw) {
                if (b < 0x20 || b > 0x7E) {
                    throw new IllegalArgumentException("non-printable byte in schema encoding");
                }
            }
            return new String(raw, StandardCharsets.US_ASCII);
        }

        int remaining() {
            return bytes.length - position;
        }
    }
}
