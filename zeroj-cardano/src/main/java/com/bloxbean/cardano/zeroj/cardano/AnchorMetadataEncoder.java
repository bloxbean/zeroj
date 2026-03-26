package com.bloxbean.cardano.zeroj.cardano;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.*;

import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Encodes a {@link ProofAnchor} as CIP-10 compatible Cardano transaction metadata.
 *
 * <p>The metadata is a CBOR map under a ZeroJ-specific label.
 * Default label: 7270 (ASCII "zj" = 0x7A 0x6A → chosen as a recognizable label).</p>
 *
 * <p>CBOR map keys are integers for compactness:</p>
 * <pre>
 * 0: pattern (uint: 0=PROOF_HASH_ONLY, 1=STATE_ROOT_AND_PROOF_HASH, 2=FULL_VERIFICATION_REF, 3=NULLIFIER_COMMITMENT)
 * 1: proofHash (bstr, 32 bytes)
 * 2: stateRoot (bstr, optional)
 * 3: circuitId (tstr, optional)
 * 4: vkHash (bstr, optional)
 * 5: nullifier (bstr, optional)
 * 6: appId (tstr, optional)
 * </pre>
 */
public final class AnchorMetadataEncoder {

    /** Default CIP-10 metadata label for ZeroJ anchors. */
    public static final long DEFAULT_LABEL = 7270;

    private AnchorMetadataEncoder() {}

    /**
     * Encode a proof anchor as a CBOR map (the metadata value under the label).
     *
     * @return CBOR-encoded bytes of the metadata map
     */
    public static byte[] encode(ProofAnchor anchor) {
        try {
            var map = new co.nstant.in.cbor.model.Map();

            // 0: pattern
            map.put(new UnsignedInteger(0), new UnsignedInteger(anchor.pattern().ordinal()));

            // 1: proofHash (always present)
            map.put(new UnsignedInteger(1), new ByteString(anchor.proofHash()));

            // 2: stateRoot (optional)
            anchor.stateRoot().ifPresent(root ->
                    map.put(new UnsignedInteger(2), new ByteString(root)));

            // 3: circuitId (optional)
            anchor.circuitId().ifPresent(id ->
                    map.put(new UnsignedInteger(3), new UnicodeString(id)));

            // 4: vkHash (optional)
            anchor.vkHash().ifPresent(hash ->
                    map.put(new UnsignedInteger(4), new ByteString(hash)));

            // 5: nullifier (optional)
            anchor.nullifier().ifPresent(n ->
                    map.put(new UnsignedInteger(5), new ByteString(n)));

            // 6: appId (optional)
            anchor.appId().ifPresent(id ->
                    map.put(new UnsignedInteger(6), new UnicodeString(id)));

            var baos = new ByteArrayOutputStream();
            new CborEncoder(baos).encode(new CborBuilder().add(map).build());
            return baos.toByteArray();
        } catch (CborException e) {
            throw new RuntimeException("Failed to encode anchor metadata", e);
        }
    }

    /**
     * Decode a proof anchor from CBOR metadata bytes.
     */
    public static ProofAnchor decode(byte[] cbor) {
        try {
            var items = co.nstant.in.cbor.CborDecoder.decode(cbor);
            if (items.isEmpty() || !(items.getFirst() instanceof co.nstant.in.cbor.model.Map map)) {
                throw new IllegalArgumentException("Expected CBOR map");
            }

            int patternOrd = ((co.nstant.in.cbor.model.Number) map.get(new UnsignedInteger(0))).getValue().intValue();
            var pattern = AnchorPattern.values()[patternOrd];
            byte[] proofHash = ((ByteString) map.get(new UnsignedInteger(1))).getBytes();

            var builder = ProofAnchor.builder()
                    .pattern(pattern)
                    .proofHash(proofHash);

            var stateRootItem = map.get(new UnsignedInteger(2));
            if (stateRootItem instanceof ByteString bs) builder.stateRoot(bs.getBytes());

            var circuitItem = map.get(new UnsignedInteger(3));
            if (circuitItem instanceof UnicodeString us) builder.circuitId(us.getString());

            var vkHashItem = map.get(new UnsignedInteger(4));
            if (vkHashItem instanceof ByteString bs) builder.vkHash(bs.getBytes());

            var nullifierItem = map.get(new UnsignedInteger(5));
            if (nullifierItem instanceof ByteString bs) builder.nullifier(bs.getBytes());

            var appIdItem = map.get(new UnsignedInteger(6));
            if (appIdItem instanceof UnicodeString us) builder.appId(us.getString());

            return builder.build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to decode anchor metadata", e);
        }
    }

    /**
     * Encode a proof anchor as a full CIP-10 metadata structure (label → map).
     *
     * @param anchor the anchor to encode
     * @param label  the CIP-10 metadata label
     * @return CBOR bytes of {label: anchor_map}
     */
    public static byte[] encodeWithLabel(ProofAnchor anchor, long label) {
        try {
            var innerMap = new co.nstant.in.cbor.model.Map();
            innerMap.put(new UnsignedInteger(0), new UnsignedInteger(anchor.pattern().ordinal()));
            innerMap.put(new UnsignedInteger(1), new ByteString(anchor.proofHash()));
            anchor.stateRoot().ifPresent(root ->
                    innerMap.put(new UnsignedInteger(2), new ByteString(root)));
            anchor.circuitId().ifPresent(id ->
                    innerMap.put(new UnsignedInteger(3), new UnicodeString(id)));
            anchor.vkHash().ifPresent(hash ->
                    innerMap.put(new UnsignedInteger(4), new ByteString(hash)));
            anchor.nullifier().ifPresent(n ->
                    innerMap.put(new UnsignedInteger(5), new ByteString(n)));
            anchor.appId().ifPresent(id ->
                    innerMap.put(new UnsignedInteger(6), new UnicodeString(id)));

            var outerMap = new co.nstant.in.cbor.model.Map();
            outerMap.put(new UnsignedInteger(label), innerMap);

            var baos = new ByteArrayOutputStream();
            new CborEncoder(baos).encode(new CborBuilder().add(outerMap).build());
            return baos.toByteArray();
        } catch (CborException e) {
            throw new RuntimeException("Failed to encode labeled anchor metadata", e);
        }
    }
}
