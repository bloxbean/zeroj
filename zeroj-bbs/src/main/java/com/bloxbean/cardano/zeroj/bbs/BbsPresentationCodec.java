package com.bloxbean.cardano.zeroj.bbs;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Deterministic CBOR wrapper for draft-compatible BBS proof presentations.
 *
 * <p>Map keys are fixed:</p>
 * <pre>
 * 1: version (uint)
 * 2: ciphersuite id (text)
 * 3: draft BBS proof bytes (bstr)
 * 4: header (bstr)
 * 5: presentation header (bstr)
 * 6: revealed messages ([[index, message], ...])
 * </pre>
 */
public final class BbsPresentationCodec {
    private static final int VERSION = 1;
    private static final int MAX_ENVELOPE_BYTES = 1024 * 1024;
    private static final int MAX_HEADER_BYTES = 65_535;
    private static final int MAX_PRESENTATION_HEADER_BYTES = 65_535;
    private static final int MAX_REVEALED_MESSAGE_BYTES = 65_535;
    private static final int MAX_MESSAGES = 1024;
    private static final int MAX_CIPHERSUITE_ID_CHARS = 128;

    private BbsPresentationCodec() {}

    public static byte[] encode(BbsPresentation presentation) {
        Objects.requireNonNull(presentation, "presentation required");
        try {
            BbsProof proof = presentation.proof();
            validateProofLength(proof.bytes(), proof.ciphersuite());
            requireMaxLength(presentation.header(), MAX_HEADER_BYTES, "BBS header");
            requireMaxLength(presentation.presentationHeader(), MAX_PRESENTATION_HEADER_BYTES, "BBS presentation header");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            new CborEncoder(baos).encode(new CborBuilder()
                    .addMap()
                    .put(new UnsignedInteger(1), new UnsignedInteger(VERSION))
                    .put(new UnsignedInteger(2), new UnicodeString(proof.ciphersuite().ciphersuiteId()))
                    .put(new UnsignedInteger(3), new ByteString(proof.bytes()))
                    .put(new UnsignedInteger(4), new ByteString(presentation.header()))
                    .put(new UnsignedInteger(5), new ByteString(presentation.presentationHeader()))
                    .put(new UnsignedInteger(6), encodeRevealedMessages(presentation.revealedMessages()))
                    .end()
                    .build());
            return baos.toByteArray();
        } catch (CborException e) {
            throw new BbsException("Failed to encode BBS presentation CBOR", e);
        }
    }

    /**
     * Decode a canonical deterministic CBOR BBS presentation.
     *
     * <p>The decoder rejects byte-distinct non-canonical encodings of the same
     * logical presentation by decoding and re-encoding with the canonical encoder.
     * Callers that hash, sign, or content-address presentation envelopes can rely
     * on this method accepting only ZeroJ's canonical envelope form.</p>
     */
    public static BbsPresentation decode(byte[] cbor) {
        return decodeStrict(cbor);
    }

    public static BbsPresentation decodeStrict(byte[] cbor) {
        return decodeInternal(cbor, true);
    }

    private static BbsPresentation decodeInternal(byte[] cbor, boolean strict) {
        try {
            validateEnvelopeBytes(cbor);
            CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(cbor));
            decoder.setRejectDuplicateKeys(true);
            decoder.setMaxPreallocationSize(MAX_ENVELOPE_BYTES);
            List<DataItem> items = decoder.decode();
            if (items.size() != 1 || !(items.getFirst() instanceof co.nstant.in.cbor.model.Map map)) {
                throw new BbsException("BBS presentation CBOR must be a map");
            }
            if (map.getKeys().size() != 6) {
                throw new BbsException("BBS presentation CBOR map must contain exactly 6 keys");
            }
            int version = intAt(map, 1);
            if (version != VERSION) {
                throw new BbsException("Unsupported BBS presentation CBOR version: " + version);
            }
            BbsCiphersuite ciphersuite = BbsCiphersuite.fromCiphersuiteId(textAt(map, 2));
            byte[] proofBytes = bytesAt(map, 3, "BBS proof", maxProofBytes(ciphersuite));
            BbsProof proof = new BbsProof(proofBytes, ciphersuite);
            byte[] header = bytesAt(map, 4, "BBS header", MAX_HEADER_BYTES);
            byte[] presentationHeader = bytesAt(map, 5, "BBS presentation header", MAX_PRESENTATION_HEADER_BYTES);
            List<BbsRevealedMessage> revealedMessages = decodeRevealedMessages(arrayAt(map, 6));
            validateProofAndRevealedMessageCount(proof.bytes(), ciphersuite, revealedMessages.size());
            BbsPresentation presentation = new BbsPresentation(proof, header, presentationHeader, revealedMessages);
            if (strict && !Arrays.equals(cbor, encode(presentation))) {
                throw new BbsException("BBS presentation CBOR must be canonical");
            }
            return presentation;
        } catch (BbsException e) {
            throw e;
        } catch (Exception e) {
            throw new BbsException("Failed to decode BBS presentation CBOR", e);
        }
    }

    private static Array encodeRevealedMessages(List<BbsRevealedMessage> messages) {
        Objects.requireNonNull(messages, "revealed messages required");
        if (messages.size() > MAX_MESSAGES) {
            throw new BbsException("BBS revealed message count exceeds " + MAX_MESSAGES);
        }
        Array outer = new Array();
        int previous = -1;
        for (BbsRevealedMessage message : messages) {
            if (message.index() <= previous) {
                throw new BbsException("BBS revealed message indexes must be strictly ascending");
            }
            previous = message.index();
            requireMaxLength(message.message(), MAX_REVEALED_MESSAGE_BYTES, "BBS revealed message");
            Array item = new Array();
            item.add(new UnsignedInteger(message.index()));
            item.add(new ByteString(message.message()));
            outer.add(item);
        }
        return outer;
    }

    private static List<BbsRevealedMessage> decodeRevealedMessages(Array array) {
        if (array.getDataItems().size() > MAX_MESSAGES) {
            throw new BbsException("BBS revealed message count exceeds " + MAX_MESSAGES);
        }
        List<BbsRevealedMessage> out = new ArrayList<>();
        int previous = -1;
        for (DataItem item : array.getDataItems()) {
            if (!(item instanceof Array pair) || pair.getDataItems().size() != 2) {
                throw new BbsException("BBS revealed message must be [index, message]");
            }
            int index = intFromItem(pair.getDataItems().get(0), "BBS revealed message index");
            if (index <= previous) {
                throw new BbsException("BBS revealed message indexes must be strictly ascending");
            }
            previous = index;
            byte[] message = bytesFromItem(
                    pair.getDataItems().get(1),
                    "BBS revealed message",
                    MAX_REVEALED_MESSAGE_BYTES);
            out.add(new BbsRevealedMessage(index, message));
        }
        return List.copyOf(out);
    }

    private static int intAt(co.nstant.in.cbor.model.Map map, int key) {
        return intFromItem(itemAt(map, key), "BBS presentation CBOR map key " + key);
    }

    private static String textAt(co.nstant.in.cbor.model.Map map, int key) {
        DataItem item = itemAt(map, key);
        if (!(item instanceof UnicodeString text)) {
            throw new BbsException("BBS presentation CBOR map key " + key + " must be text");
        }
        String value = text.getString();
        if (value.length() > MAX_CIPHERSUITE_ID_CHARS) {
            throw new BbsException("BBS ciphersuite id is too long");
        }
        return value;
    }

    private static byte[] bytesAt(co.nstant.in.cbor.model.Map map, int key, String label, int maxLength) {
        return bytesFromItem(itemAt(map, key), label, maxLength);
    }

    private static Array arrayAt(co.nstant.in.cbor.model.Map map, int key) {
        DataItem item = itemAt(map, key);
        if (!(item instanceof Array array)) {
            throw new BbsException("BBS presentation CBOR map key " + key + " must be an array");
        }
        return array;
    }

    private static DataItem itemAt(co.nstant.in.cbor.model.Map map, int key) {
        DataItem item = map.get(new UnsignedInteger(key));
        if (item == null) {
            throw new BbsException("Missing BBS presentation CBOR map key: " + key);
        }
        return item;
    }

    private static int intFromItem(DataItem item, String label) {
        if (!(item instanceof UnsignedInteger number)) {
            throw new BbsException(label + " must be an unsigned integer");
        }
        BigInteger value = number.getValue();
        if (value.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0) {
            throw new BbsException(label + " is too large");
        }
        return value.intValueExact();
    }

    private static byte[] bytesFromItem(DataItem item, String label, int maxLength) {
        if (!(item instanceof ByteString bytes)) {
            throw new BbsException(label + " must be a byte string");
        }
        byte[] value = bytes.getBytes();
        requireMaxLength(value, maxLength, label);
        return value.clone();
    }

    private static void validateEnvelopeBytes(byte[] cbor) {
        Objects.requireNonNull(cbor, "CBOR bytes required");
        requireMaxLength(cbor, MAX_ENVELOPE_BYTES, "BBS presentation CBOR");
    }

    private static void requireMaxLength(byte[] bytes, int maxLength, String label) {
        Objects.requireNonNull(bytes, label + " required");
        if (bytes.length > maxLength) {
            throw new BbsException(label + " exceeds " + maxLength + " bytes");
        }
    }

    private static void validateProofLength(byte[] proofBytes, BbsCiphersuite ciphersuite) {
        requireMaxLength(proofBytes, maxProofBytes(ciphersuite), "BBS proof");
        hiddenMessageCount(proofBytes, ciphersuite);
    }

    private static void validateProofAndRevealedMessageCount(
            byte[] proofBytes,
            BbsCiphersuite ciphersuite,
            int revealedCount) {
        int hiddenCount = hiddenMessageCount(proofBytes, ciphersuite);
        if (hiddenCount + revealedCount > MAX_MESSAGES) {
            throw new BbsException("BBS presentation message count exceeds " + MAX_MESSAGES);
        }
    }

    private static int hiddenMessageCount(byte[] proofBytes, BbsCiphersuite ciphersuite) {
        int floor = 3 * ciphersuite.g1Bytes() + 4 * ciphersuite.scalarBytes();
        if (proofBytes.length < floor) {
            throw new BbsException("BBS proof is too short: " + proofBytes.length);
        }
        int scalarBytes = proofBytes.length - 3 * ciphersuite.g1Bytes();
        if (scalarBytes % ciphersuite.scalarBytes() != 0) {
            throw new BbsException("BBS proof scalar section is not aligned to 32-byte scalars");
        }
        return scalarBytes / ciphersuite.scalarBytes() - 4;
    }

    private static int maxProofBytes(BbsCiphersuite ciphersuite) {
        return 3 * ciphersuite.g1Bytes() + (4 + MAX_MESSAGES) * ciphersuite.scalarBytes();
    }
}
