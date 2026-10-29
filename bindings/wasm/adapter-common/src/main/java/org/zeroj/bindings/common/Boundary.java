package org.zeroj.bindings.common;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;

/** Resource-bounded transport parsing. Cryptographic codecs stay in the existing Java APIs. */
public final class Boundary {
    public static final int MAX_REQUEST_CHARS = 1_048_576;
    public static final int MAX_BYTES = 262_144;
    public static final ObjectMapper JSON = new ObjectMapper();
    static {
        JSON.getFactory().setStreamReadConstraints(StreamReadConstraints.builder()
                .maxNestingDepth(24).maxStringLength(MAX_BYTES * 2).maxNumberLength(160).build());
        JSON.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        JSON.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    }
    private Boundary() {}
    public static JsonNode parse(String value) {
        if (value == null || value.length() > MAX_REQUEST_CHARS) throw invalid();
        try {
            JsonNode n = JSON.readTree(value);
            if (n == null || !n.isObject()) throw invalid();
            return n;
        } catch (java.io.IOException e) { throw invalid(); }
    }
    public static void fields(JsonNode n, String... names) {
        if (!n.isObject() || n.size() != names.length) throw invalid();
        Set<String> expected = Set.of(names);
        n.fieldNames().forEachRemaining(k -> { if (!expected.contains(k)) throw invalid(); });
    }
    public static String text(JsonNode n, String key) {
        JsonNode v = n.get(key);
        if (v == null || !v.isTextual()) throw invalid();
        return v.textValue();
    }
    public static int integer(JsonNode n, String key, int min, int max) {
        JsonNode v = n.get(key);
        if (v == null || !v.isIntegralNumber() || !v.canConvertToInt()) throw invalid();
        int x = v.intValue();
        if (x < min || x > max) throw invalid();
        return x;
    }
    public static BigInteger decimal(String s, BigInteger exclusiveMax) {
        if (s.length() > 160 || !s.matches("0|[1-9][0-9]*")) throw invalid();
        BigInteger v = new BigInteger(s);
        if (v.compareTo(exclusiveMax) >= 0) throw invalid();
        return v;
    }
    public static BigInteger scalar(JsonNode n, String key, BigInteger modulus) {
        return decimal(text(n,key), modulus);
    }
    public static byte[] bytes(JsonNode n, String key, int min, int max) {
        String s = text(n, key);
        if (s.length() < min * 2 || s.length() > max * 2 || !s.matches("(?:[0-9a-f]{2})*")) throw invalid();
        return HexFormat.of().parseHex(s);
    }
    public static String hex(byte[] b) { return HexFormat.of().formatHex(b); }
    public static ObjectNode object() { return JSON.createObjectNode(); }
    public static BindingException invalid() { return new BindingException("INVALID_REQUEST"); }
}
