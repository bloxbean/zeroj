package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.zeroj.bindings.common.Adapter;
import org.zeroj.bindings.common.BindingException;
import org.zeroj.bindings.common.BindingSession;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.bindings.groth16.Groth16ProverAdapter;
import org.zeroj.circuit.ConstraintGraph;

/** One compilation attempt per worker. ADR-0064; no source evaluation or witness export. */
public final class CircuitAdapter implements Adapter {
    public static final int MAX_KEY_BYTES = 2 * 1024 * 1024;
    public static final int KEY_CHUNK_BYTES = 64 * 1024;
    private final CircuitKeyProfile profile;
    public CircuitAdapter() { this(CircuitKeyProfile.STANDARD); }
    /** Trusted Java/image configuration, not an RPC option. */
    public CircuitAdapter(CircuitKeyProfile profile) { this.profile = Objects.requireNonNull(profile); }
    private boolean consumed;
    private StringBuilder upload;
    private int expectedLength;
    private String expectedGraphHash;
    private String expectedFingerprint;

    private static final class State implements AutoCloseable {
        private CompiledGraph circuit;
        private Groth16ProverAdapter prover;
        private final BindingSession session;
        private final CircuitKeyProfile profile;
        private final Set<String> keys = new HashSet<>();
        private KeyUpload upload;
        private String uploadId;
        private int peakStagingBytes;
        private double lastImportMs;
        private int lastKeyBytes;
        private int lastDomainSize;
        private boolean imported;
        void available() {
            if (imported) throw new BindingException("KEY_LIMIT");
            if (upload != null && upload.bytes != null) throw new BindingException("UPLOAD_ACTIVE");
        }
        void requireDimensions() {
            if (!profile.admits(circuit.numWires(), circuit.numPublic(), circuit.constraints().size()))
                throw new BindingException("CIRCUIT_LIMIT");
        }
        void clearUpload() {
            if (uploadId != null) session.release(uploadId);
            upload = null;
            uploadId = null;
        }
        void imported(JsonNode loaded) {
            keys.add(Boundary.text(loaded, "handle"));
            imported = true;
            lastImportMs = loaded.path("importMs").asDouble();
            lastKeyBytes = loaded.path("keyBytes").asInt();
            lastDomainSize = loaded.path("domainSize").asInt();
        }
        ObjectNode resources() {
            return Boundary.object().put("profile", profile.id())
                    .put("reservedBytes", upload == null || upload.bytes == null ? 0 : upload.bytes.length)
                    .put("receivedBytes", upload == null || upload.bytes == null ? 0 : upload.received)
                    .put("peakStagingBytes", peakStagingBytes).put("importedKeys", imported ? 1 : 0)
                    .put("maxKeyBytes", profile.limits().maxBytes()).put("chunkBytes", KEY_CHUNK_BYTES)
                    .put("maxWires", profile.limits().maxWires()).put("maxDomainSize", profile.limits().maxDomainSize())
                    .put("maxCoefficients", profile.limits().maxCoefficients())
                    .put("lastImportMs", lastImportMs).put("lastKeyBytes", lastKeyBytes)
                    .put("lastDomainSize", lastDomainSize);
        }
        State(CompiledGraph circuit, BindingSession session, CircuitKeyProfile profile) {
            this.profile = profile;
            this.circuit = circuit;
            this.prover = new Groth16ProverAdapter(Map.of(circuit.id(), circuit));
            this.session = session;
        }
        @Override public void close() {
            clearUpload();
            for (String key : keys) session.release(key);
            keys.clear();
            circuit = null;
            prover = null;
        }
    }

    /** One exact-sized public-key buffer; no accumulated hex or second binary copy. */
    private static final class KeyUpload implements AutoCloseable {
        private byte[] bytes;
        private int received;
        private final ObjectNode metadata;
        KeyUpload(int length, ObjectNode metadata) {
            this.bytes = new byte[length];
            this.metadata = metadata;
        }
        @Override public void close() { bytes = null; }
    }

    @Override public JsonNode invoke(String operation, JsonNode args, BindingSession session) {
        return switch (operation) {
            case "compileRecipe" -> {
                consume();
                Boundary.fields(args, "recipe", "expectedGraphSha256", "fingerprint");
                identity(args);
                String recipe = Boundary.text(args, "recipe");
                long start = System.nanoTime();
                var graph = SymbolicRecipe.expand(recipe);
                double expandMs = elapsed(start);
                start = System.nanoTime();
                String encoded = GraphCodec.encode(graph);
                GraphCodec.decode(encoded);
                double validationMs = elapsed(start);
                yield finish(graph, encoded, session).put("recipeSha256", GraphCodec.hash(recipe))
                        .put("expandMs", expandMs).put("graphValidationMs", validationMs);
            }
            case "beginGraph" -> {
                if (consumed || upload != null) throw Boundary.invalid();
                Boundary.fields(args, "length", "expectedGraphSha256", "fingerprint");
                expectedLength = Boundary.integer(args, "length", 1, GraphCodec.MAX_CHARS);
                identity(args);
                upload = new StringBuilder(Math.min(expectedLength, 200_000));
                yield Boundary.object().put("ready", true);
            }
            case "appendGraph" -> {
                Boundary.fields(args, "offset", "text");
                if (upload == null || consumed) throw Boundary.invalid();
                int offset = Boundary.integer(args, "offset", 0, expectedLength);
                String text = Boundary.text(args, "text");
                if (offset != upload.length() || text.isEmpty() || text.length() > 200_000
                        || upload.length() + text.length() > expectedLength) throw Boundary.invalid();
                upload.append(text);
                yield Boundary.object().put("received", upload.length());
            }
            case "compileGraph" -> {
                if (consumed || upload == null) throw Boundary.invalid();
                consumed = true;
                String encoded = upload.toString();
                upload = null;
                Boundary.fields(args);
                if (encoded.length() != expectedLength || !GraphCodec.hash(encoded).equals(expectedGraphHash))
                    throw new BindingException("CIRCUIT_MISMATCH");
                long start = System.nanoTime();
                var graph = GraphCodec.decode(encoded);
                double decodeMs = elapsed(start);
                yield finish(graph, encoded, session).put("graphValidationMs", decodeMs);
            }
            case "checkWitness" -> {
                Boundary.fields(args, "circuit", "input");
                session.requireSecrets();
                var state = state(args, session);
                long start = System.nanoTime();
                BigInteger[] witness = state.circuit.witness(args.get("input"));
                double witnessMs = elapsed(start);
                try {
                    start = System.nanoTime();
                    state.circuit.check(witness);
                    yield Boundary.object().put("valid", true).put("witnessMs", witnessMs)
                            .put("constraintCheckMs", elapsed(start));
                } finally { Arrays.fill(witness, BigInteger.ZERO); }
            }
            case "keyResources" -> {
                Boundary.fields(args, "circuit");
                yield state(args, session).resources();
            }
            case "beginKey" -> {
                Boundary.fields(args, "circuit", "fingerprint", "length", "expectedSha256", "verificationKey");
                var state = state(args, session);
                state.available();
                state.requireDimensions();
                int length = Boundary.integer(args, "length", 1, state.profile.limits().maxBytes());
                ObjectNode metadata = args.deepCopy();
                metadata.remove("length");
                metadata.put("circuit", state.circuit.id());
                state.prover.validateKeyMetadata(metadata);
                var upload = new KeyUpload(length, metadata);
                // If handle admission fails, no live state retains the buffer.
                String id = session.retain(upload);
                state.upload = upload;
                state.uploadId = id;
                state.peakStagingBytes = Math.max(state.peakStagingBytes, length);
                yield Boundary.object().put("upload", id).put("chunkBytes", KEY_CHUNK_BYTES);
            }
            case "appendKey", "finishKey", "abortKey" -> {
                var state = state(args, session);
                String id = Boundary.text(args, "upload");
                var upload = session.get(id, KeyUpload.class);
                if (!id.equals(state.uploadId) || upload != state.upload || upload.bytes == null)
                    throw new BindingException("INVALID_HANDLE");
                boolean keep = false;
                try {
                    if (operation.equals("appendKey")) {
                        Boundary.fields(args, "circuit", "upload", "offset", "chunk");
                        int offset = Boundary.integer(args, "offset", 0, upload.bytes.length);
                        byte[] chunk = Boundary.bytes(args, "chunk", 1, KEY_CHUNK_BYTES);
                        if (offset != upload.received || chunk.length > upload.bytes.length - offset)
                            throw Boundary.invalid();
                        System.arraycopy(chunk, 0, upload.bytes, offset, chunk.length);
                        upload.received += chunk.length;
                        keep = true;
                        yield Boundary.object().put("received", upload.received);
                    }
                    Boundary.fields(args, "circuit", "upload");
                    if (operation.equals("abortKey")) yield Boundary.object().put("aborted", true);
                    if (upload.received != upload.bytes.length) throw new BindingException("INCOMPLETE_KEY");
                    JsonNode loaded = state.prover.loadKeyBytes(upload.metadata, upload.bytes, session, state.profile.limits());
                    state.imported(loaded);
                    yield loaded;
                } finally { if (!keep) state.clearUpload(); }
            }
            case "loadKey" -> {
                // Compatibility for small direct requests; the standalone cap is unchanged.
                Boundary.fields(args, "circuit", "fingerprint", "zkey", "expectedSha256", "verificationKey");
                var state = state(args, session);
                state.available();
                state.requireDimensions();
                ObjectNode forwarded = args.deepCopy();
                forwarded.put("circuit", state.circuit.id());
                JsonNode loaded = state.prover.invoke("loadKey", forwarded, session);
                state.imported(loaded);
                yield loaded;
            }
            case "prove" -> {
                Boundary.fields(args, "circuit", "key", "input");
                var state = state(args, session);
                if (!state.keys.contains(Boundary.text(args, "key"))) throw new BindingException("INVALID_HANDLE");
                ObjectNode forwarded = args.deepCopy();
                forwarded.remove("circuit");
                yield state.prover.invoke("prove", forwarded, session);
            }
            default -> throw new BindingException("UNSUPPORTED_OPERATION");
        };
    }

    private void consume() {
        if (consumed || upload != null) throw Boundary.invalid();
        consumed = true;
    }

    private void identity(JsonNode args) {
        expectedGraphHash = Boundary.text(args, "expectedGraphSha256");
        expectedFingerprint = Boundary.text(args, "fingerprint");
        if (!expectedGraphHash.matches("[0-9a-f]{64}") || expectedFingerprint.length() > 160)
            throw Boundary.invalid();
    }

    private ObjectNode finish(ConstraintGraph graph, String encoded, BindingSession session) {
        if (!GraphCodec.hash(encoded).equals(expectedGraphHash)) throw new BindingException("CIRCUIT_MISMATCH");
        var compiled = new CompiledGraph(graph);
        if (!compiled.fingerprint().equals(expectedFingerprint)) throw new BindingException("CIRCUIT_MISMATCH");
        String handle = session.retain(new State(compiled, session, profile));
        var result = Boundary.object().put("handle", handle).put("compiler", GraphCodec.COMPILER)
                .put("graphSha256", expectedGraphHash).put("fingerprint", compiled.fingerprint())
                .put("name", compiled.id()).put("wires", compiled.numWires())
                .put("constraints", compiled.constraints().size()).put("publicInputs", compiled.numPublic())
                .put("compileMs", compiled.compileMs).put("maxKeyBytes", profile.limits().maxBytes())
                .put("keyChunkBytes", KEY_CHUNK_BYTES).put("keyProfile", profile.id())
                .put("maxWires", profile.limits().maxWires()).put("maxDomainSize", profile.limits().maxDomainSize())
                .put("maxCoefficients", profile.limits().maxCoefficients())
                .put("withinProverDimensions", profile.admits(compiled.numWires(), compiled.numPublic(), compiled.constraints().size()));
        var pub = result.putArray("publicNames");
        graph.publicInputs().forEach(v -> pub.add(v.name()));
        var sec = result.putArray("secretNames");
        graph.secretInputs().forEach(v -> sec.add(v.name()));
        return result;
    }

    private static State state(JsonNode args, BindingSession session) {
        var state = session.get(Boundary.text(args, "circuit"), State.class);
        if (state.circuit == null) throw new BindingException("INVALID_HANDLE");
        return state;
    }

    private static double elapsed(long start) { return (System.nanoTime() - start) / 1e6; }
}
