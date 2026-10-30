package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.zeroj.bindings.common.Adapter;
import org.zeroj.bindings.common.BindingException;
import org.zeroj.bindings.common.BindingSession;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.bindings.groth16.Groth16ProverAdapter;
import org.zeroj.circuit.ConstraintGraph;

/** One compilation attempt per worker. ADR-0064; no source evaluation or witness export. */
public final class CircuitAdapter implements Adapter {
    private boolean consumed;
    private StringBuilder upload;
    private int expectedLength;
    private String expectedGraphHash;
    private String expectedFingerprint;

    private static final class State implements AutoCloseable {
        private CompiledGraph circuit;
        private Groth16ProverAdapter prover;
        private final BindingSession session;
        private final Set<String> keys = new HashSet<>();
        State(CompiledGraph circuit, BindingSession session) {
            this.circuit = circuit;
            this.prover = new Groth16ProverAdapter(Map.of(circuit.id(), circuit));
            this.session = session;
        }
        @Override public void close() {
            for (String key : keys) session.release(key);
            keys.clear();
            circuit = null;
            prover = null;
        }
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
            case "loadKey" -> {
                Boundary.fields(args, "circuit", "fingerprint", "zkey", "expectedSha256", "verificationKey");
                var state = state(args, session);
                ObjectNode forwarded = args.deepCopy();
                forwarded.put("circuit", state.circuit.id());
                JsonNode loaded = state.prover.invoke("loadKey", forwarded, session);
                state.keys.add(Boundary.text(loaded, "handle"));
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
        String handle = session.retain(new State(compiled, session));
        var result = Boundary.object().put("handle", handle).put("compiler", GraphCodec.COMPILER)
                .put("graphSha256", expectedGraphHash).put("fingerprint", compiled.fingerprint())
                .put("name", compiled.id()).put("wires", compiled.numWires())
                .put("constraints", compiled.constraints().size()).put("publicInputs", compiled.numPublic())
                .put("compileMs", compiled.compileMs).put("maxKeyBytes", Boundary.MAX_BYTES)
                .put("withinProverDimensions", compiled.numWires() <= 4096 && compiled.numPublic() <= 64
                        && compiled.constraints().size() + compiled.numPublic() + 1 <= 4096);
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
