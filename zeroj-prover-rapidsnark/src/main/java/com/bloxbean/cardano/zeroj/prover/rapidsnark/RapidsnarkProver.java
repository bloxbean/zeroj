package com.bloxbean.cardano.zeroj.prover.rapidsnark;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.prover.sidecar.ProveRequest;
import com.bloxbean.cardano.zeroj.prover.sidecar.ProveResponse;
import com.bloxbean.cardano.zeroj.prover.sidecar.ProverException;
import com.bloxbean.cardano.zeroj.prover.sidecar.ProverService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Native in-process Groth16 prover for BN254 circuits using rapidsnark via FFM.
 *
 * <p>This is a drop-in replacement for {@link com.bloxbean.cardano.zeroj.prover.sidecar.SidecarProverClient}
 * that runs proving directly in the JVM process — no Docker container or sidecar needed.</p>
 *
 * <h3>Usage with raw zkey + witness:</h3>
 * <pre>{@code
 * try (var prover = new RapidsnarkProver()) {
 *     byte[] zkey = Files.readAllBytes(Path.of("circuit.zkey"));
 *     byte[] wtns = Files.readAllBytes(Path.of("witness.wtns"));
 *     ProveResponse response = prover.proveRaw(zkey, wtns);
 * }
 * }</pre>
 *
 * <h3>Usage with file paths:</h3>
 * <pre>{@code
 * try (var prover = new RapidsnarkProver()) {
 *     ProveResponse response = prover.proveRaw(
 *         Path.of("circuit.zkey"), Path.of("witness.wtns"));
 * }
 * }</pre>
 *
 * <p><b>Note:</b> rapidsnark only supports BN254 (alt_bn128). For BLS12-381
 * circuits (Cardano-native), use the gnark-based prover module.</p>
 */
public class RapidsnarkProver implements ProverService, AutoCloseable {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final RapidsnarkLibrary library;

    /**
     * Create a prover that auto-loads the native library from classpath.
     *
     * @throws ProverException if the native library cannot be loaded
     */
    public RapidsnarkProver() {
        try {
            this.library = new RapidsnarkLibrary();
        } catch (IOException e) {
            throw new ProverException(ProverException.ErrorCode.CONNECTION_FAILED,
                    "Failed to load rapidsnark native library: " + e.getMessage(), e);
        }
    }

    /**
     * Create a prover with an explicit path to the native library.
     *
     * @param libraryPath path to {@code librapidsnark.so} or {@code librapidsnark.dylib}
     */
    public RapidsnarkProver(Path libraryPath) {
        this.library = new RapidsnarkLibrary(libraryPath);
    }

    /**
     * Create a prover using a pre-loaded library instance.
     *
     * @param library pre-configured rapidsnark library bindings
     */
    public RapidsnarkProver(RapidsnarkLibrary library) {
        this.library = library;
    }

    // --- Low-level API: raw zkey + witness bytes ---

    /**
     * Generate a Groth16 proof from raw zkey and witness bytes.
     *
     * <p>This is the primary API for direct rapidsnark usage. The zkey file
     * contains the circuit's proving key and constraints. The witness (.wtns)
     * contains the computed witness values.</p>
     *
     * @param zkey circuit proving key bytes (.zkey file)
     * @param wtns witness data bytes (.wtns file)
     * @return prove response with proof JSON, public signals, protocol, and curve
     * @throws ProverException if proving fails
     */
    public ProveResponse proveRaw(byte[] zkey, byte[] wtns) {
        long startTime = System.nanoTime();

        RapidsnarkLibrary.ProveResult result = library.groth16Prove(zkey, wtns);

        long provingTimeMs = (System.nanoTime() - startTime) / 1_000_000;

        return toProveResponse(result, provingTimeMs);
    }

    /**
     * Generate a Groth16 proof from zkey and witness file paths.
     *
     * @param zkeyPath path to the .zkey file
     * @param wtnsPath path to the .wtns file
     * @return prove response with proof JSON, public signals, protocol, and curve
     * @throws ProverException if proving fails or files cannot be read
     */
    public ProveResponse proveRaw(Path zkeyPath, Path wtnsPath) {
        try {
            byte[] zkey = Files.readAllBytes(zkeyPath);
            byte[] wtns = Files.readAllBytes(wtnsPath);
            return proveRaw(zkey, wtns);
        } catch (IOException e) {
            throw new ProverException(ProverException.ErrorCode.CIRCUIT_NOT_FOUND,
                    "Failed to read circuit files: " + e.getMessage(), e);
        }
    }

    /**
     * Generate a Groth16 proof and wrap it as a {@link ZkProofEnvelope}.
     *
     * @param zkey      circuit proving key bytes (.zkey file)
     * @param wtns      witness data bytes (.wtns file)
     * @param vkJson    verification key JSON (for envelope construction)
     * @param circuitId circuit identifier for the envelope
     * @return a fully populated proof envelope ready for verification
     * @throws ProverException if proving fails
     */
    public ZkProofEnvelope proveRawAndWrap(byte[] zkey, byte[] wtns,
                                            String vkJson, String circuitId) {
        RapidsnarkLibrary.ProveResult result = library.groth16Prove(zkey, wtns);

        String enrichedProofJson = enrichProofJson(result.proofJson());

        return SnarkjsJsonCodec.toEnvelopeFromJson(
                enrichedProofJson, vkJson, result.publicSignalsJson(),
                new CircuitId(circuitId));
    }

    // --- ProverService interface (circuit-name based) ---

    /**
     * Not supported for the native prover — use {@link #proveRaw(byte[], byte[])} instead.
     *
     * <p>The {@code ProverService.prove(ProveRequest)} interface expects a circuit name and
     * input map, then handles witness computation internally. The native rapidsnark prover
     * operates on pre-computed {@code .zkey} + {@code .wtns} files.</p>
     *
     * <p>For a full circuit-name-based workflow, use the sidecar for witness computation
     * and this prover for proof generation, or provide pre-computed witness files.</p>
     *
     * @throws UnsupportedOperationException always
     */
    @Override
    public ProveResponse prove(ProveRequest request) {
        throw new UnsupportedOperationException(
                "Native rapidsnark prover requires raw .zkey + .wtns bytes. "
                        + "Use proveRaw(byte[] zkey, byte[] wtns) instead. "
                        + "For input-based proving, use the sidecar for witness computation.");
    }

    /**
     * Not supported — see {@link #prove(ProveRequest)}.
     *
     * @throws UnsupportedOperationException always
     */
    @Override
    public ZkProofEnvelope proveAndWrap(ProveRequest request, String circuitId) {
        throw new UnsupportedOperationException(
                "Native rapidsnark prover requires raw .zkey + .wtns bytes. "
                        + "Use proveRawAndWrap(byte[], byte[], String, String) instead.");
    }

    /**
     * Native library is always "healthy" if it loaded successfully.
     *
     * @return true
     */
    @Override
    public boolean isHealthy() {
        return true;
    }

    /**
     * Not applicable for the native prover.
     *
     * @return empty list
     */
    @Override
    public List<String> listCircuits() {
        return List.of();
    }

    @Override
    public void close() {
        library.close();
    }

    // --- Internal helpers ---

    /**
     * Enrich rapidsnark proof JSON with protocol and curve fields.
     *
     * <p>rapidsnark outputs only {@code pi_a}, {@code pi_b}, {@code pi_c} — it omits
     * the {@code protocol} and {@code curve} metadata that snarkjs includes.
     * Since rapidsnark is BN254 Groth16 only, we inject these known values.</p>
     */
    private String enrichProofJson(String rawProofJson) {
        try {
            JsonNode proofNode = MAPPER.readTree(rawProofJson);
            if (!proofNode.has("protocol") || !proofNode.has("curve")) {
                var objectNode = MAPPER.createObjectNode();
                proofNode.fields().forEachRemaining(e -> objectNode.set(e.getKey(), e.getValue()));
                if (!objectNode.has("protocol")) objectNode.put("protocol", "groth16");
                if (!objectNode.has("curve")) objectNode.put("curve", "bn128");
                return MAPPER.writeValueAsString(objectNode);
            }
            return rawProofJson;
        } catch (Exception e) {
            return rawProofJson;
        }
    }

    private ProveResponse toProveResponse(RapidsnarkLibrary.ProveResult result, long provingTimeMs) {
        try {
            // Parse public signals from JSON array: ["33", "3"]
            List<BigInteger> publicSignals = new ArrayList<>();
            JsonNode publicNode = MAPPER.readTree(result.publicSignalsJson());
            if (publicNode.isArray()) {
                for (JsonNode element : publicNode) {
                    publicSignals.add(new BigInteger(element.asText()));
                }
            }

            String enrichedProofJson = enrichProofJson(result.proofJson());

            return new ProveResponse(enrichedProofJson, publicSignals, "groth16", "bn128", provingTimeMs);
        } catch (Exception e) {
            throw new ProverException(ProverException.ErrorCode.INVALID_RESPONSE,
                    "Failed to parse rapidsnark output: " + e.getMessage(), e);
        }
    }
}
