package com.bloxbean.cardano.zeroj.prover.gnark;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.prover.spi.ProveResponse;
import com.bloxbean.cardano.zeroj.prover.spi.ProverException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Native in-process Groth16 prover using gnark via FFM.
 *
 * <p>Supports both BLS12-381 (Cardano-native) and BN254 curves.
 * gnark requires Go compilation before use.
 * Build the native library with:</p>
 * <pre>{@code
 * make -C zeroj-prover-gnark/gnark-wrapper build
 * }</pre>
 *
 * <h3>Usage:</h3>
 * <pre>{@code
 * try (var prover = new GnarkProver()) {
 *     ProveResponse response = prover.proveRaw(
 *         "bls12381",
 *         Path.of("circuit.r1cs"),
 *         Path.of("proving_key.bin"),
 *         Path.of("witness.bin"));
 *     System.out.println("gnark version: " + prover.gnarkVersion());
 * }
 * }</pre>
 *
 * <p><b>Note:</b> The gnark shared library includes the Go runtime (~30-50MB).
 * It is shipped as a separate Maven artifact, not bundled in the main JAR.</p>
 */
public class GnarkProver implements AutoCloseable {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final GnarkLibrary library;

    /**
     * Create a prover that auto-loads the native library from classpath.
     *
     * @throws ProverException if the native library cannot be loaded
     */
    public GnarkProver() {
        try {
            this.library = new GnarkLibrary();
        } catch (IOException e) {
            throw new ProverException(ProverException.ErrorCode.CONNECTION_FAILED,
                    "Failed to load gnark native library. "
                            + "Build it first: make -C gnark-wrapper build. "
                            + "Error: " + e.getMessage(), e);
        }
    }

    /**
     * Create a prover with an explicit path to the native library.
     *
     * @param libraryPath path to {@code libzeroj_gnark.so} or {@code libzeroj_gnark.dylib}
     */
    public GnarkProver(Path libraryPath) {
        this.library = new GnarkLibrary(libraryPath);
    }

    /**
     * Create a prover using a pre-loaded library instance.
     */
    public GnarkProver(GnarkLibrary library) {
        this.library = library;
    }

    // --- Low-level API ---

    /**
     * Generate a Groth16 proof using gnark.
     *
     * @param curve       curve identifier ("bls12381" or "bn254")
     * @param r1csPath    path to the compiled R1CS constraint system
     * @param pkPath      path to the proving key
     * @param witnessPath path to the witness file (gnark binary format)
     * @return prove response with proof JSON, public signals, protocol, and curve
     * @throws ProverException if proving fails
     */
    public ProveResponse proveRaw(String curve, Path r1csPath, Path pkPath, Path witnessPath) {
        long startTime = System.nanoTime();

        GnarkLibrary.ProveResult result = library.groth16Prove(
                curve,
                r1csPath.toAbsolutePath().toString(),
                pkPath.toAbsolutePath().toString(),
                witnessPath.toAbsolutePath().toString());

        long provingTimeMs = (System.nanoTime() - startTime) / 1_000_000;

        return toProveResponse(result, curve, provingTimeMs, "groth16");
    }

    /**
     * Run Groth16 trusted setup using gnark.
     *
     * @param curve    curve identifier
     * @param r1csPath path to the R1CS file
     * @return setup result with proving key path and verification key JSON
     */
    public GnarkLibrary.SetupResult setup(String curve, Path r1csPath) {
        return library.groth16Setup(curve, r1csPath.toAbsolutePath().toString());
    }

    // --- PlonK API ---

    /**
     * Run PlonK setup using gnark (generates SRS internally — for testing/dev only).
     * <p>
     * In production, use an MPC-generated SRS. The SRS is universal — one SRS
     * works for any circuit whose size does not exceed the SRS threshold.
     *
     * @param curve    curve identifier ("bls12381" or "bn254")
     * @param r1csPath path to the SparseR1CS constraint system file
     * @return setup result with proving key path and verification key JSON
     */
    public GnarkLibrary.SetupResult plonkSetup(String curve, Path r1csPath) {
        return library.plonkSetup(curve, r1csPath.toAbsolutePath().toString());
    }

    /**
     * Generate a PlonK proof using gnark.
     *
     * @param curve       curve identifier ("bls12381" or "bn254")
     * @param r1csPath    path to the SparseR1CS file
     * @param pkPath      path to the proving key
     * @param witnessPath path to the witness file (gnark binary format)
     * @return prove response with proof JSON, public signals, protocol, and curve
     * @throws ProverException if proving fails
     */
    public ProveResponse plonkProveRaw(String curve, Path r1csPath, Path pkPath, Path witnessPath) {
        long startTime = System.nanoTime();

        GnarkLibrary.ProveResult result = library.plonkProve(
                curve,
                r1csPath.toAbsolutePath().toString(),
                pkPath.toAbsolutePath().toString(),
                witnessPath.toAbsolutePath().toString());

        long provingTimeMs = (System.nanoTime() - startTime) / 1_000_000;

        return toProveResponse(result, curve, provingTimeMs, "plonk");
    }

    /**
     * Verify a PlonK proof using gnark.
     *
     * @param curve       curve identifier
     * @param vkPath      path to the verification key file
     * @param proofBase64 base64-encoded proof bytes
     * @param witnessPath path to the public witness file
     * @return true if the proof is valid
     */
    public boolean plonkVerify(String curve, Path vkPath, String proofBase64, Path witnessPath) {
        return library.plonkVerify(curve,
                vkPath.toAbsolutePath().toString(),
                proofBase64,
                witnessPath.toAbsolutePath().toString());
    }

    /**
     * Get the gnark version used by the native library.
     *
     * @return version string (e.g., "v0.14.0")
     */
    public String gnarkVersion() {
        return library.gnarkVersion();
    }

    // --- Full prove API (setup + prove in one call, no external tools) ---

    /**
     * Groth16 full prove: Java DSL R1CS constraints + witness values → proof.
     * Passes constraints as JSON to gnark, which compiles them using its frontend API,
     * then runs setup + proving in a single in-process FFM call.
     * No snarkjs, no Node.js, no CLI needed.
     *
     * @param r1cs     compiled R1CS constraint system from the Java DSL
     * @param witness  full witness array (wire 0 = "one", then public inputs, then private)
     * @param curve    elliptic curve
     * @return prove response with proof JSON, public signals, and VK JSON
     */
    public FullProveResponse groth16FullProve(R1CSConstraintSystem r1cs,
                                               BigInteger[] witness, CurveId curve) {
        String curveName = curve.value();
        String constraintsJson = serializeConstraintsToJson(r1cs);
        String valuesJson = buildWitnessValuesJson(witness, r1cs.numPublicInputs());

        long startTime = System.nanoTime();
        GnarkLibrary.FullProveResult result = library.groth16FullProve(
                curveName, constraintsJson, valuesJson);
        long provingTimeMs = (System.nanoTime() - startTime) / 1_000_000;

        return toFullProveResponse(result, curveName, provingTimeMs, "groth16");
    }

    /**
     * PlonK full prove: Java DSL R1CS constraints + witness values → proof.
     * gnark compiles the R1CS to its own SparseR1CS (PlonK) format internally.
     *
     * @param r1cs     compiled R1CS constraint system from the Java DSL
     * @param witness  full witness array
     * @param curve    elliptic curve
     * @return prove response with proof JSON, public signals, and VK JSON
     */
    public FullProveResponse plonkFullProve(R1CSConstraintSystem r1cs,
                                             BigInteger[] witness, CurveId curve) {
        String curveName = curve.value();
        String constraintsJson = serializeConstraintsToJson(r1cs);
        String valuesJson = buildWitnessValuesJson(witness, r1cs.numPublicInputs());

        long startTime = System.nanoTime();
        GnarkLibrary.FullProveResult result = library.plonkFullProve(
                curveName, constraintsJson, valuesJson);
        long provingTimeMs = (System.nanoTime() - startTime) / 1_000_000;

        return toFullProveResponse(result, curveName, provingTimeMs, "plonk");
    }

    /**
     * Response from a full prove operation, including verification key.
     */
    public record FullProveResponse(
            ProveResponse proveResponse,
            String vkJson
    ) {}

    @Override
    public void close() {
        library.close();
    }

    // --- Internal helpers ---

    /**
     * Serialize R1CS constraints to JSON for the Go FFM functions.
     * Format: {"numPublic": N, "numWires": M, "constraints": [{"a": {"wireIdx": "coeff", ...}, "b": ..., "c": ...}]}
     */
    static String serializeConstraintsToJson(R1CSConstraintSystem r1cs) {
        var sb = new StringBuilder();
        sb.append("{\"numPublic\":").append(r1cs.numPublicInputs());
        sb.append(",\"numWires\":").append(r1cs.numWires());
        sb.append(",\"constraints\":[");
        var constraints = r1cs.constraints();
        for (int i = 0; i < constraints.size(); i++) {
            if (i > 0) sb.append(',');
            var con = constraints.get(i);
            sb.append("{\"a\":").append(lcToJson(con.a()));
            sb.append(",\"b\":").append(lcToJson(con.b()));
            sb.append(",\"c\":").append(lcToJson(con.c()));
            sb.append('}');
        }
        sb.append("]}");
        return sb.toString();
    }

    private static String lcToJson(Map<Integer, BigInteger> lc) {
        var sb = new StringBuilder("{");
        boolean first = true;
        for (var entry : lc.entrySet()) {
            if (entry.getValue().signum() == 0) continue;
            if (!first) sb.append(',');
            sb.append('"').append(entry.getKey()).append("\":\"")
                    .append(entry.getValue().toString()).append('"');
            first = false;
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Build the JSON witness values payload for the Go FFM functions.
     * Format: {"numPublic": N, "values": ["v0", "v1", ...]}
     * <p>
     * The witness array follows iden3 convention: wire 0 = constant "1",
     * then numPublic public input wires, then private wires.
     * We skip wire 0 (the "one" wire) since gnark handles it internally.
     */
    static String buildWitnessValuesJson(BigInteger[] witness, int numPublic) {
        var sb = new StringBuilder();
        sb.append("{\"numPublic\":").append(numPublic).append(",\"values\":[");
        // Skip wire 0 ("one" constant) — gnark adds it internally
        for (int i = 1; i < witness.length; i++) {
            if (i > 1) sb.append(',');
            sb.append('"').append(witness[i].toString()).append('"');
        }
        sb.append("]}");
        return sb.toString();
    }

    private FullProveResponse toFullProveResponse(GnarkLibrary.FullProveResult result, String curve,
                                                   long provingTimeMs, String protocol) {
        try {
            List<BigInteger> publicSignals = new ArrayList<>();
            JsonNode publicNode = MAPPER.readTree(result.publicJson());
            if (publicNode.isArray()) {
                for (JsonNode element : publicNode) {
                    publicSignals.add(new BigInteger(element.asText()));
                }
            }

            String normalizedCurve = switch (curve.toLowerCase()) {
                case "bls12381", "bls12-381" -> "bls12381";
                case "bn254", "bn128", "alt_bn128" -> "bn128";
                default -> curve;
            };

            var proveResponse = new ProveResponse(extractProofJson(result.resultJson(), normalizedCurve, protocol), publicSignals,
                    protocol, normalizedCurve, provingTimeMs);
            return new FullProveResponse(proveResponse, result.vkJson());
        } catch (Exception e) {
            throw new ProverException(ProverException.ErrorCode.INVALID_RESPONSE,
                    "Failed to parse gnark full prove output: " + e.getMessage(), e);
        }
    }

    private ProveResponse toProveResponse(GnarkLibrary.ProveResult result, String curve, long provingTimeMs, String protocol) {
        try {
            // Parse public signals from JSON
            List<BigInteger> publicSignals = new ArrayList<>();
            JsonNode publicNode = MAPPER.readTree(result.publicJson());
            if (publicNode.isArray()) {
                for (JsonNode element : publicNode) {
                    publicSignals.add(new BigInteger(element.asText()));
                }
            }

            // Normalize curve name
            String normalizedCurve = switch (curve.toLowerCase()) {
                case "bls12381", "bls12-381" -> "bls12381";
                case "bn254", "bn128", "alt_bn128" -> "bn128";
                default -> curve;
            };

            return new ProveResponse(extractProofJson(result.resultJson(), normalizedCurve, protocol), publicSignals,
                    protocol, normalizedCurve, provingTimeMs);
        } catch (Exception e) {
            throw new ProverException(ProverException.ErrorCode.INVALID_RESPONSE,
                    "Failed to parse gnark output: " + e.getMessage(), e);
        }
    }

    private static String extractProofJson(String resultJson, String curve, String protocol) throws Exception {
        JsonNode root = MAPPER.readTree(resultJson);
        String proofJson;
        if (root.has("proof")) {
            JsonNode proof = root.get("proof");
            proofJson = proof.isTextual() ? proof.asText() : proof.toString();
        } else if (root.has("binary")) {
            proofJson = resultJson;
        } else {
            throw new IllegalArgumentException("gnark result JSON missing proof field");
        }

        JsonNode proofRoot = MAPPER.readTree(proofJson);
        if (proofRoot.isObject()) {
            var proofObject = (com.fasterxml.jackson.databind.node.ObjectNode) proofRoot;
            if (!proofObject.has("curve")) {
                proofObject.put("curve", curve);
            }
            if (!proofObject.has("protocol")) {
                proofObject.put("protocol", protocol);
            }
            return MAPPER.writeValueAsString(proofObject);
        }
        return proofJson;
    }
}
