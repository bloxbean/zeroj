package com.bloxbean.cardano.zeroj.prover.gnark;

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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Native in-process Groth16 prover using gnark via FFM.
 *
 * <p>Supports both BLS12-381 (Cardano-native) and BN254 curves.
 * Unlike rapidsnark, gnark requires Go compilation before use.
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
public class GnarkProver implements ProverService, AutoCloseable {

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

    // --- ProverService interface ---

    /**
     * Not supported — use {@link #proveRaw(String, Path, Path, String)} instead.
     *
     * @throws UnsupportedOperationException always
     */
    @Override
    public ProveResponse prove(ProveRequest request) {
        throw new UnsupportedOperationException(
                "Native gnark prover requires R1CS + proving key + witness. "
                        + "Use proveRaw(curve, r1csPath, pkPath, witnessJson) instead.");
    }

    /**
     * Not supported — see {@link #prove(ProveRequest)}.
     *
     * @throws UnsupportedOperationException always
     */
    @Override
    public ZkProofEnvelope proveAndWrap(ProveRequest request, String circuitId) {
        throw new UnsupportedOperationException(
                "Native gnark prover requires R1CS + proving key + witness.");
    }

    @Override
    public boolean isHealthy() {
        return true;
    }

    @Override
    public List<String> listCircuits() {
        return List.of();
    }

    @Override
    public void close() {
        library.close();
    }

    // --- Internal helpers ---

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

            return new ProveResponse(result.resultJson(), publicSignals, protocol, normalizedCurve, provingTimeMs);
        } catch (Exception e) {
            throw new ProverException(ProverException.ErrorCode.INVALID_RESPONSE,
                    "Failed to parse gnark output: " + e.getMessage(), e);
        }
    }
}
