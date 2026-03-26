package com.bloxbean.cardano.zeroj.prover.sidecar;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * HTTP client for the ZeroJ prover sidecar service.
 *
 * <p>Communicates with a snarkjs-based proving server over HTTP.
 * Supports configurable timeouts and retry with exponential backoff.</p>
 *
 * <p>Usage:</p>
 * <pre>{@code
 * var client = new SidecarProverClient(ProverConfig.localhost());
 * var response = client.prove(ProveRequest.of("multiplier", Map.of("a", "3", "b", "11")));
 * var envelope = client.proveAndWrap(request, "multiplier");
 * }</pre>
 */
public class SidecarProverClient implements ProverService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final ProverConfig config;
    private final HttpClient httpClient;

    public SidecarProverClient(ProverConfig config) {
        this.config = Objects.requireNonNull(config);
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(config.connectTimeout())
                .build();
    }

    @Override
    public ProveResponse prove(ProveRequest request) {
        var body = Map.of(
                "circuit", request.circuitName(),
                "input", request.input()
        );

        String responseBody = postWithRetry("/prove", body);

        try {
            var root = MAPPER.readTree(responseBody);

            // Parse proof JSON (it's a nested object)
            String proofJson;
            if (root.has("proof") && root.get("proof").isObject()) {
                proofJson = MAPPER.writeValueAsString(root.get("proof"));
            } else if (root.has("proof") && root.get("proof").isTextual()) {
                proofJson = root.get("proof").asText();
            } else {
                throw new ProverException(ProverException.ErrorCode.INVALID_RESPONSE,
                        "Response missing 'proof' field");
            }

            // Parse public signals
            List<BigInteger> publicSignals = new ArrayList<>();
            var signalsNode = root.get("publicSignals");
            if (signalsNode == null) signalsNode = root.get("public");
            if (signalsNode != null && signalsNode.isArray()) {
                for (var element : signalsNode) {
                    publicSignals.add(new BigInteger(element.asText()));
                }
            }

            String protocol = root.has("protocol") ? root.get("protocol").asText() : "groth16";
            String curve = root.has("curve") ? root.get("curve").asText() : "bn128";
            long provingTimeMs = root.has("provingTimeMs") ? root.get("provingTimeMs").asLong() : 0;

            return new ProveResponse(proofJson, publicSignals, protocol, curve, provingTimeMs);
        } catch (ProverException e) {
            throw e;
        } catch (Exception e) {
            throw new ProverException(ProverException.ErrorCode.INVALID_RESPONSE,
                    "Failed to parse prove response: " + e.getMessage(), e);
        }
    }

    @Override
    public ZkProofEnvelope proveAndWrap(ProveRequest request, String circuitId) {
        var response = prove(request);

        // We need the VK JSON to build the envelope — fetch it from sidecar
        String vkJson = fetchVerificationKey(request.circuitName());

        // Build public signals JSON
        var publicSignalsJson = new StringBuilder("[");
        for (int i = 0; i < response.publicSignals().size(); i++) {
            if (i > 0) publicSignalsJson.append(",");
            publicSignalsJson.append("\"").append(response.publicSignals().get(i)).append("\"");
        }
        publicSignalsJson.append("]");

        return SnarkjsJsonCodec.toEnvelopeFromJson(
                response.proofJson(), vkJson, publicSignalsJson.toString(),
                new CircuitId(circuitId));
    }

    @Override
    public boolean isHealthy() {
        try {
            var request = HttpRequest.newBuilder()
                    .uri(URI.create(config.baseUrl() + "/health"))
                    .timeout(config.connectTimeout())
                    .GET()
                    .build();
            var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public List<String> listCircuits() {
        try {
            var request = HttpRequest.newBuilder()
                    .uri(URI.create(config.baseUrl() + "/circuits"))
                    .timeout(config.connectTimeout())
                    .GET()
                    .build();
            var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                        "Failed to list circuits: HTTP " + response.statusCode());
            }
            return MAPPER.readValue(response.body(), new TypeReference<List<String>>() {});
        } catch (ProverException e) {
            throw e;
        } catch (Exception e) {
            throw new ProverException(ProverException.ErrorCode.CONNECTION_FAILED,
                    "Failed to list circuits: " + e.getMessage(), e);
        }
    }

    /**
     * Fetch the verification key for a circuit from the sidecar.
     */
    public String fetchVerificationKey(String circuitName) {
        try {
            var request = HttpRequest.newBuilder()
                    .uri(URI.create(config.baseUrl() + "/circuits/" + circuitName + "/vk"))
                    .timeout(config.connectTimeout())
                    .GET()
                    .build();
            var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new ProverException(ProverException.ErrorCode.CIRCUIT_NOT_FOUND,
                        "VK not found for circuit: " + circuitName);
            }
            return response.body();
        } catch (ProverException e) {
            throw e;
        } catch (Exception e) {
            throw new ProverException(ProverException.ErrorCode.CONNECTION_FAILED,
                    "Failed to fetch VK: " + e.getMessage(), e);
        }
    }

    /**
     * POST with retry and exponential backoff.
     */
    private String postWithRetry(String path, Object body) {
        int attempt = 0;
        long delayMs = config.retryDelay().toMillis();
        Exception lastException = null;

        while (attempt <= config.maxRetries()) {
            try {
                String jsonBody = MAPPER.writeValueAsString(body);
                var request = HttpRequest.newBuilder()
                        .uri(URI.create(config.baseUrl() + path))
                        .timeout(config.proveTimeout())
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                        .build();

                var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 200) {
                    return response.body();
                }

                // Parse error response
                if (response.statusCode() == 404) {
                    throw new ProverException(ProverException.ErrorCode.CIRCUIT_NOT_FOUND,
                            "Circuit not found: " + response.body());
                }
                if (response.statusCode() == 400) {
                    throw new ProverException(ProverException.ErrorCode.INVALID_INPUT,
                            "Invalid input: " + response.body());
                }

                // Server error — retryable
                lastException = new ProverException(ProverException.ErrorCode.PROVING_FAILED,
                        "HTTP " + response.statusCode() + ": " + response.body());
            } catch (ProverException e) {
                if (e.errorCode() == ProverException.ErrorCode.CIRCUIT_NOT_FOUND
                        || e.errorCode() == ProverException.ErrorCode.INVALID_INPUT) {
                    throw e; // Non-retryable
                }
                lastException = e;
            } catch (HttpTimeoutException e) {
                lastException = new ProverException(ProverException.ErrorCode.TIMEOUT,
                        "Prove request timed out after " + config.proveTimeout(), e);
            } catch (ConnectException e) {
                lastException = new ProverException(ProverException.ErrorCode.CONNECTION_FAILED,
                        "Cannot connect to sidecar at " + config.baseUrl(), e);
            } catch (Exception e) {
                lastException = new ProverException(ProverException.ErrorCode.CONNECTION_FAILED,
                        "Request failed: " + e.getMessage(), e);
            }

            attempt++;
            if (attempt <= config.maxRetries()) {
                try { Thread.sleep(delayMs); } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new ProverException(ProverException.ErrorCode.RETRIES_EXHAUSTED,
                            "Interrupted during retry", ie);
                }
                delayMs *= 2; // exponential backoff
            }
        }

        throw new ProverException(ProverException.ErrorCode.RETRIES_EXHAUSTED,
                "All " + (config.maxRetries() + 1) + " attempts failed", lastException);
    }
}
