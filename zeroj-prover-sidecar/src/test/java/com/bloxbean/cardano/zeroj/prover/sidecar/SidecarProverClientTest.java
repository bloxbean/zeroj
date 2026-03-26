package com.bloxbean.cardano.zeroj.prover.sidecar;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;

import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the SidecarProverClient using an embedded HTTP server.
 */
class SidecarProverClientTest {

    private static HttpServer server;
    private static int port;
    private SidecarProverClient client;

    @BeforeAll
    static void startServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        port = server.getAddress().getPort();

        // GET /health
        server.createContext("/health", exchange -> {
            var resp = """
                    {"status":"ok","circuits":1}""".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(resp); }
        });

        // GET /circuits
        server.createContext("/circuits", exchange -> {
            if (exchange.getRequestURI().getPath().equals("/circuits")) {
                var resp = """
                        ["multiplier"]""".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, resp.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(resp); }
            } else if (exchange.getRequestURI().getPath().equals("/circuits/multiplier/vk")) {
                var resp = """
                        {"protocol":"groth16","curve":"bn128","nPublic":2,"vk_alpha_1":["1","2","1"],"vk_beta_2":[["1","0"],["1","0"],["1","0"]],"vk_gamma_2":[["1","0"],["1","0"],["1","0"]],"vk_delta_2":[["1","0"],["1","0"],["1","0"]],"vk_alphabeta_12":[[["1","0"],["1","0"],["1","0"]],[["1","0"],["1","0"],["1","0"]]],"IC":[["1","2","1"],["1","2","1"],["1","2","1"]]}""".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, resp.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(resp); }
            } else {
                exchange.sendResponseHeaders(404, 0);
                exchange.getResponseBody().close();
            }
        });

        // POST /prove
        server.createContext("/prove", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, 0);
                exchange.getResponseBody().close();
                return;
            }
            // Read request body
            var body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

            if (body.contains("\"bad_circuit\"")) {
                exchange.sendResponseHeaders(404, 0);
                exchange.getResponseBody().close();
                return;
            }

            var resp = """
                    {
                      "proof": {
                        "pi_a": ["100", "200", "1"],
                        "pi_b": [["10","20"],["30","40"],["1","0"]],
                        "pi_c": ["300", "400", "1"],
                        "protocol": "groth16",
                        "curve": "bn128"
                      },
                      "publicSignals": ["33", "3"],
                      "protocol": "groth16",
                      "curve": "bn128",
                      "provingTimeMs": 42
                    }""".getBytes(StandardCharsets.UTF_8);

            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(resp); }
        });

        server.setExecutor(null);
        server.start();
    }

    @AfterAll
    static void stopServer() {
        server.stop(0);
    }

    @BeforeEach
    void setUp() {
        var config = new ProverConfig(
                "http://localhost:" + port,
                Duration.ofSeconds(5),
                Duration.ofSeconds(10),
                1,
                Duration.ofMillis(100));
        client = new SidecarProverClient(config);
    }

    // --- Health ---

    @Test
    void isHealthy_returnsTrue() {
        assertTrue(client.isHealthy());
    }

    @Test
    void isHealthy_returnsFalse_whenUnreachable() {
        var badConfig = new ProverConfig("http://localhost:1", Duration.ofMillis(500),
                Duration.ofSeconds(1), 0, Duration.ofMillis(100));
        var badClient = new SidecarProverClient(badConfig);
        assertFalse(badClient.isHealthy());
    }

    // --- List circuits ---

    @Test
    void listCircuits_returnsAvailable() {
        var circuits = client.listCircuits();
        assertEquals(1, circuits.size());
        assertEquals("multiplier", circuits.getFirst());
    }

    // --- Prove ---

    @Test
    void prove_returnsProof() {
        var response = client.prove(ProveRequest.of("multiplier", Map.of("a", "3", "b", "11")));

        assertEquals("groth16", response.protocol());
        assertEquals("bn128", response.curve());
        assertEquals(2, response.publicSignals().size());
        assertEquals(BigInteger.valueOf(33), response.publicSignals().get(0));
        assertEquals(BigInteger.valueOf(3), response.publicSignals().get(1));
        assertEquals(42, response.provingTimeMs());
        assertTrue(response.proofJson().contains("pi_a"));
    }

    @Test
    void prove_circuitNotFound_throws() {
        var ex = assertThrows(ProverException.class, () ->
                client.prove(ProveRequest.of("bad_circuit", Map.of("x", "1"))));
        assertEquals(ProverException.ErrorCode.CIRCUIT_NOT_FOUND, ex.errorCode());
    }

    // --- Retry ---

    @Test
    void connectionFailure_retriesAndFails() {
        var badConfig = new ProverConfig("http://localhost:1",
                Duration.ofMillis(200), Duration.ofMillis(500), 1, Duration.ofMillis(50));
        var badClient = new SidecarProverClient(badConfig);

        var ex = assertThrows(ProverException.class, () ->
                badClient.prove(ProveRequest.of("test", Map.of("x", "1"))));
        assertEquals(ProverException.ErrorCode.RETRIES_EXHAUSTED, ex.errorCode());
    }

    // --- Config ---

    @Test
    void localhostConfig() {
        var config = ProverConfig.localhost();
        assertEquals("http://localhost:3000", config.baseUrl());
        assertEquals(Duration.ofSeconds(5), config.connectTimeout());
        assertEquals(Duration.ofSeconds(30), config.proveTimeout());
        assertEquals(2, config.maxRetries());
    }

    // --- Request validation ---

    @Test
    void proveRequest_emptyInputThrows() {
        assertThrows(IllegalArgumentException.class, () ->
                ProveRequest.of("test", Map.of()));
    }

    @Test
    void proveRequest_nullCircuitThrows() {
        assertThrows(NullPointerException.class, () ->
                ProveRequest.of(null, Map.of("x", "1")));
    }
}
