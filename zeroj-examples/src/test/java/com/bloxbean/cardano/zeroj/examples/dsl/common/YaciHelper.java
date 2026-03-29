package com.bloxbean.cardano.zeroj.examples.dsl.common;

import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Shared helper for connecting to Yaci DevKit and managing test accounts.
 * <p>
 * Yaci DevKit must be running locally:
 * <ul>
 *   <li>Blockfrost-compatible API on port 8080</li>
 *   <li>Admin API on port 10000</li>
 * </ul>
 */
public final class YaciHelper {

    public static final String YACI_BASE_URL = "http://localhost:8080/api/v1/";
    public static final String YACI_ADMIN_URL = "http://localhost:10000";

    private YaciHelper() {}

    /**
     * Create a BackendService connected to the local Yaci DevKit node.
     */
    public static BackendService createBackendService() {
        return new BFBackendService(YACI_BASE_URL, "dummy-key");
    }

    /**
     * Check if Yaci DevKit is reachable (both the node API and admin API).
     */
    public static boolean isYaciReachable() {
        try {
            var client = HttpClient.newHttpClient();
            var request = HttpRequest.newBuilder()
                    .uri(URI.create(YACI_BASE_URL))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            var response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // Check admin API as well
            var adminRequest = HttpRequest.newBuilder()
                    .uri(URI.create(YACI_ADMIN_URL))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            var adminResponse = client.send(adminRequest, HttpResponse.BodyHandlers.ofString());

            return response.statusCode() < 500 && adminResponse.statusCode() < 500;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Top up an address with ADA via the Yaci DevKit admin API.
     * Waits 1 second after the topup for the transaction to be processed (devnet is fast).
     *
     * @param address   the bech32 address to fund
     * @param adaAmount the amount of ADA (not lovelace) to send
     */
    public static void topUp(String address, long adaAmount) {
        try {
            var client = HttpClient.newHttpClient();
            var body = "{\"address\":\"" + address + "\",\"adaAmount\":" + adaAmount + "}";
            var request = HttpRequest.newBuilder()
                    .uri(URI.create(YACI_ADMIN_URL + "/local-cluster/api/addresses/topup"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            var response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new RuntimeException("Topup failed: " + response.statusCode() + " " + response.body());
            }
            System.out.println("  Topped up " + adaAmount + " ADA to " + address.substring(0, 20) + "...");
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to topup account", e);
        }
    }

    /**
     * Wait for a transaction to be confirmed on-chain.
     * Polls up to 30 times with 2-second intervals (60 seconds total).
     *
     * @param backend the backend service to query
     * @param txHash  the transaction hash to wait for
     */
    public static void waitForConfirmation(BackendService backend, String txHash) throws Exception {
        System.out.println("  Waiting for confirmation of " + txHash + "...");
        for (int i = 0; i < 30; i++) {
            try {
                var txResult = backend.getTransactionService().getTransaction(txHash);
                if (txResult.isSuccessful() && txResult.getValue() != null) {
                    System.out.println("  Confirmed!");
                    return;
                }
            } catch (Exception ignored) {
            }
            Thread.sleep(2000);
        }
        throw new RuntimeException("Transaction not confirmed within 60s: " + txHash);
    }

    /**
     * Find a UTXO at the given address matching a specific transaction hash.
     * Polls up to 5 times with 2-second intervals.
     *
     * @param backend the backend service to query
     * @param address the address to search
     * @param txHash  the transaction hash to match
     * @return the matching UTXO
     */
    public static Utxo findUtxo(BackendService backend, String address, String txHash) throws Exception {
        for (int attempt = 0; attempt < 5; attempt++) {
            var utxoResult = backend.getUtxoService().getUtxos(address, 100, 1);
            if (utxoResult.isSuccessful() && utxoResult.getValue() != null) {
                var match = utxoResult.getValue().stream()
                        .filter(u -> u.getTxHash().equals(txHash))
                        .findFirst();
                if (match.isPresent()) return match.get();
            }
            Thread.sleep(2000);
        }
        throw new RuntimeException("UTXO not found at " + address + " for tx " + txHash);
    }

    /**
     * Find all UTXOs at the given address matching a specific transaction hash.
     * Polls up to 5 times with 2-second intervals.
     *
     * @param backend the backend service to query
     * @param address the address to search
     * @param txHash  the transaction hash to match
     * @return the list of matching UTXOs
     */
    public static List<Utxo> findAllUtxos(BackendService backend, String address, String txHash) throws Exception {
        for (int attempt = 0; attempt < 5; attempt++) {
            var utxoResult = backend.getUtxoService().getUtxos(address, 100, 1);
            if (utxoResult.isSuccessful() && utxoResult.getValue() != null) {
                var matches = new ArrayList<Utxo>();
                for (var utxo : utxoResult.getValue()) {
                    if (utxo.getTxHash().equals(txHash)) {
                        matches.add(utxo);
                    }
                }
                if (!matches.isEmpty()) return matches;
            }
            Thread.sleep(2000);
        }
        throw new RuntimeException("No UTXOs found at " + address + " for tx " + txHash);
    }
}
