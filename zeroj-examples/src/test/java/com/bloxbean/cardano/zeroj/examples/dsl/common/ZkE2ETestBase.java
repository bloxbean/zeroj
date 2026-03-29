package com.bloxbean.cardano.zeroj.examples.dsl.common;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.zeroj.onchain.julc.SnarkjsToCardano;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Base class for end-to-end integration tests on Yaci DevKit (local devnet).
 * <p>
 * Provides: Yaci backend, fresh test wallet (funded via topUp), ZK proof test vectors, and UTXO helpers.
 */
public abstract class ZkE2ETestBase {

    protected static BackendService backend;
    protected static Account sender;
    protected static boolean isYaciAvailable;
    protected static SnarkjsToCardano.VkCompressed vk;
    protected static SnarkjsToCardano.ProofCompressed proof;
    protected static List<BigInteger> publicInputs;

    /**
     * Initialize with a specific circuit's proof artifacts.
     *
     * @param circuitDir resource directory name, e.g. "sealed-bid-bls12381"
     */
    protected static void initBase(String circuitDir) throws Exception {
        // Check Yaci DevKit availability
        isYaciAvailable = YaciHelper.isYaciReachable();
        if (!isYaciAvailable) {
            System.out.println("WARNING: Yaci DevKit not running — tests will be skipped");
            return;
        }

        // Connect to Yaci DevKit
        backend = YaciHelper.createBackendService();

        // Create fresh wallet and fund via topUp
        sender = new Account(Networks.testnet());
        System.out.println("Test wallet address: " + sender.baseAddress());
        YaciHelper.topUp(sender.baseAddress(), 1000);

        // Load ZK proof test vectors for the specific circuit
        String base = "/test-circuits/" + circuitDir + "/";
        vk = SnarkjsToCardano.parseVk(loadResource(base + "verification_key.json"));
        proof = SnarkjsToCardano.parseProof(loadResource(base + "proof.json"));
        publicInputs = SnarkjsToCardano.parsePublicInputs(loadResource(base + "public.json"));
        System.out.println("Circuit: " + circuitDir + " | Public inputs: " + publicInputs);
    }

    protected static byte[] toMinimalBytes(BigInteger v) {
        byte[] b = v.toByteArray();
        return (b.length > 1 && b[0] == 0) ? java.util.Arrays.copyOfRange(b, 1, b.length) : b;
    }

    protected static String loadResource(String path) throws IOException {
        try (var is = ZkE2ETestBase.class.getResourceAsStream(path)) {
            if (is == null) throw new IOException("Resource not found: " + path);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    protected static String hex(byte[] bytes) {
        return java.util.HexFormat.of().formatHex(bytes);
    }

    protected static Utxo findScriptUtxo(String address, String txHash) throws Exception {
        return YaciHelper.findUtxo(backend, address, txHash);
    }

    protected static List<Utxo> findAllScriptUtxos(String address, String txHash) throws Exception {
        return YaciHelper.findAllUtxos(backend, address, txHash);
    }

    protected static void waitForTx(String txHash) throws Exception {
        YaciHelper.waitForConfirmation(backend, txHash);
    }

    /**
     * Submit a transaction with automatic retry on UTXO contention errors.
     * <p>
     * When multiple e2e tests run from the same wallet, UTXOs can be consumed
     * between coin selection and submission, causing "inputs are spent" errors.
     * This helper retries with a backoff to wait for the conflicting tx to confirm.
     */
    protected static com.bloxbean.cardano.client.api.model.Result<String> submitTxWithRetry(
            QuickTxBuilder quickTx, Tx tx, Account signer, int maxRetries) throws Exception {
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            var result = quickTx.compose(tx)
                    .withSigner(SignerProviders.signerFrom(signer))
                    .complete();
            if (result.isSuccessful()) return result;
            String resp = result.getResponse();
            if (resp != null && (resp.contains("inputs are spent") || resp.contains("already been included"))) {
                System.out.println("UTXO contention (attempt " + attempt + "/" + maxRetries + "), waiting...");
                Thread.sleep(5000);
                continue;
            }
            return result; // Non-retryable error
        }
        // Last attempt
        return quickTx.compose(tx).withSigner(SignerProviders.signerFrom(signer)).complete();
    }
}
