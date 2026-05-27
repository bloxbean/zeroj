package com.bloxbean.cardano.zeroj.examples.dsl.auction;

import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.*;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import com.bloxbean.cardano.zeroj.examples.dsl.auction.onchain.ZkAuctionVerifier;
import com.bloxbean.cardano.zeroj.examples.dsl.common.ZkE2ETestBase;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Full end-to-end sealed-bid auction on Cardano via Yaci DevKit.
 * <p>
 * Demonstrates the complete ZK on-chain verification flow:
 * <ol>
 *   <li>Load pre-generated snarkjs BLS12-381 proof artifacts (from Java DSL circuit)</li>
 *   <li>Compile ZkAuctionVerifier Julc script with VK + reserve price params</li>
 *   <li>Lock tADA at script address with public inputs as datum</li>
 *   <li>Unlock with ZK proof as redeemer — verified by Plutus V3 on-chain</li>
 * </ol>
 * <p>
 * This test is tagged {@code e2e} and skips gracefully if Yaci DevKit is not running.
 * Run with: {@code ./gradlew :zeroj-examples:e2eTest --tests "*SealedBidOnChainE2ETest"}
 */
@Tag("e2e")
class SealedBidOnChainE2ETest extends ZkE2ETestBase {

    @BeforeAll
    static void setup() throws Exception {
        initBase("sealed-bid-bls12381");
    }

    @Test
    void sealedBidVerifiedOnChain() throws Exception {
        assumeTrue(isYaciAvailable, "Yaci DevKit not running");

        // --- Circuit public inputs ---
        // pub[0] = bidCommitment = Poseidon(bidAmount=1000, salt=42) on BLS12-381
        // pub[1] = reservePrice = 500
        BigInteger reservePrice = BigInteger.valueOf(500);

        // Cross-check: circuit's reserve price matches our domain value
        assertEquals(reservePrice, publicInputs.get(1),
                "Circuit reservePrice must match domain reservePrice");

        // Reserve price as big-endian bytes (baked into validator as @Param)
        byte[] reservePriceBytes = toMinimalBytes(reservePrice);

        // 1. Load the compiled auction verifier with reserve price + VK params
        var script = JulcScriptLoader.load(ZkAuctionVerifier.class,
                new BytesPlutusData(reservePriceBytes),
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                vkIcData(vk.ic()));

        var scriptAddr = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        System.out.println("Auction script address: " + scriptAddr);

        // 2. Datum: [bidCommitment, reservePrice] — the ZK public inputs
        var datum = ListPlutusData.of(
                BigIntPlutusData.of(publicInputs.get(0)),   // bidCommitment
                BigIntPlutusData.of(publicInputs.get(1)));  // reservePrice

        // 3. Lock: simulate auction escrow (bidder locks ADA with bid commitment)
        var quickTx = new QuickTxBuilder(backend);

        var lockTx = new Tx()
                .payToContract(scriptAddr, Amount.ada(5), datum)
                .from(sender.baseAddress());

        var lockResult = quickTx.compose(lockTx)
                .withSigner(SignerProviders.signerFrom(sender))
                .complete();

        assertTrue(lockResult.isSuccessful(), "Lock failed: " + lockResult.getResponse());
        String lockTxHash = lockResult.getValue();
        System.out.println("Auction escrow lock tx: " + lockTxHash);
        waitForTx(lockTxHash);

        // 4. Find the script UTXO
        var scriptUtxo = findScriptUtxo(scriptAddr, lockTxHash);

        // 5. Redeemer: ZK proof (bid matches commitment + exceeds reserve)
        var redeemer = ConstrPlutusData.builder()
                .alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(proof.piA()),
                        new BytesPlutusData(proof.piB()),
                        new BytesPlutusData(proof.piC())))
                .build();

        // 6. Unlock: bidder claims escrow with valid ZK bid proof
        var unlockTx = new ScriptTx()
                .collectFrom(scriptUtxo, redeemer)
                .payToAddress(sender.baseAddress(), Amount.ada(4.5))
                .attachSpendingValidator(script);

        var unlockResult = quickTx.compose(unlockTx)
                .withSigner(SignerProviders.signerFrom(sender))
                .feePayer(sender.baseAddress())
                .collateralPayer(sender.baseAddress())
                .complete();

        assertTrue(unlockResult.isSuccessful(), "Unlock failed: " + unlockResult.getResponse());
        String unlockTxHash = unlockResult.getValue();
        System.out.println("Auction bid verified on-chain: " + unlockTxHash);
        waitForTx(unlockTxHash);

        System.out.println();
        System.out.println("=== SUCCESS: Sealed-bid auction ZK proof verified on Cardano ===");
        System.out.println();
        System.out.println("Flow: Java DSL circuit -> snarkjs BLS12-381 proof -> Julc Plutus V3 verifier -> Yaci DevKit");
        System.out.println("Reserve price: " + reservePrice + " (verified: domain == circuit == on-chain)");
        System.out.println("Bid amount: 1000 (PRIVATE — hidden inside ZK proof, never on-chain)");
    }

    private static ListPlutusData vkIcData(List<byte[]> ic) {
        List<PlutusData> values = new ArrayList<>();
        for (byte[] point : ic) {
            values.add(new BytesPlutusData(point));
        }
        return ListPlutusData.of(values.toArray(new PlutusData[0]));
    }
}
