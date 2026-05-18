package com.bloxbean.cardano.zeroj.examples.dsl;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.*;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.onchain.julc.ProverToCardano;
import com.bloxbean.cardano.zeroj.examples.dsl.common.YaciHelper;
import com.bloxbean.cardano.zeroj.onchain.julc.Groth16BLS12381GenericVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Full-stack E2E: Java DSL circuit → pure Java BLS12-381 prove → Yaci DevKit on-chain verify.
 *
 * <p>This is the <b>definitive end-to-end test</b> for the pure Java ZK prover on Cardano:</p>
 * <ol>
 *   <li>Define circuit via Java DSL ({@link CircuitBuilder})</li>
 *   <li>Compile to R1CS for BLS12-381</li>
 *   <li>Generate dev Powers of Tau + Groth16 setup (pure Java)</li>
 *   <li>Compute witness and prove (pure Java BLS12-381 prover)</li>
 *   <li>Compress proof + VK to BLS bytes</li>
 *   <li>Load generic {@link Groth16BLS12381GenericVerifier} Plutus V3 script with VK params</li>
 *   <li>Lock tADA at script address with public inputs as datum</li>
 *   <li>Unlock with ZK proof as redeemer — verified on-chain by Cardano node</li>
 * </ol>
 *
 * <p><b>Zero external tools.</b> No circom, no snarkjs, no native provers.
 * 100% pure Java 25 from circuit definition to on-chain verification.</p>
 *
 * <h3>DEV/TEST (this test)</h3>
 * <p>Uses single-party {@code PowersOfTauBLS381.generate()} — toxic waste is known.
 * <b>DO NOT use this setup for production.</b></p>
 *
 * <h3>PRODUCTION</h3>
 * <pre>
 * // Import .ptau from MPC ceremony (Hermez, PPOT)
 * var srs = PtauImporterBLS381.importPtau(new FileInputStream("hermez_pot20.ptau"));
 * // OR import snarkjs .zkey from multi-party ceremony
 * var zkeyData = ZkeyImporterBLS381.importZkeyFull(Files.readAllBytes(Path.of("circuit.zkey")));
 * </pre>
 *
 * <p>Requires Yaci DevKit running. Run with:
 * {@code ./gradlew :zeroj-examples:e2eTest --tests "*PureJavaProverYaciE2ETest"}</p>
 */
@Tag("e2e")
class PureJavaProverYaciE2ETest {

    private static boolean isYaciAvailable;
    private static com.bloxbean.cardano.client.backend.api.BackendService backend;
    private static Account sender;

    @BeforeAll
    static void setup() throws Exception {
        isYaciAvailable = YaciHelper.isYaciReachable();
        if (!isYaciAvailable) return;

        backend = YaciHelper.createBackendService();
        sender = new Account(Networks.testnet());
        YaciHelper.topUp(sender.baseAddress(), 1000);
        System.out.println("Test wallet: " + sender.baseAddress());
    }

    /**
     * Pure Java circuit → prove → Yaci DevKit on-chain verify using generic Groth16 verifier.
     *
     * <p>Circuit: a * x + b = c, where a, b, and c are public and x is private.
     * Uses the generic {@link Groth16BLS12381GenericVerifier} with 3 public
     * inputs and 4 IC points.</p>
     */
    @Test
    void pureJavaProve_groth16_onChainVerify() throws Exception {
        assumeTrue(isYaciAvailable, "Yaci DevKit not running");

        System.out.println("=== Pure Java BLS12-381 Prove → Yaci DevKit On-Chain Verify ===");

        // 1. Define a three-public-input circuit via Java DSL
        var circuit = CircuitBuilder.create("three-public-linear-yaci")
                .publicVar("a")
                .publicVar("b")
                .publicVar("c")
                .secretVar("x")
                .define(api -> api.assertEqual(
                        api.add(api.mul(api.var("a"), api.var("x")), api.var("b")),
                        api.var("c")));

        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        assertEquals(3, r1cs.numPublicInputs(), "Need three public inputs for arbitrary-count verifier e2e");

        var constraints = r1cs.constraints();

        // 2. Witness: a=3, b=4, c=25, x=7
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(4)),
                "c", List.of(BigInteger.valueOf(25)),
                "x", List.of(BigInteger.valueOf(7))), CurveId.BLS12_381);

        System.out.println("Circuit compiled: " + r1cs.numConstraints() + " constraints");

        // 3. Dev trusted setup (DEVELOPMENT ONLY — see class Javadoc for production)
        var srs = PowersOfTauBLS381.generate(4);
        var setupResult = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());
        var pk = setupResult.provingKey();

        // 4. PROVE with pure Java BLS12-381 prover
        var proof = Groth16ProverBLS381.prove(pk, witness, constraints, r1cs.numWires());
        assertTrue(proof.a().isOnCurve());
        assertTrue(proof.b().isOnCurve());
        assertTrue(proof.c().isOnCurve());
        System.out.println("Proof generated (pure Java BLS12-381)");

        // 5. Compress VK + proof for on-chain
        var compressedVk = ProverToCardano.compressVk(setupResult);
        var compressedProof = ProverToCardano.compressProof(proof);
        assertEquals(4, compressedVk.ic().size(), "IC must have numPublic+1 entries");

        // 6. Load the generic Groth16 BLS12-381 verifier with VK params
        var script = JulcScriptLoader.load(Groth16BLS12381GenericVerifier.class,
                new BytesPlutusData(compressedVk.alpha()),
                new BytesPlutusData(compressedVk.beta()),
                new BytesPlutusData(compressedVk.gamma()),
                new BytesPlutusData(compressedVk.delta()),
                vkIcData(compressedVk.ic()));

        var scriptAddr = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        System.out.println("Verifier script address: " + scriptAddr);

        // 7. Lock tADA at script address with public inputs as datum
        BigInteger pub0 = witness[1]; // a = 3
        BigInteger pub1 = witness[2]; // b = 4
        BigInteger pub2 = witness[3]; // c = 25
        var datum = ListPlutusData.of(
                BigIntPlutusData.of(pub0),
                BigIntPlutusData.of(pub1),
                BigIntPlutusData.of(pub2));

        var quickTx = new QuickTxBuilder(backend);
        var lockTx = new Tx()
                .payToContract(scriptAddr, Amount.ada(5), datum)
                .from(sender.baseAddress());

        var lockResult = quickTx.compose(lockTx)
                .withSigner(SignerProviders.signerFrom(sender))
                .complete();

        assertTrue(lockResult.isSuccessful(), "Lock failed: " + lockResult.getResponse());
        String lockTxHash = lockResult.getValue();
        System.out.println("Lock tx: " + lockTxHash);
        YaciHelper.waitForConfirmation(backend, lockTxHash);

        // 8. Find the script UTXO
        var scriptUtxo = YaciHelper.findUtxo(backend, scriptAddr, lockTxHash);
        assertNotNull(scriptUtxo, "Script UTXO not found");

        // 9. Unlock with ZK proof as redeemer
        var redeemer = ConstrPlutusData.builder()
                .alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(compressedProof.piA()),
                        new BytesPlutusData(compressedProof.piB()),
                        new BytesPlutusData(compressedProof.piC())))
                .build();

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
        System.out.println("Unlock tx (ZK verified on-chain): " + unlockTxHash);
        YaciHelper.waitForConfirmation(backend, unlockTxHash);

        System.out.println();
        System.out.println("=== SUCCESS: Pure Java ZK proof verified ON-CHAIN on Cardano ===");
        System.out.println();
        System.out.println("Pipeline: Java DSL circuit");
        System.out.println("       → pure Java BLS12-381 Groth16 prover");
        System.out.println("       → generic Groth16BLS12381GenericVerifier (Plutus V3)");
        System.out.println("       → Yaci DevKit (Cardano local devnet)");
        System.out.println("Zero external tools. 100% Java 25.");
    }

    private static ListPlutusData vkIcData(List<byte[]> ic) {
        var list = ListPlutusData.of();
        for (byte[] point : ic) {
            list.add(new BytesPlutusData(point));
        }
        return list;
    }
}
