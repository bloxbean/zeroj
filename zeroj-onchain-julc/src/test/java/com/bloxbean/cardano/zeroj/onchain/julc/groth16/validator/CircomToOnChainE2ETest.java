package com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyImporterBLS381;
import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import supranational.blst.P1_Affine;
import supranational.blst.P2_Affine;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Full-stack E2E: <b>Circom circuit → snarkjs .zkey → pure Java prove → on-chain Julc VM verify</b>.
 *
 * <p>Validates that a circuit written in <b>circom</b> can be proven by the
 * <b>pure Java BLS12-381 prover</b> and verified on-chain by the
 * <b>Plutus V3 Groth16 BLS12-381 verifier</b>.</p>
 *
 * <h3>Circuit (multiplier2pub.circom)</h3>
 * <pre>
 * template Multiplier2Pub() {
 *     signal input a;   // public
 *     signal input b;   // private
 *     signal output c;  // public
 *     c &lt;== a * b;
 * }
 * component main {public [a]} = Multiplier2Pub();
 * // Witness: a=3, b=11, c=33
 * // Public signals: [c=33, a=3]  (outputs first, then inputs)
 * </pre>
 *
 * <h3>Production usage</h3>
 * <p>Replace the single-party .ptau with MPC ceremony output. The .zkey import
 * and Java prover path is identical.</p>
 */
class CircomToOnChainE2ETest extends ContractTest {

    private static final String BASE = "/test-circuits/circom-multiplier-bls12381/";

    private static com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyDataBLS381 zkeyData;
    private static BigInteger[] witness;
    private static SnarkjsToCardano.VkCompressed vk;

    @BeforeAll
    static void loadCircomArtifacts() throws Exception {
        zkeyData = ZkeyImporterBLS381.importZkeyFull(loadBytes(BASE + "circuit.zkey"));
        witness = ZkeyImporterBLS381.importWtns(
                CircomToOnChainE2ETest.class.getResourceAsStream(BASE + "witness.wtns"));
        vk = SnarkjsToCardano.parseVk(loadString(BASE + "verification_key.json"));
    }

    /**
     * Circom → Java prove → on-chain Julc VM Plutus V3 verify.
     */
    @Test
    void circom_javaProve_onChainVerify() {
        // Prove with pure Java BLS12-381 prover using circom's .zkey
        var proof = Groth16ProverBLS381.prove(zkeyData.provingKey(), witness,
                zkeyData.constraints(), zkeyData.numWires());

        assertTrue(proof.a().isOnCurve(), "Proof A on BLS12-381 G1");
        assertTrue(proof.b().isOnCurve(), "Proof B on BLS12-381 G2");
        assertTrue(proof.c().isOnCurve(), "Proof C on BLS12-381 G1");

        // Compress proof for on-chain
        byte[] piA = g1Compress(proof.a());
        byte[] piB = g2Compress(proof.b());
        byte[] piC = g1Compress(proof.c());

        // Compile on-chain verifier with circom VK
        var compiled = compileValidator(Groth16BLS12381Verifier.class);
        var program = compiled.program().applyParams(
                PlutusData.bytes(vk.alpha()),
                PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()),
                PlutusData.bytes(vk.delta()),
                vkIcData(vk.ic()));

        // Datum: public signals [c=33, a=3]
        var datum = PlutusData.list(
                PlutusData.integer(witness[1]),
                PlutusData.integer(witness[2]));

        // Redeemer: compressed proof
        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(piA),
                PlutusData.bytes(piB),
                PlutusData.bytes(piC));

        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        var ctx = spendingContext(txOutRef, datum).redeemer(redeemer).buildPlutusData();

        var result = evaluate(program, ctx);
        assertSuccess(result);
        System.out.println("=== Circom → Java prove → Julc VM on-chain verify: PASSED ===");
        System.out.println("  Budget: " + result.budgetConsumed());
    }

    @Test
    void circom_wrongWitness_onChainRejects() {
        // Prove with valid witness
        var proof = Groth16ProverBLS381.prove(zkeyData.provingKey(), witness,
                zkeyData.constraints(), zkeyData.numWires());

        byte[] piA = g1Compress(proof.a());
        byte[] piB = g2Compress(proof.b());
        byte[] piC = g1Compress(proof.c());

        var compiled = compileValidator(Groth16BLS12381Verifier.class);
        var program = compiled.program().applyParams(
                PlutusData.bytes(vk.alpha()),
                PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()),
                PlutusData.bytes(vk.delta()),
                vkIcData(vk.ic()));

        // Wrong public inputs: claim c=99, a=3 (instead of c=33, a=3)
        var wrongDatum = PlutusData.list(
                PlutusData.integer(99),
                PlutusData.integer(3));

        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(piA),
                PlutusData.bytes(piB),
                PlutusData.bytes(piC));

        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        var ctx = spendingContext(txOutRef, wrongDatum).redeemer(redeemer).buildPlutusData();

        var result = evaluate(program, ctx);
        assertFailure(result);
        System.out.println("Circom wrong witness → on-chain rejection: PASSED");
    }

    // --- BLS compression helpers ---

    private static final int FP = 48;

    private static byte[] g1Compress(JacobianG1BLS381.AffineG1 p) {
        if (p.isInfinity()) { byte[] r = new byte[FP]; r[0] = (byte) 0xC0; return r; }
        byte[] u = new byte[FP * 2];
        writeFp(u, 0, p.xBigInt()); writeFp(u, FP, p.yBigInt());
        return new P1_Affine(u).compress();
    }

    private static byte[] g2Compress(JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) { byte[] r = new byte[FP * 2]; r[0] = (byte) 0xC0; return r; }
        byte[] u = new byte[FP * 4];
        writeFp(u, 0, p.x().imBigInt()); writeFp(u, FP, p.x().reBigInt());
        writeFp(u, FP * 2, p.y().imBigInt()); writeFp(u, FP * 3, p.y().reBigInt());
        return new P2_Affine(u).compress();
    }

    private static void writeFp(byte[] buf, int off, BigInteger v) {
        byte[] b = v.toByteArray();
        int s = Math.max(0, b.length - FP), c = Math.min(b.length, FP);
        System.arraycopy(b, s, buf, off + FP - c, c);
    }

    private static PlutusData vkIcData(List<byte[]> ic) {
        List<PlutusData> values = new ArrayList<>();
        for (byte[] point : ic) {
            values.add(PlutusData.bytes(point));
        }
        return PlutusData.list(values.toArray(new PlutusData[0]));
    }

    private static byte[] loadBytes(String path) throws IOException {
        try (var is = CircomToOnChainE2ETest.class.getResourceAsStream(path)) {
            if (is == null) throw new IOException("Resource not found: " + path);
            return is.readAllBytes();
        }
    }

    private static String loadString(String path) throws IOException {
        return new String(loadBytes(path), StandardCharsets.UTF_8);
    }
}
