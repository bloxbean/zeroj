package com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * Unit test: validates the PlonK Julc prototype with gnark test vectors.
 * Verifies Fiat-Shamir challenge re-derivation matches gnark's exported values.
 */
class PlonkBLS12381FullVerifierTest extends ContractTest {

    private static final BigInteger FR = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    private static JsonNode json;

    @BeforeAll
    static void loadVectors() throws Exception {
        json = new ObjectMapper().readTree(new String(
                PlonkBLS12381FullVerifierTest.class.getResourceAsStream(
                        "/test-circuits/plonk-multiplier-bls12381/plonk_cardano.json").readAllBytes(),
                StandardCharsets.UTF_8));
    }

    @Test
    void fiatShamir_matchesGnark() {
        var compiled = compileValidator(PlonkBLS12381FullVerifier.class);

        // Domain params
        BigInteger omega = new BigInteger(json.at("/vk_params/generator").asText());
        BigInteger nInv = new BigInteger(json.at("/vk_params/sizeInv").asText());
        BigInteger k1 = BigInteger.TWO;
        BigInteger k2 = BigInteger.valueOf(3);

        // VK uncompressed raw bytes (96 bytes each)
        byte[] s1Raw = hex(json.at("/vk_uncompressed/s1_raw").asText());
        byte[] s2Raw = hex(json.at("/vk_uncompressed/s2_raw").asText());
        byte[] s3Raw = hex(json.at("/vk_uncompressed/s3_raw").asText());
        byte[] qlRaw = hex(json.at("/vk_uncompressed/ql_raw").asText());
        byte[] qrRaw = hex(json.at("/vk_uncompressed/qr_raw").asText());
        byte[] qmRaw = hex(json.at("/vk_uncompressed/qm_raw").asText());
        byte[] qoRaw = hex(json.at("/vk_uncompressed/qo_raw").asText());
        byte[] qkRaw = hex(json.at("/vk_uncompressed/qk_raw").asText());

        // VK compressed (for BLS ops)
        byte[] s3 = hex(json.at("/vk/s3").asText());
        byte[] s1 = hex(json.at("/vk/s1").asText());
        byte[] s2 = hex(json.at("/vk/s2").asText());
        byte[] qm = hex(json.at("/vk/qm").asText());
        byte[] ql = hex(json.at("/vk/ql").asText());
        byte[] qr = hex(json.at("/vk/qr").asText());
        byte[] qo = hex(json.at("/vk/qo").asText());
        byte[] qk = hex(json.at("/vk/qk").asText());
        byte[] x2 = hex(json.at("/vk/kzg_g2_1").asText());

        // Generators
        byte[] g1Gen = hex("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
        byte[] g2Gen = hex("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8");

        // Challenge name bytes
        byte[] gammaBytes = "gamma".getBytes(StandardCharsets.UTF_8);
        byte[] betaBytes = "beta".getBytes(StandardCharsets.UTF_8);
        byte[] alphaBytes = "alpha".getBytes(StandardCharsets.UTF_8);
        byte[] zetaBytes = "zeta".getBytes(StandardCharsets.UTF_8);

        // Apply all @Param values
        var program = compiled.program().applyParams(
                PlutusData.bytes(s1Raw), PlutusData.bytes(s2Raw),
                PlutusData.bytes(s3Raw), PlutusData.bytes(qlRaw),
                PlutusData.bytes(qrRaw), PlutusData.bytes(qmRaw),
                PlutusData.bytes(qoRaw), PlutusData.bytes(qkRaw),
                PlutusData.bytes(s3), PlutusData.bytes(s1), PlutusData.bytes(s2),
                PlutusData.bytes(qm), PlutusData.bytes(ql), PlutusData.bytes(qr),
                PlutusData.bytes(qo), PlutusData.bytes(qk), PlutusData.bytes(x2),
                PlutusData.integer(omega), PlutusData.integer(k1), PlutusData.integer(k2),
                PlutusData.integer(FR), PlutusData.integer(nInv),
                PlutusData.bytes(g1Gen), PlutusData.bytes(g2Gen),
                PlutusData.bytes(gammaBytes), PlutusData.bytes(betaBytes),
                PlutusData.bytes(alphaBytes), PlutusData.bytes(zetaBytes));

        // Proof data
        byte[] cmA = hex(json.at("/proof/cmL").asText());
        byte[] cmB = hex(json.at("/proof/cmR").asText());
        byte[] cmC = hex(json.at("/proof/cmO").asText());
        byte[] cmZ = hex(json.at("/proof/cmZ").asText());
        byte[] cmT1 = hex(json.at("/proof/cmH0").asText());
        byte[] cmT2 = hex(json.at("/proof/cmH1").asText());
        byte[] cmT3 = hex(json.at("/proof/cmH2").asText());
        byte[] wXi = hex(json.at("/proof/wZeta").asText());
        byte[] wXiw = hex(json.at("/proof/wZetaOmega").asText());

        // Uncompressed proof bytes for transcript
        byte[] cmARaw = hex(json.at("/proof_uncompressed/cmL_raw").asText());
        byte[] cmBRaw = hex(json.at("/proof_uncompressed/cmR_raw").asText());
        byte[] cmCRaw = hex(json.at("/proof_uncompressed/cmO_raw").asText());
        byte[] cmZRaw = hex(json.at("/proof_uncompressed/cmZ_raw").asText());
        byte[] cmT1Raw = hex(json.at("/proof_uncompressed/cmH0_raw").asText());
        byte[] cmT2Raw = hex(json.at("/proof_uncompressed/cmH1_raw").asText());
        byte[] cmT3Raw = hex(json.at("/proof_uncompressed/cmH2_raw").asText());

        // Evaluations
        JsonNode claimed = json.at("/proof/claimedValues");
        BigInteger evalA = new BigInteger(claimed.get(0).asText());
        BigInteger evalB = new BigInteger(claimed.get(1).asText());
        BigInteger evalC = new BigInteger(claimed.get(2).asText());
        BigInteger evalS1 = new BigInteger(claimed.get(3).asText());
        BigInteger evalS2 = new BigInteger(claimed.get(4).asText());
        BigInteger evalZw = new BigInteger(claimed.get(5).asText());

        // Pre-computed inverses using gnark's zeta
        BigInteger zeta = new BigInteger(json.at("/challenges/zeta").asText());
        BigInteger xiMinusOneInv = zeta.subtract(BigInteger.ONE).mod(FR).modInverse(FR);
        BigInteger xiMinusOmegaInv = zeta.subtract(omega).mod(FR).modInverse(FR);

        // Build redeemer
        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(cmA), PlutusData.bytes(cmB), PlutusData.bytes(cmC),
                PlutusData.bytes(cmZ), PlutusData.bytes(cmT1), PlutusData.bytes(cmT2),
                PlutusData.bytes(cmT3), PlutusData.bytes(wXi), PlutusData.bytes(wXiw),
                PlutusData.bytes(cmARaw), PlutusData.bytes(cmBRaw), PlutusData.bytes(cmCRaw),
                PlutusData.bytes(cmZRaw), PlutusData.bytes(cmT1Raw), PlutusData.bytes(cmT2Raw),
                PlutusData.bytes(cmT3Raw),
                PlutusData.integer(evalA), PlutusData.integer(evalB), PlutusData.integer(evalC),
                PlutusData.integer(evalS1), PlutusData.integer(evalS2), PlutusData.integer(evalZw),
                PlutusData.integer(xiMinusOneInv), PlutusData.integer(xiMinusOmegaInv));

        // Datum: 1 public input [Z=33]
        var datum = PlutusData.list(PlutusData.integer(33));

        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        var ctx = spendingContext(txOutRef, datum).redeemer(redeemer).buildPlutusData();

        System.out.println("[test] Running PlonK verifier in Julc VM...");
        var result = evaluate(program, ctx);

        System.out.println("[test] Success: " + result.isSuccess());
        System.out.println("[test] Budget: " + result.budgetConsumed());

        assertSuccess(result);
        System.out.println("[test] PlonK Julc prototype accepted transcript and inverse checks.");
    }

    private static byte[] hex(String h) {
        return HexFormat.of().parseHex(h);
    }
}
