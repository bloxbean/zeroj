package com.bloxbean.cardano.zeroj.onchain.julc.bbs;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.core.Program;
import com.bloxbean.cardano.julc.ledger.TxOutRef;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.zeroj.bbs.BbsKeyPair;
import com.bloxbean.cardano.zeroj.bbs.BbsPresentation;
import com.bloxbean.cardano.zeroj.bbs.BbsService;
import com.bloxbean.cardano.zeroj.bbs.BbsSignature;
import com.bloxbean.cardano.zeroj.bbs.cardano.BbsToCardano;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

/**
 * Differential test of the full on-chain BBS {@code ProofVerify} against a <b>real</b> off-chain
 * presentation: build a 5-attribute credential and reveal indexes {@code {2, 3}}
 * ({@code country, kycLevel}) with {@code zeroj-bbs}, flatten it with {@link BbsToCardano}, feed the
 * params + redeemer to the compiled {@link BbsProofVerifyProbe}, and assert the Julc VM accepts it —
 * and rejects a tampered presentation header. This is the same UPLC that runs on-chain.
 */
class BbsProofVerifyVmTest extends ContractTest {

    private static final BbsService BBS = BbsService.pureJava();
    private static final byte[] HEADER = "reusable-kyc/v1|issuer=kyc-provider-1".getBytes(StandardCharsets.UTF_8);
    private static final List<byte[]> MESSAGES = List.of(
            "Alice Example".getBytes(StandardCharsets.UTF_8),   // 0 givenName
            "1990-05-01".getBytes(StandardCharsets.UTF_8),      // 1 dob
            "USA".getBytes(StandardCharsets.UTF_8),             // 2 country
            "verified".getBytes(StandardCharsets.UTF_8),        // 3 kycLevel
            "9f86d081".getBytes(StandardCharsets.UTF_8));       // 4 docHash

    private static Program program;
    private static BbsToCardano.OnChainProof proof;

    @BeforeAll
    static void setup() {
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 7);
        BbsKeyPair kp = BBS.keyPair(seed, "kyc-provider-1".getBytes(StandardCharsets.UTF_8));
        BbsSignature sig = BBS.sign(kp.secretKey(), kp.publicKey(), MESSAGES, HEADER);

        byte[] ph = "onchain-claim-session-1".getBytes(StandardCharsets.UTF_8);
        BbsPresentation presentation = BBS.derivePresentation(
                kp.publicKey(), sig, MESSAGES, HEADER, ph, new int[] {2, 3});

        var params = BbsToCardano.verifierParams(kp.publicKey(), HEADER, MESSAGES.size());
        proof = BbsToCardano.onChainProof(presentation);

        program = new BbsProofVerifyVmTest()
                .compileValidator(BbsProofVerifyProbe.class, Path.of("src/test/java")).program().applyParams(
                PlutusData.bytes(params.publicKey()),
                PlutusData.bytes(params.g2Generator()),
                PlutusData.bytes(params.p1()),
                PlutusData.bytes(params.q1()),
                PlutusData.bytes(params.h().get(0)), PlutusData.bytes(params.h().get(1)),
                PlutusData.bytes(params.h().get(2)), PlutusData.bytes(params.h().get(3)),
                PlutusData.bytes(params.h().get(4)),
                PlutusData.bytes(params.domain()),
                PlutusData.bytes(params.dstHashToScalar()),
                PlutusData.bytes(params.dstMapToScalar()));
    }

    @Test
    void onchain_proof_verify_accepts_real_presentation() {
        var result = evaluate(program, ctx(claim(proof.presentationHeader())));
        assertSuccess(result);
        System.out.println("[BbsProofVerify on-chain] budget consumed: " + result.budgetConsumed());
    }

    @Test
    void tampered_presentation_header_is_rejected() {
        // Same proof, different ph → the recomputed challenge won't match the proof's challenge.
        assertFailure(evaluate(program, ctx(claim("a-different-header".getBytes(StandardCharsets.UTF_8)))));
    }

    private PlutusData claim(byte[] ph) {
        return PlutusData.constr(0,
                PlutusData.bytes(proof.aBar()), PlutusData.bytes(proof.bBar()), PlutusData.bytes(proof.d()),
                PlutusData.integer(proof.eHat()), PlutusData.integer(proof.r1Hat()), PlutusData.integer(proof.r3Hat()),
                PlutusData.integer(proof.mHats().get(0)), PlutusData.integer(proof.mHats().get(1)),
                PlutusData.integer(proof.mHats().get(2)), PlutusData.integer(proof.challenge()),
                PlutusData.bytes(proof.disclosed().get(0).message()),
                PlutusData.bytes(proof.disclosed().get(1).message()),
                PlutusData.bytes(ph));
    }

    private PlutusData ctx(PlutusData redeemer) {
        TxOutRef ref = TestDataBuilder.randomTxOutRef_typed();
        return spendingContext(ref, PlutusData.integer(0)).redeemer(redeemer).buildPlutusData();
    }
}
