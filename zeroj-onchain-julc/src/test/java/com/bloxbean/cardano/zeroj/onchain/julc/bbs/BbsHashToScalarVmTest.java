package com.bloxbean.cardano.zeroj.onchain.julc.bbs;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.TxOutRef;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bbs.internal.CfrgBbsCore;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * Differential test of the on-chain BBS {@code hash_to_scalar} (the crux of an on-chain
 * {@code ProofVerify}). Compiles {@link BbsHashToScalarProbe} and, for several {@code (message, dst)}
 * pairs, asserts the value the Julc VM recomputes equals the off-chain
 * {@code CfrgBbsCore.hashToScalar} in {@code zeroj-bbs} — proving the {@code expand_message_xmd(SHA-256)}
 * port is byte-exact.
 */
class BbsHashToScalarVmTest extends ContractTest {

    // A realistic BBS BLS12381G1-SHA256 H2S domain separation tag.
    private static final byte[] DST =
            "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_".getBytes(StandardCharsets.US_ASCII);

    @Test
    void onchain_hash_to_scalar_matches_offchain() {
        assertMatches("".getBytes(StandardCharsets.UTF_8));
        assertMatches("the quick brown fox".getBytes(StandardCharsets.UTF_8));
        assertMatches("USA".getBytes(StandardCharsets.UTF_8));
        // a message longer than one SHA-256 block, to exercise the b0/b1/b2 path fully
        assertMatches(("reusable-kyc/v1|kycLevel=verified|country=USA|"
                + "0123456789abcdef0123456789abcdef0123456789abcdef").getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void wrong_expected_is_rejected() {
        byte[] message = "USA".getBytes(StandardCharsets.UTF_8);
        BigInteger expected = CfrgBbsCore.hashToScalar(message, DST, BbsCiphersuite.BLS12381_SHA256);
        assertFailure(evaluate(program(), probeCtx(message, DST, expected.add(BigInteger.ONE))));
    }

    private void assertMatches(byte[] message) {
        BigInteger expected = CfrgBbsCore.hashToScalar(message, DST, BbsCiphersuite.BLS12381_SHA256);
        assertSuccess(evaluate(program(), probeCtx(message, DST, expected)));
    }

    private com.bloxbean.cardano.julc.core.Program program() {
        return compileValidator(BbsHashToScalarProbe.class, Path.of("src/test/java")).program();
    }

    private PlutusData probeCtx(byte[] message, byte[] dst, BigInteger expected) {
        PlutusData redeemer = PlutusData.constr(0,
                PlutusData.bytes(message), PlutusData.bytes(dst), PlutusData.integer(expected));
        TxOutRef ref = TestDataBuilder.randomTxOutRef_typed();
        return spendingContext(ref, PlutusData.integer(0)).redeemer(redeemer).buildPlutusData();
    }
}
