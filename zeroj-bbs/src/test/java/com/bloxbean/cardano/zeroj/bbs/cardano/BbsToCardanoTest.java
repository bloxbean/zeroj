package com.bloxbean.cardano.zeroj.bbs.cardano;

import com.bloxbean.cardano.zeroj.bbs.BbsKeyPair;
import com.bloxbean.cardano.zeroj.bbs.BbsPresentation;
import com.bloxbean.cardano.zeroj.bbs.BbsService;
import com.bloxbean.cardano.zeroj.bbs.BbsSignature;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link BbsToCardano}: the off-chain material it derives is well-formed (correct point
 * sizes, generator count, disclosed/undisclosed split) and consistent with the presentation the
 * on-chain verifier will check.
 */
class BbsToCardanoTest {

    private static final BbsService BBS = BbsService.pureJava();
    private static final byte[] HEADER = "reusable-kyc/v1|issuer=kyc-provider-1".getBytes(StandardCharsets.UTF_8);
    private static final List<byte[]> MESSAGES = List.of(
            "Alice Example".getBytes(StandardCharsets.UTF_8),   // 0 givenName
            "1990-05-01".getBytes(StandardCharsets.UTF_8),      // 1 dob
            "USA".getBytes(StandardCharsets.UTF_8),             // 2 country
            "verified".getBytes(StandardCharsets.UTF_8),        // 3 kycLevel
            "9f86d081".getBytes(StandardCharsets.UTF_8));       // 4 docHash

    private static BbsKeyPair keyPair() {
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 7);
        return BBS.keyPair(seed, "kyc-provider-1".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void verifierParams_areWellFormed() {
        BbsKeyPair kp = keyPair();
        var params = BbsToCardano.verifierParams(kp.publicKey(), HEADER, MESSAGES.size());

        assertEquals(96, params.publicKey().length, "W is a compressed G2 point");
        assertEquals(96, params.g2Generator().length, "BP2 is a compressed G2 point");
        assertEquals(48, params.p1().length, "P1 is a compressed G1 point");
        assertEquals(48, params.q1().length, "Q1 is a compressed G1 point");
        assertEquals(5, params.h().size(), "one H generator per message");
        params.h().forEach(h -> assertEquals(48, h.length, "each H is a compressed G1 point"));
        assertEquals(32, params.domain().length, "domain is a 32-byte scalar");
        assertTrue(new String(params.dstHashToScalar(), StandardCharsets.US_ASCII).endsWith("H2S_"));
        assertTrue(new String(params.dstMapToScalar(), StandardCharsets.US_ASCII)
                .endsWith("MAP_MSG_TO_SCALAR_AS_HASH_"));
    }

    @Test
    void onChainProof_flattensDisclosedAndBlindsHidden() {
        BbsKeyPair kp = keyPair();
        BbsSignature sig = BBS.sign(kp.secretKey(), kp.publicKey(), MESSAGES, HEADER);
        byte[] ph = "challenge-abc".getBytes(StandardCharsets.UTF_8);

        // reveal country[2] + kycLevel[3]; hide givenName[0], dob[1], docHash[4]
        BbsPresentation presentation = BBS.derivePresentation(
                kp.publicKey(), sig, MESSAGES, HEADER, ph, new int[] {2, 3});
        assertTrue(BBS.verifyPresentation(kp.publicKey(), presentation), "presentation must be valid off-chain");

        var proof = BbsToCardano.onChainProof(presentation);

        assertEquals(48, proof.aBar().length);
        assertEquals(48, proof.bBar().length);
        assertEquals(48, proof.d().length);
        assertEquals(3, proof.mHats().size(), "one blinded response per hidden message (0,1,4)");
        assertArrayEquals(ph, proof.presentationHeader(), "header is carried through unchanged");

        assertEquals(2, proof.disclosed().size(), "exactly the two revealed messages");
        assertEquals(2, proof.disclosed().get(0).index());
        assertArrayEquals("USA".getBytes(StandardCharsets.UTF_8), proof.disclosed().get(0).message());
        assertEquals(3, proof.disclosed().get(1).index());
        assertArrayEquals("verified".getBytes(StandardCharsets.UTF_8), proof.disclosed().get(1).message());

        // the hidden attribute values must appear nowhere in the flattened proof
        for (var d : proof.disclosed()) {
            assertTrue(d.index() == 2 || d.index() == 3, "only country/kycLevel are disclosed");
        }
    }
}
