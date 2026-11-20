package org.zeroj.bbs.cardano;

import org.zeroj.bbs.BbsCiphersuite;
import org.zeroj.bbs.BbsKeyPair;
import org.zeroj.bbs.BbsPresentation;
import org.zeroj.bbs.BbsProof;
import org.zeroj.bbs.BbsPublicKey;
import org.zeroj.bbs.BbsService;
import org.zeroj.bbs.BbsSignature;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    @Test
    void verifierParams_rejectsIdentityMalformedAndWrongSuitePublicKeys() {
        byte[] g2Identity = new byte[96];
        g2Identity[0] = (byte) 0xc0;
        BbsPublicKey identityKey = new BbsPublicKey(g2Identity, BbsCiphersuite.BLS12381_SHA256);
        assertThrows(IllegalArgumentException.class,
                () -> BbsToCardano.verifierParams(identityKey, HEADER, MESSAGES.size()),
                "verifierParams must reject compressed G2 identity public key");

        byte[] malformed = new byte[96];
        malformed[0] = (byte) 0x80; // compressed zero x is not on G2 twist
        BbsPublicKey offCurveKey = new BbsPublicKey(malformed, BbsCiphersuite.BLS12381_SHA256);
        assertThrows(IllegalArgumentException.class,
                () -> BbsToCardano.verifierParams(offCurveKey, HEADER, MESSAGES.size()),
                "verifierParams must reject off-curve public key");

        BbsKeyPair shakeKp = BbsService.pureJava(BbsCiphersuite.BLS12381_SHAKE256)
                .keyPair(new byte[32], "shake".getBytes(StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class,
                () -> BbsToCardano.verifierParams(shakeKp.publicKey(), HEADER, MESSAGES.size()),
                "verifierParams must reject ciphersuite mismatch");
    }

    @Test
    void onChainProof_rejectsWrongSuiteAndZeroScalarProof() {
        BbsService shakeBbs = BbsService.pureJava(BbsCiphersuite.BLS12381_SHAKE256);
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 9);
        BbsKeyPair shakeKp = shakeBbs.keyPair(seed, "shake".getBytes(StandardCharsets.UTF_8));
        BbsSignature shakeSig = shakeBbs.sign(shakeKp.secretKey(), shakeKp.publicKey(), MESSAGES, HEADER);
        BbsPresentation shakePres = shakeBbs.derivePresentation(
                shakeKp.publicKey(), shakeSig, MESSAGES, HEADER, "ph".getBytes(StandardCharsets.UTF_8), new int[]{2, 3});
        assertThrows(IllegalArgumentException.class,
                () -> BbsToCardano.onChainProof(shakePres),
                "onChainProof must reject presentation from different ciphersuite");

        BbsKeyPair kp = keyPair();
        BbsSignature sig = BBS.sign(kp.secretKey(), kp.publicKey(), MESSAGES, HEADER);
        BbsPresentation pres = BBS.derivePresentation(
                kp.publicKey(), sig, MESSAGES, HEADER, "ph".getBytes(StandardCharsets.UTF_8), new int[]{2, 3});
        byte[] zeroScalarProof = pres.proof().bytes();
        // Zero out eHat (first 32-byte scalar after 3 * 48 = 144 point bytes)
        Arrays.fill(zeroScalarProof, 144, 176, (byte) 0);
        BbsPresentation badPres = new BbsPresentation(
                new BbsProof(zeroScalarProof, BbsCiphersuite.BLS12381_SHA256),
                pres.header(), pres.presentationHeader(), pres.revealedMessages());
        assertThrows(IllegalArgumentException.class,
                () -> BbsToCardano.onChainProof(badPres),
                "onChainProof must reject proof with zero scalar");
    }
}
