package org.zeroj.onchain.julc.bbs;

import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.TxOutRef;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.TestDataBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zeroj.bbs.BbsKeyPair;
import org.zeroj.bbs.BbsPresentation;
import org.zeroj.bbs.BbsService;
import org.zeroj.bbs.BbsSignature;
import org.zeroj.bbs.cardano.BbsToCardano;
import org.zeroj.bbs.internal.BbsCodec;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.Bls12381Hash;
import org.zeroj.bls12381.ec.G1Point;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Differential and adversarial VM tests for on-chain BBS {@code ProofVerify} (ADR-0064):
 *
 * <ul>
 *   <li>Accepts a real 5-attribute presentation disclosing indexes {@code {2, 3}} within ExUnits bounds.</li>
 *   <li>Rejects both the <b>all-zero</b> and <b>all-non-zero</b> identity-point forgery variants
 *       (zero-credential attack with {@code Abar = Bbar = O}, {@code D = Bv}, {@code r3Hat = r - c}).</li>
 *   <li>Rejects individual identity proof points ({@code Abar = O}, {@code Bbar = O}, {@code D = O}).</li>
 *   <li>Rejects zero, negative, {@code r}, and {@code s ± r} scalars in every one of the 7 proof-scalar
 *       slots ({@code eHat, r1Hat, r3Hat, mHat0, mHat1, mHat2, c}) per draft-10 §4.2.4.5.</li>
 *   <li>Rejects malformed G1 encodings (non-canonical infinity {@code 0xe0‖0^47}, cleared compression
 *       bit, wrong lengths).</li>
 *   <li>Rejects {@code W = G2_INFINITY}, {@code W / domain} mismatch, and {@code domain >= r}.</li>
 * </ul>
 */
class BbsProofVerifyVmTest extends ContractTest {

    private static final BigInteger R = G1Point.R;
    private static final BbsService BBS = BbsService.pureJava();
    private static final byte[] HEADER = "reusable-kyc/v1|issuer=kyc-provider-1".getBytes(StandardCharsets.UTF_8);
    private static final List<byte[]> MESSAGES = List.of(
            "Alice Example".getBytes(StandardCharsets.UTF_8),   // 0 givenName
            "1990-05-01".getBytes(StandardCharsets.UTF_8),      // 1 dob
            "USA".getBytes(StandardCharsets.UTF_8),             // 2 country
            "verified".getBytes(StandardCharsets.UTF_8),        // 3 kycLevel
            "9f86d081".getBytes(StandardCharsets.UTF_8));       // 4 docHash

    private static Program unappliedProgram;
    private static Program program;
    private static BbsToCardano.VerifierParams params;
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

        params = BbsToCardano.verifierParams(kp.publicKey(), HEADER, MESSAGES.size());
        proof = BbsToCardano.onChainProof(presentation);

        unappliedProgram = new BbsProofVerifyVmTest()
                .compileValidator(BbsProofVerifyProbe.class, Path.of("src/test/java")).program();
        program = applyParams(unappliedProgram, params.publicKey(), params.domain());
    }

    @Test
    void onchain_proof_verify_accepts_real_presentation() {
        var result = evaluate(program, ctx(honestClaim(proof.presentationHeader())));
        assertSuccess(result);
        System.out.println("[BbsProofVerify on-chain] budget consumed: " + result.budgetConsumed());
        // ADR-0064 I5: pre-fix Julc pre22 baseline is 2,434,070,891 CPU / 170,454 mem;
        // hardened verifier measures 2,442,385,555 CPU (+0.34%) / 207,274 mem (+21.6%, ~1.48% of 14M tx limit).
        assertTrue(result.budgetConsumed().cpuSteps() <= 2_460_000_000L,
                "CPU steps regressed past ADR-0064 I5 ceiling (2.46B): " + result.budgetConsumed());
        assertTrue(result.budgetConsumed().memoryUnits() <= 215_000L,
                "Memory units regressed past ADR-0064 I5 ceiling (215k): " + result.budgetConsumed());
    }

    @Test
    void tampered_presentation_header_is_rejected() {
        assertFailure(evaluate(program, ctx(honestClaim("a-different-header".getBytes(StandardCharsets.UTF_8)))));
    }

    @Test
    void identity_point_forgery_all_zero_scalars_is_rejected() {
        PlutusData forged = buildIdentityPointForgery(
                BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO,
                "attacker-country".getBytes(StandardCharsets.UTF_8),
                "attacker-kyc".getBytes(StandardCharsets.UTF_8),
                "attacker-session".getBytes(StandardCharsets.UTF_8));
        var result = evaluate(program, ctx(forged));
        assertFailure(result);
        assertTrue(result.budgetConsumed().cpuSteps() < 100_000_000L,
                "Forged zero-scalar redeemer must fail fast before curve ops: " + result.budgetConsumed());
    }

    @Test
    void identity_point_forgery_all_nonzero_scalars_is_rejected() {
        // ADR-0064 critical regression: all 7 scalars are strictly in [1, r - 1], so a fix that only
        // rejects zero scalars would still accept this forgery. Identity-point rejection must stop it.
        PlutusData forged = buildIdentityPointForgery(
                BigInteger.valueOf(7), BigInteger.valueOf(11),
                BigInteger.valueOf(13), BigInteger.valueOf(17), BigInteger.valueOf(19),
                "USA".getBytes(StandardCharsets.UTF_8),
                "verified".getBytes(StandardCharsets.UTF_8),
                "forged-session-nonzero".getBytes(StandardCharsets.UTF_8));
        var result = evaluate(program, ctx(forged));
        assertFailure(result);
        assertTrue(result.budgetConsumed().cpuSteps() < 100_000_000L,
                "Forged identity-point redeemer must fail fast before curve ops: " + result.budgetConsumed());
    }

    @Test
    void individual_identity_proof_points_are_rejected() {
        byte[] g1Identity = g1IdentityBytes();
        assertFailure(evaluate(program, ctx(claimWithPoints(g1Identity, proof.bBar(), proof.d()))));
        assertFailure(evaluate(program, ctx(claimWithPoints(proof.aBar(), g1Identity, proof.d()))));
        assertFailure(evaluate(program, ctx(claimWithPoints(proof.aBar(), proof.bBar(), g1Identity))));
    }

    @Test
    void zero_negative_and_out_of_range_scalars_are_rejected_in_every_slot() {
        BigInteger[] base = {
                proof.eHat(), proof.r1Hat(), proof.r3Hat(),
                proof.mHats().get(0), proof.mHats().get(1), proof.mHats().get(2),
                proof.challenge()
        };
        for (int slot = 0; slot < base.length; slot++) {
            BigInteger valid = base[slot];
            BigInteger[] badValues = {
                    BigInteger.ZERO,
                    BigInteger.ONE.negate(),
                    valid.subtract(R),
                    R,
                    valid.add(R)
            };
            for (BigInteger bad : badValues) {
                BigInteger[] mutated = base.clone();
                mutated[slot] = bad;
                var result = evaluate(program, ctx(claimWithScalars(mutated)));
                assertFailure(result);
                assertTrue(result.budgetConsumed().cpuSteps() < 100_000_000L,
                        "Out-of-range scalar at slot " + slot + " must fail fast: " + result.budgetConsumed());
            }
        }
    }

    @Test
    void malformed_point_encodings_are_rejected() {
        byte[] nonCanonicalInfinity = g1IdentityBytes();
        nonCanonicalInfinity[0] = (byte) 0xe0; // infinity flag + sort bit set
        assertFailure(evaluate(program, ctx(claimWithPoints(nonCanonicalInfinity, proof.bBar(), proof.d()))));

        byte[] clearedCompressionBit = proof.aBar().clone();
        clearedCompressionBit[0] &= 0x7f;
        assertFailure(evaluate(program, ctx(claimWithPoints(clearedCompressionBit, proof.bBar(), proof.d()))));

        assertFailure(evaluate(program, ctx(claimWithPoints(Arrays.copyOf(proof.aBar(), 47), proof.bBar(), proof.d()))));
        assertFailure(evaluate(program, ctx(claimWithPoints(Arrays.copyOf(proof.aBar(), 49), proof.bBar(), proof.d()))));
    }

    @Test
    void identity_issuer_key_and_domain_mismatch_and_oversized_domain_are_rejected() {
        byte[] g2Identity = new byte[96];
        g2Identity[0] = (byte) 0xc0;
        Program identityIssuerProgram = applyParams(unappliedProgram, g2Identity, params.domain());
        assertFailure(evaluate(identityIssuerProgram, ctx(honestClaim(proof.presentationHeader()))));

        // Mismatched W / domain: issuer A's W paired with a domain computed for a different header.
        byte[] otherSeed = new byte[32];
        Arrays.fill(otherSeed, (byte) 13);
        BbsKeyPair otherIssuer = BBS.keyPair(otherSeed, "other-issuer".getBytes(StandardCharsets.UTF_8));
        var otherParams = BbsToCardano.verifierParams(otherIssuer.publicKey(), HEADER, MESSAGES.size());
        Program mismatchedDomainProgram = applyParams(unappliedProgram, params.publicKey(), otherParams.domain());
        assertFailure(evaluate(mismatchedDomainProgram, ctx(honestClaim(proof.presentationHeader()))));

        // Out-of-range domain == r.
        byte[] rBytes = new byte[32];
        byte[] rRaw = R.toByteArray();
        System.arraycopy(rRaw, Math.max(0, rRaw.length - 32), rBytes,
                32 - Math.min(32, rRaw.length), Math.min(32, rRaw.length));
        Program oversizedDomainProgram = applyParams(unappliedProgram, params.publicKey(), rBytes);
        assertFailure(evaluate(oversizedDomainProgram, ctx(honestClaim(proof.presentationHeader()))));
    }

    /**
     * Constructs the ADR-0064 identity-point forgery for arbitrary {@code eHat, r1Hat, mHat0..2},
     * {@code msg2, msg3}, and {@code ph} using only public validator parameters.
     */
    private static PlutusData buildIdentityPointForgery(
            BigInteger eHat, BigInteger r1Hat,
            BigInteger mHat0, BigInteger mHat1, BigInteger mHat2,
            byte[] msg2, byte[] msg3, byte[] ph) {
        byte[] g1Identity = g1IdentityBytes();
        BigInteger domain = new BigInteger(1, params.domain());

        BigInteger s2 = Bls12381Hash.hashToScalar(msg2, params.dstMapToScalar());
        BigInteger s3 = Bls12381Hash.hashToScalar(msg3, params.dstMapToScalar());

        G1Point p1 = Bls12381Codecs.g1FromCompressed(params.p1());
        G1Point q1 = Bls12381Codecs.g1FromCompressed(params.q1());
        G1Point h0 = Bls12381Codecs.g1FromCompressed(params.h().get(0));
        G1Point h1 = Bls12381Codecs.g1FromCompressed(params.h().get(1));
        G1Point h2 = Bls12381Codecs.g1FromCompressed(params.h().get(2));
        G1Point h3 = Bls12381Codecs.g1FromCompressed(params.h().get(3));
        G1Point h4 = Bls12381Codecs.g1FromCompressed(params.h().get(4));

        G1Point bv = p1.add(q1.scalarMul(domain)).add(h2.scalarMul(s2)).add(h3.scalarMul(s3));
        byte[] dBytes = Bls12381Codecs.g1ToCompressed(bv);

        // With Abar = Bbar = O and D = Bv, T1 = r1Hat * D and (setting r3Hat = r - c) T2 = sum(mHat_j * H_j).
        G1Point t1 = bv.scalarMul(r1Hat);
        G1Point t2 = h0.scalarMul(mHat0).add(h1.scalarMul(mHat1)).add(h4.scalarMul(mHat2));

        byte[] cInput = BbsCodec.concat(
                BbsCodec.serialize(
                        2L, 2L, s2, 3L, s3,
                        G1Point.INFINITY, G1Point.INFINITY, bv, t1, t2, domain),
                BbsCodec.i2osp(ph.length, 8),
                ph);
        BigInteger c = Bls12381Hash.hashToScalar(cInput, params.dstHashToScalar());
        BigInteger r3Hat = R.subtract(c).mod(R);

        return PlutusData.constr(0,
                PlutusData.bytes(g1Identity), PlutusData.bytes(g1Identity), PlutusData.bytes(dBytes),
                PlutusData.integer(eHat), PlutusData.integer(r1Hat), PlutusData.integer(r3Hat),
                PlutusData.integer(mHat0), PlutusData.integer(mHat1), PlutusData.integer(mHat2),
                PlutusData.integer(c),
                PlutusData.bytes(msg2), PlutusData.bytes(msg3), PlutusData.bytes(ph));
    }

    private static byte[] g1IdentityBytes() {
        byte[] id = new byte[48];
        id[0] = (byte) 0xc0;
        return id;
    }

    private static Program applyParams(Program base, byte[] wBytes, byte[] domainBytes) {
        return base.applyParams(
                PlutusData.bytes(wBytes),
                PlutusData.bytes(params.g2Generator()),
                PlutusData.bytes(params.p1()),
                PlutusData.bytes(params.q1()),
                PlutusData.bytes(params.h().get(0)), PlutusData.bytes(params.h().get(1)),
                PlutusData.bytes(params.h().get(2)), PlutusData.bytes(params.h().get(3)),
                PlutusData.bytes(params.h().get(4)),
                PlutusData.bytes(domainBytes),
                PlutusData.bytes(params.dstHashToScalar()),
                PlutusData.bytes(params.dstMapToScalar()));
    }

    private PlutusData honestClaim(byte[] ph) {
        return PlutusData.constr(0,
                PlutusData.bytes(proof.aBar()), PlutusData.bytes(proof.bBar()), PlutusData.bytes(proof.d()),
                PlutusData.integer(proof.eHat()), PlutusData.integer(proof.r1Hat()), PlutusData.integer(proof.r3Hat()),
                PlutusData.integer(proof.mHats().get(0)), PlutusData.integer(proof.mHats().get(1)),
                PlutusData.integer(proof.mHats().get(2)), PlutusData.integer(proof.challenge()),
                PlutusData.bytes(proof.disclosed().get(0).message()),
                PlutusData.bytes(proof.disclosed().get(1).message()),
                PlutusData.bytes(ph));
    }

    private PlutusData claimWithPoints(byte[] abar, byte[] bbar, byte[] d) {
        return PlutusData.constr(0,
                PlutusData.bytes(abar), PlutusData.bytes(bbar), PlutusData.bytes(d),
                PlutusData.integer(proof.eHat()), PlutusData.integer(proof.r1Hat()), PlutusData.integer(proof.r3Hat()),
                PlutusData.integer(proof.mHats().get(0)), PlutusData.integer(proof.mHats().get(1)),
                PlutusData.integer(proof.mHats().get(2)), PlutusData.integer(proof.challenge()),
                PlutusData.bytes(proof.disclosed().get(0).message()),
                PlutusData.bytes(proof.disclosed().get(1).message()),
                PlutusData.bytes(proof.presentationHeader()));
    }

    private PlutusData claimWithScalars(BigInteger[] s) {
        return PlutusData.constr(0,
                PlutusData.bytes(proof.aBar()), PlutusData.bytes(proof.bBar()), PlutusData.bytes(proof.d()),
                PlutusData.integer(s[0]), PlutusData.integer(s[1]), PlutusData.integer(s[2]),
                PlutusData.integer(s[3]), PlutusData.integer(s[4]), PlutusData.integer(s[5]),
                PlutusData.integer(s[6]),
                PlutusData.bytes(proof.disclosed().get(0).message()),
                PlutusData.bytes(proof.disclosed().get(1).message()),
                PlutusData.bytes(proof.presentationHeader()));
    }

    private PlutusData ctx(PlutusData redeemer) {
        TxOutRef ref = TestDataBuilder.randomTxOutRef_typed();
        return spendingContext(ref, PlutusData.integer(0)).redeemer(redeemer).buildPlutusData();
    }
}
