package com.bloxbean.cardano.zeroj.onchain.julc.bbs.lib;

import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.OnchainLibrary;

import java.math.BigInteger;

/**
 * Reusable on-chain BBS {@code ProofVerify} ({@code BLS12381G1-SHA-256}) — a native Plutus V3 port of
 * the off-chain {@code CfrgBbsCore.coreProofVerify} in {@code zeroj-bbs}. It recomputes {@code T1}/
 * {@code T2}, rebuilds the Fiat–Shamir challenge (serialise + {@link BbsHashToScalar#hashToScalar})
 * and checks it equals the proof's, then does the pairing check {@code e(Abar, W) == e(Bbar, BP2)}.
 *
 * <p><b>Disclosure profile.</b> {@link #verify} is unrolled for a <b>5-message credential disclosing
 * indexes {@code {2, 3}}</b> (undisclosed {@code {0, 1, 4}}) — the common "reveal two attributes of
 * five" shape. The unrolling is deliberate: Plutus has no cheap dynamic loop, so a fixed disclosure
 * shape keeps the ExUnits well inside the per-tx budget (~2.4×10⁹ CPU / ~0.18M mem for this profile).
 * The underlying algorithm is general; other {@code (L, disclosed-set)} shapes compose the same
 * {@link BbsHashToScalar} primitive and the same T1/T2/challenge/pairing structure with a different
 * unrolling. A parameterised, arbitrary-disclosure variant is tracked as follow-up (mirroring how the
 * PlonK verifier grew from one input to a bounded multi-input profile).</p>
 *
 * <p><b>Crypto-only.</b> Like the Groth16/PlonK libs, this verifies the proof but binds no
 * {@code ScriptContext}. A validator protecting value must compose it and add its own policy (disclosed
 * values match, payout, and — critically for replay — binding the presentation header to the spend).
 * See {@code zeroj-usecases} reusable-kyc for a worked claim validator.</p>
 *
 * <p>Verification-key material (issuer PK {@code W}, generators, {@code domain}, DSTs) is baked in by
 * the caller as validator params; the proof + disclosed messages + presentation header come from the
 * redeemer.</p>
 */
@OnchainLibrary
public final class BbsProofVerify {

    private BbsProofVerify() {}

    /**
     * @param w,bp2        issuer public key and the G2 generator (compressed, 96 B)
     * @param p1,q1,h0..h4 ciphersuite P1 + the 6 BBS generators (compressed G1, 48 B)
     * @param domain       precomputed BBS domain scalar (depends only on PK/generators/header)
     * @param dstH2S,dstMap the H2S and message-map domain separation tags
     * @param abar,bbar,d  proof points (compressed G1)
     * @param eHat,r1Hat,r3Hat,mHat0,mHat1,mHat2,c proof responses + challenge (undisclosed indexes 0,1,4)
     * @param msg2,msg3    disclosed message bytes for indexes 2 and 3
     * @param ph           presentation header (binds the presentation to a claim/session)
     */
    public static boolean verify(
            byte[] w, byte[] bp2, byte[] p1, byte[] q1,
            byte[] h0, byte[] h1, byte[] h2, byte[] h3, byte[] h4,
            BigInteger domain, byte[] dstH2S, byte[] dstMap,
            byte[] abar, byte[] bbar, byte[] d,
            BigInteger eHat, BigInteger r1Hat, BigInteger r3Hat,
            BigInteger mHat0, BigInteger mHat1, BigInteger mHat2, BigInteger c,
            byte[] msg2, byte[] msg3, byte[] ph) {

        byte[] abarE = Builtins.bls12_381_G1_uncompress(abar);
        byte[] bbarE = Builtins.bls12_381_G1_uncompress(bbar);
        byte[] dE = Builtins.bls12_381_G1_uncompress(d);

        // T1 = c*Bbar + eHat*Abar + r1Hat*D
        byte[] t1 = g1add(g1add(g1mul(c, bbarE), g1mul(eHat, abarE)), g1mul(r1Hat, dE));

        // disclosed message scalars (map_message_to_scalar_as_hash)
        BigInteger s2 = BbsHashToScalar.hashToScalar(msg2, dstMap);
        BigInteger s3 = BbsHashToScalar.hashToScalar(msg3, dstMap);

        // Bv = P1 + domain*Q1 + s2*H2 + s3*H3
        byte[] bv = g1add(g1add(g1add(
                Builtins.bls12_381_G1_uncompress(p1),
                g1mul(domain, Builtins.bls12_381_G1_uncompress(q1))),
                g1mul(s2, Builtins.bls12_381_G1_uncompress(h2))),
                g1mul(s3, Builtins.bls12_381_G1_uncompress(h3)));

        // T2 = c*Bv + r3Hat*D + mHat0*H0 + mHat1*H1 + mHat2*H4   (undisclosed indexes 0,1,4)
        byte[] t2 = g1add(g1add(g1add(g1add(
                g1mul(c, bv), g1mul(r3Hat, dE)),
                g1mul(mHat0, Builtins.bls12_381_G1_uncompress(h0))),
                g1mul(mHat1, Builtins.bls12_381_G1_uncompress(h1))),
                g1mul(mHat2, Builtins.bls12_381_G1_uncompress(h4)));

        // challenge = hash_to_scalar( serialize([2, 2,s2, 3,s3, Abar,Bbar,D,T1,T2, domain]) || I2OSP(len(ph),8) || ph )
        byte[] disclosed = cat(i8(2L), cat(cat(i8(2L), s32(s2)), cat(i8(3L), s32(s3))));
        byte[] points = cat(cat(cat(cat(cat(cat(abar, bbar), d),
                Builtins.bls12_381_G1_compress(t1)),
                Builtins.bls12_381_G1_compress(t2)),
                s32(domain)), cat(Builtins.integerToByteString(true, 8L, Builtins.lengthOfByteString(ph)), ph));
        BigInteger challenge = BbsHashToScalar.hashToScalar(cat(disclosed, points), dstH2S);
        if (!c.equals(challenge)) {
            return false;
        }

        // e(Abar, W) == e(Bbar, BP2)   (equivalent to e(Abar,W)·e(Bbar,-BP2) == 1)
        return Builtins.bls12_381_finalVerify(
                Builtins.bls12_381_millerLoop(abarE, Builtins.bls12_381_G2_uncompress(w)),
                Builtins.bls12_381_millerLoop(bbarE, Builtins.bls12_381_G2_uncompress(bp2)));
    }

    private static byte[] g1mul(BigInteger scalar, byte[] pointElement) {
        return Builtins.bls12_381_G1_scalarMul(scalar, pointElement);
    }

    private static byte[] g1add(byte[] a, byte[] b) {
        return Builtins.bls12_381_G1_add(a, b);
    }

    private static byte[] cat(byte[] a, byte[] b) {
        return Builtins.appendByteString(a, b);
    }

    /** I2OSP(value, 8) — big-endian, 8 bytes (BBS serialises lengths/indexes this way). */
    private static byte[] i8(long value) {
        return Builtins.integerToByteString(true, 8L, value);
    }

    /** Scalar → 32-byte big-endian (BBS {@code scalar_to_bytes}). */
    private static byte[] s32(BigInteger scalar) {
        return Builtins.integerToByteString(true, 32L, scalar);
    }
}
