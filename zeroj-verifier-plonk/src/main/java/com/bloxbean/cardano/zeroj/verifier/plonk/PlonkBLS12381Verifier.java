package com.bloxbean.cardano.zeroj.verifier.plonk;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.BackendDescriptor;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.field.*;

import java.math.BigInteger;
import java.util.List;

/**
 * Pure Java PlonK verifier for BLS12-381 — no native dependencies.
 *
 * <p>Uses the pure Java BLS12-381 field arithmetic and pairing implementation
 * in {@link com.bloxbean.cardano.zeroj.verifier.plonk.bls12381}.</p>
 *
 * <p>Implements the snarkjs PlonK verification algorithm:
 * <ol>
 *   <li>Re-derive Fiat-Shamir challenges (beta, gamma, alpha, zeta, v, u)</li>
 *   <li>Evaluate vanishing polynomial Z_H(zeta) = zeta^n - 1</li>
 *   <li>Evaluate Lagrange polynomial L1(zeta)</li>
 *   <li>Compute the public input polynomial at zeta</li>
 *   <li>Compute the linearized commitment</li>
 *   <li>Perform KZG batch opening verification via pairing</li>
 * </ol>
 */
public class PlonkBLS12381Verifier implements ZkVerifier {

    private static final BackendDescriptor DESCRIPTOR =
            new BackendDescriptor(ProofSystemId.PLONK, CurveId.BLS12_381, "plonk-bls12381-java");

    private static final BigInteger Fr = G1Point.R;

    @Override
    public BackendDescriptor descriptor() {
        return DESCRIPTOR;
    }

    @Override
    public VerificationResult verify(ZkProofEnvelope envelope, VerificationMaterial material) {
        try {
            var proofJson = new String(envelope.proofBytes());
            var vkJson = new String(material.vkBytes());

            var sp = com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkCodec.parseProof(proofJson);
            var sv = com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkCodec.parseVerificationKey(vkJson);

            var proof = new PlonkProof(
                    sp.A(), sp.B(), sp.C(), sp.Z(),
                    sp.T1(), sp.T2(), sp.T3(),
                    sp.evalA(), sp.evalB(), sp.evalC(),
                    sp.evalS1(), sp.evalS2(), sp.evalZw(),
                    sp.Wxi(), sp.Wxiw());
            var vk = new PlonkVerificationKey(
                    sv.nPublic(), sv.domainSize(), sv.w(),
                    sv.Ql(), sv.Qr(), sv.Qo(), sv.Qm(), sv.Qc(),
                    sv.S1(), sv.S2(), sv.S3(),
                    sv.X_2(), sv.k1(), sv.k2(),
                    sv.protocol(), sv.curve());

            var publicInputs = envelope.publicInputs();
            if (publicInputs.size() != vk.nPublic()) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS,
                        "Expected " + vk.nPublic() + " public inputs, got " + publicInputs.size());
            }

            int n = vk.domainSize();
            BigInteger omega = vk.omega();

            // Step 1: Fiat-Shamir challenges
            var transcript = new FiatShamirTranscript(Fr);
            appendG1(transcript, proof.cmA());
            appendG1(transcript, proof.cmB());
            appendG1(transcript, proof.cmC());
            BigInteger beta = transcript.squeezeNonZeroChallenge();
            BigInteger gamma = transcript.squeezeNonZeroChallenge();

            appendG1(transcript, proof.cmZ());
            BigInteger alpha = transcript.squeezeNonZeroChallenge();

            appendG1(transcript, proof.cmT1());
            appendG1(transcript, proof.cmT2());
            appendG1(transcript, proof.cmT3());
            BigInteger zeta = transcript.squeezeNonZeroChallenge();

            transcript.appendScalar(proof.evalA());
            transcript.appendScalar(proof.evalB());
            transcript.appendScalar(proof.evalC());
            transcript.appendScalar(proof.evalS1());
            transcript.appendScalar(proof.evalS2());
            transcript.appendScalar(proof.evalZOmega());
            BigInteger v = transcript.squeezeNonZeroChallenge();

            appendG1(transcript, proof.wZeta());
            appendG1(transcript, proof.wZetaOmega());
            BigInteger u = transcript.squeezeNonZeroChallenge();

            // Step 2: Z_H(zeta) = zeta^n - 1
            BigInteger zetaPowN = zeta.modPow(BigInteger.valueOf(n), Fr);
            BigInteger zh = zetaPowN.subtract(BigInteger.ONE).mod(Fr);

            // Step 3: L1(zeta)
            BigInteger nInv = BigInteger.valueOf(n).modInverse(Fr);
            BigInteger l1 = zh.multiply(nInv).mod(Fr)
                    .multiply(zeta.subtract(BigInteger.ONE).mod(Fr).modInverse(Fr)).mod(Fr);

            // Step 4: PI(zeta)
            BigInteger pi = BigInteger.ZERO;
            for (int i = 0; i < publicInputs.size(); i++) {
                BigInteger omegaI = omega.modPow(BigInteger.valueOf(i), Fr);
                BigInteger li = zh.multiply(nInv).mod(Fr)
                        .multiply(omegaI).mod(Fr)
                        .multiply(zeta.subtract(omegaI).mod(Fr).modInverse(Fr)).mod(Fr);
                pi = pi.add(publicInputs.get(i).multiply(li).mod(Fr)).mod(Fr);
            }

            // Step 5: r0 (linearized polynomial evaluation)
            BigInteger a = proof.evalA(), b = proof.evalB(), c = proof.evalC();
            BigInteger s1Eval = proof.evalS1(), s2Eval = proof.evalS2();
            BigInteger zOmega = proof.evalZOmega();

            BigInteger r0 = pi.subtract(l1.multiply(alpha).mod(Fr).multiply(alpha).mod(Fr)).mod(Fr);

            BigInteger perm = a.add(beta.multiply(s1Eval).mod(Fr)).add(gamma).mod(Fr);
            perm = perm.multiply(b.add(beta.multiply(s2Eval).mod(Fr)).add(gamma).mod(Fr)).mod(Fr);
            perm = perm.multiply(c.add(gamma).mod(Fr)).mod(Fr);
            perm = perm.multiply(zOmega).mod(Fr);
            perm = perm.multiply(alpha).mod(Fr);
            r0 = r0.subtract(perm).mod(Fr);

            // Step 6: Linearized commitment and pairing — pure Java G1/G2 arithmetic
            G1Point wZetaPt = toG1(proof.wZeta());
            G1Point wZetaOmegaPt = toG1(proof.wZetaOmega());

            // LHS = [W_zeta] + u * [W_zeta_omega]
            G1Point lhsG1 = wZetaPt.add(wZetaOmegaPt.scalarMul(u));

            // RHS base = zeta * [W_zeta] + u*zeta*omega * [W_zeta_omega]
            BigInteger zetaOmega = zeta.multiply(omega).mod(Fr);
            G1Point rhsBase = wZetaPt.scalarMul(zeta).add(wZetaOmegaPt.scalarMul(u.multiply(zetaOmega).mod(Fr)));

            // Linearized commitment [F]
            BigInteger k1 = vk.k1(), k2 = vk.k2();

            // Gate: a*[qL] + b*[qR] + c*[qO] + a*b*[qM] + [qC]
            G1Point fGate = toG1(vk.qL()).scalarMul(a)
                    .add(toG1(vk.qR()).scalarMul(b))
                    .add(toG1(vk.qO()).scalarMul(c))
                    .add(toG1(vk.qM()).scalarMul(a.multiply(b).mod(Fr)))
                    .add(toG1(vk.qC()));

            // Permutation Z coefficient
            BigInteger permZ = a.add(beta.multiply(zeta).mod(Fr)).add(gamma).mod(Fr);
            permZ = permZ.multiply(b.add(beta.multiply(k1).mod(Fr).multiply(zeta).mod(Fr)).add(gamma).mod(Fr)).mod(Fr);
            permZ = permZ.multiply(c.add(beta.multiply(k2).mod(Fr).multiply(zeta).mod(Fr)).add(gamma).mod(Fr)).mod(Fr);
            permZ = permZ.multiply(alpha).mod(Fr);
            permZ = permZ.add(alpha.multiply(alpha).mod(Fr).multiply(l1).mod(Fr)).mod(Fr);
            G1Point fPerm = toG1(proof.cmZ()).scalarMul(permZ);

            // Permutation sigma3 coefficient
            BigInteger permS3 = a.add(beta.multiply(s1Eval).mod(Fr)).add(gamma).mod(Fr);
            permS3 = permS3.multiply(b.add(beta.multiply(s2Eval).mod(Fr)).add(gamma).mod(Fr)).mod(Fr);
            permS3 = permS3.multiply(alpha).mod(Fr).multiply(beta).mod(Fr).multiply(zOmega).mod(Fr);
            G1Point fS3 = toG1(vk.s3()).scalarMul(permS3);

            // Quotient: zh * ([t1] + zeta^n*[t2] + zeta^(2n)*[t3])
            G1Point fQuotient = toG1(proof.cmT1())
                    .add(toG1(proof.cmT2()).scalarMul(zetaPowN))
                    .add(toG1(proof.cmT3()).scalarMul(zetaPowN.multiply(zetaPowN).mod(Fr)));
            fQuotient = fQuotient.scalarMul(zh);

            // [F] = fGate + fPerm - fS3 - fQuotient
            G1Point fCommit = fGate.add(fPerm).add(fS3.negate()).add(fQuotient.negate());

            // RHS = rhsBase + [F] - r0 * G1_generator
            // We need the G1 generator; for BLS12-381 it's a well-known point
            G1Point g1Gen = BLS12381_G1_GENERATOR;
            G1Point rhsG1 = rhsBase.add(fCommit).add(g1Gen.scalarMul(r0).negate());

            // G2 points: [x]_2 from VK, G2 generator
            G2Point x2Pt = toG2(vk.x2());
            G2Point g2Gen = BLS12381_G2_GENERATOR;

            // Pairing check: e(lhsG1, x2) * e(-rhsG1, g2Gen) == 1
            boolean valid = BLS12381Pairing.pairingCheck(
                    new G1Point[]{lhsG1, rhsG1.negate()},
                    new G2Point[]{x2Pt, g2Gen});

            return valid ? VerificationResult.cryptoValid()
                    : VerificationResult.proofInvalid("PlonK BLS12-381 pairing check failed");

        } catch (Exception e) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.INTERNAL_ERROR,
                    "PlonK BLS12-381 verification error: " + e.getMessage());
        }
    }

    // --- BLS12-381 generator points ---

    /** BLS12-381 G1 generator. */
    private static final G1Point BLS12381_G1_GENERATOR = new G1Point(
            Fp.of(new BigInteger("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", 16)),
            Fp.of(new BigInteger("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", 16))
    );

    /** BLS12-381 G2 generator. */
    private static final G2Point BLS12381_G2_GENERATOR = new G2Point(
            Fp2.of(
                    Fp.of(new BigInteger("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8", 16)),
                    Fp.of(new BigInteger("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e", 16))
            ),
            Fp2.of(
                    Fp.of(new BigInteger("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801", 16)),
                    Fp.of(new BigInteger("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be", 16))
            )
    );

    // --- Helpers ---

    private void appendG1(FiatShamirTranscript transcript, List<BigInteger> point) {
        if (point.size() >= 2) transcript.appendG1Point(point.get(0), point.get(1));
    }

    private G1Point toG1(List<BigInteger> coords) {
        BigInteger z = coords.size() > 2 ? coords.get(2) : BigInteger.ONE;
        return G1Point.fromProjective(coords.get(0), coords.get(1), z);
    }

    private G2Point toG2(List<List<BigInteger>> coords) {
        var z = coords.size() > 2 ? coords.get(2) : List.of(BigInteger.ONE, BigInteger.ZERO);
        return G2Point.fromProjective(
                coords.get(0).get(0), coords.get(0).get(1),
                coords.get(1).get(0), coords.get(1).get(1),
                z.get(0), z.get(1));
    }
}
