package com.bloxbean.cardano.zeroj.verifier.plonk;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.BackendDescriptor;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import com.bloxbean.cardano.zeroj.bls12381.ec.*;
import com.bloxbean.cardano.zeroj.bls12381.field.*;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.crypto.transcript.FiatShamirTranscript;

import java.math.BigInteger;
import java.util.List;

/**
 * Pure Java PlonK verifier for BLS12-381 — no native dependencies.
 *
 * <p>Uses the pure Java BLS12-381 field arithmetic and pairing implementation
 * from {@code zeroj-bls12381}.</p>
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
            if (envelope.proofFormat().filter("gnark-plonk-json"::equals).isPresent()) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.UNSUPPORTED_PROOF_SYSTEM,
                        "gnark binary PlonK JSON is not accepted by the snarkjs/ZeroJ structured PlonK verifier");
            }

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

            // Step 1: Fiat-Shamir challenges. This mirrors the BLS12-381 prover
            // and BN254 verifier transcript round boundaries.
            G1Point A = toG1(proof.cmA()), B = toG1(proof.cmB()), C = toG1(proof.cmC());
            G1Point Z = toG1(proof.cmZ());
            G1Point T1 = toG1(proof.cmT1()), T2 = toG1(proof.cmT2()), T3 = toG1(proof.cmT3());
            G1Point Wxi = toG1(proof.wZeta()), Wxiw = toG1(proof.wZetaOmega());

            G1Point Qm = toG1(vk.qM()), Ql = toG1(vk.qL()), Qr = toG1(vk.qR());
            G1Point Qo = toG1(vk.qO()), Qc = toG1(vk.qC());
            G1Point S1 = toG1(vk.s1()), S2 = toG1(vk.s2()), S3 = toG1(vk.s3());
            G2Point X_2 = toG2(vk.x2());

            var transcript = new FiatShamirTranscript(Fr, 32, 48);
            addG1(transcript, Qm); addG1(transcript, Ql); addG1(transcript, Qr);
            addG1(transcript, Qo); addG1(transcript, Qc);
            addG1(transcript, S1); addG1(transcript, S2); addG1(transcript, S3);
            for (int i = 0; i < publicInputs.size(); i++) {
                transcript.addScalar(publicInputs.get(i));
            }
            addG1(transcript, A); addG1(transcript, B); addG1(transcript, C);
            BigInteger beta = transcript.getChallenge();

            transcript.reset();
            transcript.addScalar(beta);
            BigInteger gamma = transcript.getChallenge();

            transcript.reset();
            transcript.addScalar(beta);
            transcript.addScalar(gamma);
            addG1(transcript, Z);
            BigInteger alpha = transcript.getChallenge();

            transcript.reset();
            transcript.addScalar(alpha);
            addG1(transcript, T1); addG1(transcript, T2); addG1(transcript, T3);
            BigInteger xi = transcript.getChallenge();

            BigInteger eval_a = proof.evalA(), eval_b = proof.evalB(), eval_c = proof.evalC();
            BigInteger eval_s1 = proof.evalS1(), eval_s2 = proof.evalS2(), eval_zw = proof.evalZOmega();

            transcript.reset();
            transcript.addScalar(xi);
            transcript.addScalar(eval_a); transcript.addScalar(eval_b); transcript.addScalar(eval_c);
            transcript.addScalar(eval_s1); transcript.addScalar(eval_s2); transcript.addScalar(eval_zw);
            BigInteger v1 = transcript.getChallenge();
            BigInteger v2 = v1.multiply(v1).mod(Fr);
            BigInteger v3 = v2.multiply(v1).mod(Fr);
            BigInteger v4 = v3.multiply(v1).mod(Fr);
            BigInteger v5 = v4.multiply(v1).mod(Fr);

            transcript.reset();
            addG1(transcript, Wxi); addG1(transcript, Wxiw);
            BigInteger u = transcript.getChallenge();

            // Step 2: Z_H(xi) = xi^n - 1
            int power = Integer.numberOfTrailingZeros(n);
            BigInteger xin = xi;
            for (int i = 0; i < power; i++) {
                xin = xin.multiply(xin).mod(Fr);
            }
            BigInteger zh = xin.subtract(BigInteger.ONE).mod(Fr);

            // Step 3: Lagrange evaluations for public input positions.
            BigInteger nBI = BigInteger.valueOf(n);
            BigInteger l1 = zh.multiply(nBI.multiply(xi.subtract(BigInteger.ONE).mod(Fr)).mod(Fr).modInverse(Fr)).mod(Fr);

            // Step 4: PI(xi). Public inputs are subtracted, matching the prover's
            // PI polynomial where PI(omega^i) = -public_i.
            BigInteger pi = BigInteger.ZERO;
            BigInteger wPow = BigInteger.ONE;
            for (int i = 0; i < publicInputs.size(); i++) {
                BigInteger li = wPow.multiply(zh).mod(Fr)
                        .multiply(nBI.multiply(xi.subtract(wPow).mod(Fr)).mod(Fr).modInverse(Fr)).mod(Fr);
                pi = pi.subtract(publicInputs.get(i).multiply(li).mod(Fr)).mod(Fr);
                wPow = wPow.multiply(omega).mod(Fr);
            }

            // Step 5: r0
            BigInteger alpha2 = alpha.multiply(alpha).mod(Fr);
            BigInteger e1 = pi;
            BigInteger e2 = l1.multiply(alpha2).mod(Fr);
            BigInteger e3a = eval_a.add(beta.multiply(eval_s1).mod(Fr)).add(gamma).mod(Fr);
            BigInteger e3b = eval_b.add(beta.multiply(eval_s2).mod(Fr)).add(gamma).mod(Fr);
            BigInteger e3c = eval_c.add(gamma).mod(Fr);
            BigInteger e3 = e3a.multiply(e3b).mod(Fr).multiply(e3c).mod(Fr)
                    .multiply(eval_zw).mod(Fr).multiply(alpha).mod(Fr);
            BigInteger r0 = e1.subtract(e2).mod(Fr).subtract(e3).mod(Fr);

            // Step 6: Linearized commitment and pairing.
            BigInteger k1 = vk.k1(), k2 = vk.k2();

            G1Point d1 = Qm.scalarMul(eval_a.multiply(eval_b).mod(Fr))
                    .add(Ql.scalarMul(eval_a))
                    .add(Qr.scalarMul(eval_b))
                    .add(Qo.scalarMul(eval_c))
                    .add(Qc);

            BigInteger betaxi = beta.multiply(xi).mod(Fr);
            BigInteger d2a = eval_a.add(betaxi).add(gamma).mod(Fr)
                    .multiply(eval_b.add(betaxi.multiply(k1).mod(Fr)).add(gamma).mod(Fr)).mod(Fr)
                    .multiply(eval_c.add(betaxi.multiply(k2).mod(Fr)).add(gamma).mod(Fr)).mod(Fr)
                    .multiply(alpha).mod(Fr);
            BigInteger d2b = l1.multiply(alpha2).mod(Fr);
            G1Point d2 = Z.scalarMul(d2a.add(d2b).add(u).mod(Fr));

            BigInteger d3s = eval_a.add(beta.multiply(eval_s1).mod(Fr)).add(gamma).mod(Fr)
                    .multiply(eval_b.add(beta.multiply(eval_s2).mod(Fr)).add(gamma).mod(Fr)).mod(Fr)
                    .multiply(alpha.multiply(beta).mod(Fr).multiply(eval_zw).mod(Fr)).mod(Fr);
            G1Point d3 = S3.scalarMul(d3s);

            G1Point d4 = T1.add(T2.scalarMul(xin)).add(T3.scalarMul(xin.multiply(xin).mod(Fr))).scalarMul(zh);
            G1Point D = d1.add(d2).add(d3.negate()).add(d4.negate());

            G1Point F = D.add(A.scalarMul(v1)).add(B.scalarMul(v2)).add(C.scalarMul(v3))
                    .add(S1.scalarMul(v4)).add(S2.scalarMul(v5));

            BigInteger eScalar = r0.negate().mod(Fr)
                    .add(v1.multiply(eval_a).mod(Fr))
                    .add(v2.multiply(eval_b).mod(Fr))
                    .add(v3.multiply(eval_c).mod(Fr))
                    .add(v4.multiply(eval_s1).mod(Fr))
                    .add(v5.multiply(eval_s2).mod(Fr))
                    .add(u.multiply(eval_zw).mod(Fr))
                    .mod(Fr);
            G1Point E = BLS12381_G1_GENERATOR.scalarMul(eScalar);

            G1Point B1 = F.add(E.negate())
                    .add(Wxi.scalarMul(xi))
                    .add(Wxiw.scalarMul(u.multiply(xi).mod(Fr).multiply(omega).mod(Fr)));
            G1Point A1 = Wxi.add(Wxiw.scalarMul(u));

            // Pairing check: e(B1, G2) * e(-A1, X_2) == 1
            boolean valid = BLS12381Pairing.pairingCheck(
                    new G1Point[]{B1, A1.negate()},
                    new G2Point[]{BLS12381_G2_GENERATOR, X_2});

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

    private void addG1(FiatShamirTranscript transcript, G1Point point) {
        if (point.isInfinity()) {
            transcript.addPolCommitment(BigInteger.ZERO, BigInteger.ZERO);
        } else {
            transcript.addPolCommitment(point.x().value(), point.y().value());
        }
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
