package com.bloxbean.cardano.zeroj.verifier.plonk;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.BackendDescriptor;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import com.bloxbean.cardano.zeroj.crypto.transcript.FiatShamirTranscript;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.*;

import java.math.BigInteger;
import java.util.List;

/**
 * Pure Java PlonK verifier for BN254 — snarkjs compatible.
 *
 * <p>Follows the exact snarkjs PlonK verification algorithm from
 * {@code snarkjs/src/plonk_verify.js} including the Keccak-256 Fiat-Shamir transcript.</p>
 */
public class PlonkBN254Verifier implements ZkVerifier {

    private static final BackendDescriptor DESCRIPTOR =
            new BackendDescriptor(ProofSystemId.PLONK, CurveId.BN254, "plonk-bn254-java");

    private static final BigInteger Fr = G1Point.R;

    @Override
    public BackendDescriptor descriptor() { return DESCRIPTOR; }

    @Override
    public VerificationResult verify(ZkProofEnvelope envelope, VerificationMaterial material) {
        if (!LegacyCurvePolicy.legacyBn254Enabled()) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.UNSUPPORTED_CURVE,
                    LegacyCurvePolicy.legacyBn254DisabledMessage());
        }

        try {
            if (envelope.proofFormat().filter("gnark-plonk-json"::equals).isPresent()) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.UNSUPPORTED_PROOF_SYSTEM,
                        "gnark binary PlonK JSON is not accepted by the snarkjs/ZeroJ structured PlonK verifier");
            }

            var sp = com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkCodec.parseProof(new String(envelope.proofBytes()));
            var sv = com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkCodec.parseVerificationKey(new String(material.vkBytes()));

            var publicInputs = envelope.publicInputs();
            if (publicInputs.size() != sv.nPublic()) {
                return VerificationResult.error(VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS,
                        "Expected " + sv.nPublic() + " public inputs, got " + publicInputs.size());
            }

            int power = sv.power();
            int domainSize = sv.domainSize();
            BigInteger omega = sv.w();

            // Parse all points
            G1Point A = toG1(sp.A()), B = toG1(sp.B()), C = toG1(sp.C());
            G1Point Z = toG1(sp.Z());
            G1Point T1 = toG1(sp.T1()), T2 = toG1(sp.T2()), T3 = toG1(sp.T3());
            G1Point Wxi = toG1(sp.Wxi()), Wxiw = toG1(sp.Wxiw());

            G1Point Qm = toG1(sv.Qm()), Ql = toG1(sv.Ql()), Qr = toG1(sv.Qr());
            G1Point Qo = toG1(sv.Qo()), Qc = toG1(sv.Qc());
            G1Point S1 = toG1(sv.S1()), S2 = toG1(sv.S2()), S3 = toG1(sv.S3());
            G2Point X_2 = toG2(sv.X_2());

            BigInteger eval_a = sp.evalA(), eval_b = sp.evalB(), eval_c = sp.evalC();
            BigInteger eval_s1 = sp.evalS1(), eval_s2 = sp.evalS2(), eval_zw = sp.evalZw();
            BigInteger k1 = sv.k1(), k2 = sv.k2();

            // === calculatechallenges (exactly matching snarkjs) ===
            var transcript = new FiatShamirTranscript(Fr, 32, 32);

            // Round 2: beta — includes VK commitments + public signals + A,B,C
            addG1(transcript, Qm); addG1(transcript, Ql); addG1(transcript, Qr);
            addG1(transcript, Qo); addG1(transcript, Qc);
            addG1(transcript, S1); addG1(transcript, S2); addG1(transcript, S3);
            for (int i = 0; i < publicInputs.size(); i++) {
                transcript.addScalar(publicInputs.get(i));
            }
            addG1(transcript, A); addG1(transcript, B); addG1(transcript, C);
            BigInteger beta = transcript.getChallenge();

            // gamma
            transcript.reset();
            transcript.addScalar(beta);
            BigInteger gamma = transcript.getChallenge();

            // Round 3: alpha
            transcript.reset();
            transcript.addScalar(beta);
            transcript.addScalar(gamma);
            addG1(transcript, Z);
            BigInteger alpha = transcript.getChallenge();

            // Round 4: xi
            transcript.reset();
            transcript.addScalar(alpha);
            addG1(transcript, T1); addG1(transcript, T2); addG1(transcript, T3);
            BigInteger xi = transcript.getChallenge();

            // Round 5: v
            transcript.reset();
            transcript.addScalar(xi);
            transcript.addScalar(eval_a); transcript.addScalar(eval_b); transcript.addScalar(eval_c);
            transcript.addScalar(eval_s1); transcript.addScalar(eval_s2); transcript.addScalar(eval_zw);
            BigInteger v1 = transcript.getChallenge();
            BigInteger v2 = v1.multiply(v1).mod(Fr);
            BigInteger v3 = v2.multiply(v1).mod(Fr);
            BigInteger v4 = v3.multiply(v1).mod(Fr);
            BigInteger v5 = v4.multiply(v1).mod(Fr);

            // u
            transcript.reset();
            addG1(transcript, Wxi); addG1(transcript, Wxiw);
            BigInteger u = transcript.getChallenge();

            // === calculateLagrangeEvaluations ===
            BigInteger xin = xi;
            for (int i = 0; i < power; i++) xin = xin.multiply(xin).mod(Fr);
            BigInteger zh = xin.subtract(BigInteger.ONE).mod(Fr);

            BigInteger n = BigInteger.valueOf(domainSize);
            BigInteger[] L = new BigInteger[publicInputs.size() + 2];
            BigInteger w = BigInteger.ONE;
            for (int i = 1; i <= Math.max(1, publicInputs.size()); i++) {
                L[i] = w.multiply(zh).mod(Fr).multiply(n.multiply(xi.subtract(w).mod(Fr)).mod(Fr).modInverse(Fr)).mod(Fr);
                w = w.multiply(omega).mod(Fr);
            }

            // === calculatePI ===
            BigInteger pi = BigInteger.ZERO;
            for (int i = 0; i < publicInputs.size(); i++) {
                pi = pi.subtract(publicInputs.get(i).multiply(L[i + 1]).mod(Fr)).mod(Fr);
            }

            // === calculateR0 ===
            BigInteger e1 = pi;
            BigInteger e2 = L[1].multiply(alpha.multiply(alpha).mod(Fr)).mod(Fr);

            BigInteger e3a = eval_a.add(beta.multiply(eval_s1).mod(Fr)).add(gamma).mod(Fr);
            BigInteger e3b = eval_b.add(beta.multiply(eval_s2).mod(Fr)).add(gamma).mod(Fr);
            BigInteger e3c = eval_c.add(gamma).mod(Fr);
            BigInteger e3 = e3a.multiply(e3b).mod(Fr).multiply(e3c).mod(Fr)
                    .multiply(eval_zw).mod(Fr).multiply(alpha).mod(Fr);

            BigInteger r0 = e1.subtract(e2).mod(Fr).subtract(e3).mod(Fr);

            // === calculateD ===
            // d1 = a*b*[Qm] + a*[Ql] + b*[Qr] + c*[Qo] + [Qc]
            G1Point d1 = Qm.scalarMul(eval_a.multiply(eval_b).mod(Fr))
                    .add(Ql.scalarMul(eval_a))
                    .add(Qr.scalarMul(eval_b))
                    .add(Qo.scalarMul(eval_c))
                    .add(Qc);

            BigInteger betaxi = beta.multiply(xi).mod(Fr);
            BigInteger d2a1 = eval_a.add(betaxi).add(gamma).mod(Fr);
            BigInteger d2a2 = eval_b.add(betaxi.multiply(k1).mod(Fr)).add(gamma).mod(Fr);
            BigInteger d2a3 = eval_c.add(betaxi.multiply(k2).mod(Fr)).add(gamma).mod(Fr);
            BigInteger d2a = d2a1.multiply(d2a2).mod(Fr).multiply(d2a3).mod(Fr).multiply(alpha).mod(Fr);
            BigInteger d2b = L[1].multiply(alpha.multiply(alpha).mod(Fr)).mod(Fr);
            G1Point d2 = Z.scalarMul(d2a.add(d2b).add(u).mod(Fr));

            BigInteger d3a = eval_a.add(beta.multiply(eval_s1).mod(Fr)).add(gamma).mod(Fr);
            BigInteger d3b = eval_b.add(beta.multiply(eval_s2).mod(Fr)).add(gamma).mod(Fr);
            BigInteger d3c = alpha.multiply(beta).mod(Fr).multiply(eval_zw).mod(Fr);
            G1Point d3 = S3.scalarMul(d3a.multiply(d3b).mod(Fr).multiply(d3c).mod(Fr));

            G1Point d4 = T1.add(T2.scalarMul(xin)).add(T3.scalarMul(xin.multiply(xin).mod(Fr)));
            d4 = d4.scalarMul(zh);

            G1Point D = d1.add(d2).add(d3.negate()).add(d4.negate());

            // === calculateF ===
            G1Point F = D.add(A.scalarMul(v1)).add(B.scalarMul(v2)).add(C.scalarMul(v3))
                    .add(S1.scalarMul(v4)).add(S2.scalarMul(v5));

            // === calculateE ===
            BigInteger e = r0.negate().mod(Fr)
                    .add(v1.multiply(eval_a).mod(Fr))
                    .add(v2.multiply(eval_b).mod(Fr))
                    .add(v3.multiply(eval_c).mod(Fr))
                    .add(v4.multiply(eval_s1).mod(Fr))
                    .add(v5.multiply(eval_s2).mod(Fr))
                    .add(u.multiply(eval_zw).mod(Fr))
                    .mod(Fr);
            G1Point E = G1Point.GENERATOR.scalarMul(e);

            // === isValidPairing ===
            // A1 = Wxi + u*Wxiw
            G1Point A1 = Wxi.add(Wxiw.scalarMul(u));

            // B1 = xi*Wxi + u*xi*omega*Wxiw + F - E
            BigInteger s = u.multiply(xi).mod(Fr).multiply(omega).mod(Fr);
            G1Point B1 = Wxi.scalarMul(xi).add(Wxiw.scalarMul(s)).add(F).add(E.negate());

            // Check: e(-A1, X_2) * e(B1, G2) == 1
            boolean valid = BN254Pairing.pairingCheck(
                    new G1Point[]{A1.negate(), B1},
                    new G2Point[]{X_2, BN254_G2_GENERATOR});

            return valid ? VerificationResult.cryptoValid()
                    : VerificationResult.proofInvalid("PlonK BN254 pairing check failed");

        } catch (Exception e) {
            return VerificationResult.error(VerificationResult.ReasonCode.INTERNAL_ERROR,
                    "PlonK BN254 verification error: " + e.getMessage());
        }
    }

    private static final G2Point BN254_G2_GENERATOR = new G2Point(
            Fp2.of(Fp.of("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
                    Fp.of("11559732032986387107991004021392285783925812861821192530917403151452391805634")),
            Fp2.of(Fp.of("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
                    Fp.of("4082367875863433681332203403145435568316851327593401208105741076214120093531")));

    private void addG1(FiatShamirTranscript t, G1Point p) {
        if (p.isInfinity()) {
            t.addPolCommitment(BigInteger.ZERO, BigInteger.ZERO);
        } else {
            t.addPolCommitment(p.x().value(), p.y().value());
        }
    }

    private G1Point toG1(List<BigInteger> c) {
        BigInteger z = c.size() > 2 ? c.get(2) : BigInteger.ONE;
        return G1Point.fromProjective(c.get(0), c.get(1), z);
    }

    private G2Point toG2(List<List<BigInteger>> c) {
        var z = c.size() > 2 ? c.get(2) : List.of(BigInteger.ONE, BigInteger.ZERO);
        return G2Point.fromProjective(c.get(0).get(0), c.get(0).get(1),
                c.get(1).get(0), c.get(1).get(1), z.get(0), z.get(1));
    }
}
