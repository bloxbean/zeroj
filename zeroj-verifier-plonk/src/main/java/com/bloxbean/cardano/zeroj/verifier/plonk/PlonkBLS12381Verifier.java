package com.bloxbean.cardano.zeroj.verifier.plonk;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.BackendDescriptor;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.ec.*;
import com.bloxbean.cardano.zeroj.bls12381.field.*;
import com.bloxbean.cardano.zeroj.codec.CodecException;
import com.bloxbean.cardano.zeroj.codec.CanonicalHash;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.transcript.FiatShamirTranscript;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
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

    public static final String SNARKJS_PROOF_FORMAT = "snarkjs-plonk-json";
    public static final String CARDANO_PROOF_FORMAT = "zeroj-plonk-bls12381-cardano-v1-json";
    public static final String CARDANO_MPI_PROOF_FORMAT = PlonKProverBLS381.CARDANO_MPI_PROFILE_TAG;

    private static final BigInteger Fr = G1Point.R;
    private static final BigInteger BASE_FIELD_MODULUS = com.bloxbean.cardano.zeroj.bls12381.field.Fp.P;
    private static final int MAX_DOMAIN_POWER = 24;
    private static final int MAX_PUBLIC_INPUTS = 256;

    @Override
    public BackendDescriptor descriptor() {
        return DESCRIPTOR;
    }

    @Override
    public VerificationResult verify(ZkProofEnvelope envelope, VerificationMaterial material) {
        try {
            var bindingError = validateEnvelopeMaterial(envelope, material);
            if (bindingError != null) {
                return bindingError;
            }

            if (envelope.proofFormat().filter("gnark-plonk-json"::equals).isPresent()) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.UNSUPPORTED_PROOF_SYSTEM,
                        "gnark binary PlonK JSON is not accepted by the snarkjs/ZeroJ structured PlonK verifier");
            }
            if (envelope.proofFormat().isPresent()
                    && !envelope.proofFormat().orElseThrow().equals(SNARKJS_PROOF_FORMAT)
                    && !envelope.proofFormat().orElseThrow().equals(CARDANO_PROOF_FORMAT)
                    && !envelope.proofFormat().orElseThrow().equals(CARDANO_MPI_PROOF_FORMAT)) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                        "Unsupported PlonK proof format for BLS12-381 verifier");
            }
            boolean compressedTranscript = envelope.proofFormat()
                    .filter(CARDANO_PROOF_FORMAT::equals)
                    .isPresent();
            boolean mpiTranscript = envelope.proofFormat()
                    .filter(CARDANO_MPI_PROOF_FORMAT::equals)
                    .isPresent();
            compressedTranscript = compressedTranscript || mpiTranscript;

            var proofJson = new String(envelope.proofBytes(), StandardCharsets.UTF_8);
            var vkJson = new String(material.vkBytes(), StandardCharsets.UTF_8);

            var sp = com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkCodec.parseProof(proofJson);
            var sv = com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkCodec.parseVerificationKey(vkJson);
            validateParsedMetadata(sp.protocol(), sp.curve(), sv.protocol(), sv.curve());
            validateVkShape(sv.nPublic(), sv.power());

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
            validateCardanoProfilePublicInputCount(compressedTranscript, mpiTranscript, publicInputs.size());
            validatePublicInputs(publicInputs);
            validateProofScalars(proof);
            validateVkDomain(vk);

            int n = vk.domainSize();
            BigInteger omega = vk.omega();

            // Step 1: Fiat-Shamir challenges. This mirrors the BLS12-381 prover
            // and BN254 verifier transcript round boundaries.
            G1Point A = requireG1(proof.cmA(), "A", false);
            G1Point B = requireG1(proof.cmB(), "B", false);
            G1Point C = requireG1(proof.cmC(), "C", false);
            G1Point Z = requireG1(proof.cmZ(), "Z", false);
            G1Point T1 = requireG1(proof.cmT1(), "T1", false);
            G1Point T2 = requireG1(proof.cmT2(), "T2", false);
            G1Point T3 = requireG1(proof.cmT3(), "T3", false);
            G1Point Wxi = requireG1(proof.wZeta(), "Wxi", false);
            G1Point Wxiw = requireG1(proof.wZetaOmega(), "Wxiw", false);

            G1Point Qm = requireG1(vk.qM(), "Qm", true);
            G1Point Ql = requireG1(vk.qL(), "Ql", true);
            G1Point Qr = requireG1(vk.qR(), "Qr", true);
            G1Point Qo = requireG1(vk.qO(), "Qo", true);
            G1Point Qc = requireG1(vk.qC(), "Qc", true);
            G1Point S1 = requireG1(vk.s1(), "S1", false);
            G1Point S2 = requireG1(vk.s2(), "S2", false);
            G1Point S3 = requireG1(vk.s3(), "S3", false);
            G2Point X_2 = requireG2(vk.x2(), "X_2", false);

            var transcript = new FiatShamirTranscript(Fr, 32, 48);
            addG1(transcript, Qm, compressedTranscript); addG1(transcript, Ql, compressedTranscript);
            addG1(transcript, Qr, compressedTranscript);
            addG1(transcript, Qo, compressedTranscript); addG1(transcript, Qc, compressedTranscript);
            addG1(transcript, S1, compressedTranscript); addG1(transcript, S2, compressedTranscript);
            addG1(transcript, S3, compressedTranscript);
            if (mpiTranscript) {
                transcript.addBytes(CARDANO_MPI_PROOF_FORMAT.getBytes(StandardCharsets.US_ASCII));
                transcript.addScalar(BigInteger.valueOf(publicInputs.size()));
            }
            for (int i = 0; i < publicInputs.size(); i++) {
                transcript.addScalar(publicInputs.get(i));
            }
            addG1(transcript, A, compressedTranscript); addG1(transcript, B, compressedTranscript);
            addG1(transcript, C, compressedTranscript);
            BigInteger beta = transcript.getChallenge();

            transcript.reset();
            transcript.addScalar(beta);
            BigInteger gamma = transcript.getChallenge();

            transcript.reset();
            transcript.addScalar(beta);
            transcript.addScalar(gamma);
            addG1(transcript, Z, compressedTranscript);
            BigInteger alpha = transcript.getChallenge();

            transcript.reset();
            transcript.addScalar(alpha);
            addG1(transcript, T1, compressedTranscript); addG1(transcript, T2, compressedTranscript);
            addG1(transcript, T3, compressedTranscript);
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
            addG1(transcript, Wxi, compressedTranscript); addG1(transcript, Wxiw, compressedTranscript);
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
            if (xi.equals(BigInteger.ONE)) {
                return VerificationResult.proofInvalid("PlonK BLS12-381 challenge is inside the evaluation domain");
            }
            BigInteger l1 = zh.multiply(nBI.multiply(xi.subtract(BigInteger.ONE).mod(Fr)).mod(Fr).modInverse(Fr)).mod(Fr);

            // Step 4: PI(xi). Public inputs are subtracted, matching the prover's
            // PI polynomial where PI(omega^i) = -public_i.
            BigInteger pi = BigInteger.ZERO;
            BigInteger wPow = BigInteger.ONE;
            for (int i = 0; i < publicInputs.size(); i++) {
                if (xi.equals(wPow)) {
                    return VerificationResult.proofInvalid("PlonK BLS12-381 challenge is inside the evaluation domain");
                }
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
            if (e instanceof VerificationInputException vie) {
                return VerificationResult.error(vie.reasonCode, vie.getMessage());
            }
            if (e instanceof CodecException) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                        "Malformed PlonK BLS12-381 proof or verification key");
            }
            if (e instanceof ArithmeticException) {
                return VerificationResult.proofInvalid("PlonK BLS12-381 arithmetic check failed");
            }
            return VerificationResult.error(
                    VerificationResult.ReasonCode.INTERNAL_ERROR,
                    "PlonK BLS12-381 verification failed unexpectedly");
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

    private void addG1(FiatShamirTranscript transcript, G1Point point, boolean compressed) {
        if (compressed) {
            transcript.addBytes(Bls12381Codecs.g1ToCompressed(point));
        } else if (point.isInfinity()) {
            transcript.addPolCommitment(BigInteger.ZERO, BigInteger.ZERO);
        } else {
            transcript.addPolCommitment(point.x().value(), point.y().value());
        }
    }

    private VerificationResult validateEnvelopeMaterial(ZkProofEnvelope envelope, VerificationMaterial material) {
        if (envelope.proofSystem() != ProofSystemId.PLONK) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.UNSUPPORTED_PROOF_SYSTEM,
                    "Expected PlonK proof envelope");
        }
        if (envelope.curve() != CurveId.BLS12_381) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.UNSUPPORTED_CURVE,
                    "Expected BLS12-381 proof envelope");
        }
        if (material.proofSystemId() != envelope.proofSystem()
                || material.curveId() != envelope.curve()
                || !material.circuitId().equals(envelope.circuitId())) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.VK_MISMATCH,
                    "Verification material does not match proof envelope");
        }

        byte[] actualVkHash = CanonicalHash.sha256(material.vkBytes());
        if (material.vkHash().isPresent() && !Arrays.equals(material.vkHash().orElseThrow(), actualVkHash)) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.VK_MISMATCH,
                    "Verification material hash does not match VK bytes");
        }
        if (envelope.vkRef() instanceof VerificationKeyRef.ByHash byHash
                && !Arrays.equals(byHash.hash(), actualVkHash)) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.VK_MISMATCH,
                    "Proof envelope VK hash does not match verification material");
        }
        return null;
    }

    private void validateParsedMetadata(String proofProtocol, String proofCurve, String vkProtocol, String vkCurve) {
        if (!"plonk".equals(proofProtocol) || !"plonk".equals(vkProtocol)) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.UNSUPPORTED_PROOF_SYSTEM,
                    "Expected PlonK proof and verification key");
        }
        if (!CurveId.BLS12_381.value().equals(proofCurve) || !CurveId.BLS12_381.value().equals(vkCurve)) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.UNSUPPORTED_CURVE,
                    "Expected BLS12-381 proof and verification key");
        }
    }

    private void validateVkShape(int nPublic, int power) {
        if (nPublic < 0 || nPublic > MAX_PUBLIC_INPUTS) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Invalid PlonK BLS12-381 public input count");
        }
        if (power <= 0 || power > MAX_DOMAIN_POWER) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Invalid PlonK BLS12-381 domain size");
        }
    }

    private void validatePublicInputs(PublicInputs publicInputs) {
        for (int i = 0; i < publicInputs.size(); i++) {
            BigInteger value = publicInputs.get(i);
            if (value == null || value.signum() < 0 || value.compareTo(Fr) >= 0) {
                throw new VerificationInputException(
                        VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS,
                        "Invalid PlonK BLS12-381 public input");
            }
        }
    }

    private void validateCardanoProfilePublicInputCount(boolean compressedTranscript,
                                                        boolean mpiTranscript,
                                                        int publicInputCount) {
        if (mpiTranscript) {
            if (publicInputCount < 1 || publicInputCount > PlonKProverBLS381.MAX_CARDANO_MPI_PUBLIC_INPUTS) {
                throw new VerificationInputException(
                        VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS,
                        "Cardano PlonK MPI profile supports 1.."
                                + PlonKProverBLS381.MAX_CARDANO_MPI_PUBLIC_INPUTS + " public inputs");
            }
        } else if (compressedTranscript && publicInputCount != 1) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS,
                    "Cardano PlonK v1 profile requires exactly one public input");
        }
    }

    private void validateProofScalars(PlonkProof proof) {
        requireScalar(proof.evalA(), "eval_a");
        requireScalar(proof.evalB(), "eval_b");
        requireScalar(proof.evalC(), "eval_c");
        requireScalar(proof.evalS1(), "eval_s1");
        requireScalar(proof.evalS2(), "eval_s2");
        requireScalar(proof.evalZOmega(), "eval_zw");
    }

    private void validateVkDomain(PlonkVerificationKey vk) {
        requireScalar(vk.omega(), "omega");
        requireNonZeroScalar(vk.omega(), "omega");
        requireScalar(vk.k1(), "k1");
        requireNonZeroScalar(vk.k1(), "k1");
        requireScalar(vk.k2(), "k2");
        requireNonZeroScalar(vk.k2(), "k2");

        int n = vk.domainSize();
        if (Integer.bitCount(n) != 1) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Invalid PlonK BLS12-381 domain size");
        }
        BigInteger nBI = BigInteger.valueOf(n);
        if (!vk.omega().modPow(nBI, Fr).equals(BigInteger.ONE)
                || vk.omega().modPow(BigInteger.valueOf(n / 2L), Fr).equals(BigInteger.ONE)) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Invalid PlonK BLS12-381 domain root");
        }
        if (isInDomainSubgroup(vk.k1(), nBI)
                || isInDomainSubgroup(vk.k2(), nBI)
                || isInDomainSubgroup(vk.k1().multiply(vk.k2().modInverse(Fr)).mod(Fr), nBI)) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Invalid PlonK BLS12-381 permutation cosets");
        }
    }

    private boolean isInDomainSubgroup(BigInteger value, BigInteger domainSize) {
        return value.modPow(domainSize, Fr).equals(BigInteger.ONE);
    }

    private void requireScalar(BigInteger value, String name) {
        if (value == null || value.signum() < 0 || value.compareTo(Fr) >= 0) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Invalid PlonK BLS12-381 scalar: " + name);
        }
    }

    private void requireNonZeroScalar(BigInteger value, String name) {
        if (value.signum() == 0) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Invalid PlonK BLS12-381 scalar: " + name);
        }
    }

    private G1Point requireG1(List<BigInteger> coords, String name, boolean allowInfinity) {
        validateG1Encoding(coords, name, allowInfinity);
        BigInteger z = coords.size() > 2 ? coords.get(2) : BigInteger.ONE;
        G1Point point = G1Point.fromProjective(coords.get(0), coords.get(1), z);
        if ((!allowInfinity && point.isInfinity()) || !point.isValid()) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.INVALID_PROOF,
                    "Invalid PlonK BLS12-381 G1 point: " + name);
        }
        return point;
    }

    private G2Point requireG2(List<List<BigInteger>> coords, String name, boolean allowInfinity) {
        validateG2Encoding(coords, name, allowInfinity);
        var z = coords.size() > 2 ? coords.get(2) : List.of(BigInteger.ONE, BigInteger.ZERO);
        G2Point point = G2Point.fromProjective(
                coords.get(0).get(0), coords.get(0).get(1),
                coords.get(1).get(0), coords.get(1).get(1),
                z.get(0), z.get(1));
        if ((!allowInfinity && point.isInfinity()) || !point.isValid()) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.INVALID_PROOF,
                    "Invalid PlonK BLS12-381 G2 point: " + name);
        }
        return point;
    }

    private void validateG1Encoding(List<BigInteger> coords, String name, boolean allowInfinity) {
        if (coords == null || (coords.size() != 2 && coords.size() != 3)) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Invalid PlonK BLS12-381 G1 encoding: " + name);
        }
        for (BigInteger coord : coords) {
            requireBaseField(coord, "G1 " + name);
        }
        BigInteger z = coords.size() == 3 ? coords.get(2) : BigInteger.ONE;
        boolean infinity = z.signum() == 0;
        if (infinity) {
            if (!allowInfinity || coords.get(0).signum() != 0 || !coords.get(1).equals(BigInteger.ONE)) {
                throw new VerificationInputException(
                        VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                        "Invalid PlonK BLS12-381 G1 infinity encoding: " + name);
            }
        } else if (!z.equals(BigInteger.ONE)) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Non-normalized PlonK BLS12-381 G1 encoding: " + name);
        }
    }

    private void validateG2Encoding(List<List<BigInteger>> coords, String name, boolean allowInfinity) {
        if (coords == null || coords.size() != 3) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Invalid PlonK BLS12-381 G2 encoding: " + name);
        }
        for (List<BigInteger> pair : coords) {
            if (pair == null || pair.size() != 2) {
                throw new VerificationInputException(
                        VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                        "Invalid PlonK BLS12-381 G2 encoding: " + name);
            }
            requireBaseField(pair.get(0), "G2 " + name);
            requireBaseField(pair.get(1), "G2 " + name);
        }
        var z = coords.get(2);
        boolean infinity = z.get(0).signum() == 0 && z.get(1).signum() == 0;
        if (infinity) {
            var x = coords.get(0);
            var y = coords.get(1);
            boolean canonicalInfinity = x.get(0).signum() == 0 && x.get(1).signum() == 0
                    && y.get(0).equals(BigInteger.ONE) && y.get(1).signum() == 0;
            if (!allowInfinity || !canonicalInfinity) {
                throw new VerificationInputException(
                        VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                        "Invalid PlonK BLS12-381 G2 infinity encoding: " + name);
            }
        } else if (!z.get(0).equals(BigInteger.ONE) || z.get(1).signum() != 0) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Non-normalized PlonK BLS12-381 G2 encoding: " + name);
        }
    }

    private void requireBaseField(BigInteger value, String name) {
        if (value == null || value.signum() < 0 || value.compareTo(BASE_FIELD_MODULUS) >= 0) {
            throw new VerificationInputException(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Invalid PlonK BLS12-381 coordinate: " + name);
        }
    }

    private static final class VerificationInputException extends RuntimeException {
        private final VerificationResult.ReasonCode reasonCode;

        private VerificationInputException(VerificationResult.ReasonCode reasonCode, String message) {
            super(message);
            this.reasonCode = reasonCode;
        }
    }
}
