package com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec;

import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Generators;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.transcript.FiatShamirTranscript;

import java.math.BigInteger;

/**
 * Converts pure Java BLS12-381 PlonK prover output to the compressed point
 * format expected by the ZeroJ Cardano Julc verifier profile.
 */
public final class PlonKProverToCardano {

    private static final BigInteger FR = MontFr381.modulus();

    private PlonKProverToCardano() {}

    public static ProofCompressed compressProof(
            PlonKProofBLS381 proof,
            PlonKProvingKeyBLS381 pk,
            BigInteger[] publicInputs) {
        var vk = compressVk(pk);
        var withoutInverses = compressProofWithInverses(proof, BigInteger.ZERO, BigInteger.ZERO);
        var challenges = computeChallenges(vk, withoutInverses, publicInputs);
        return compressProofWithInverses(proof, challenges.xiMinusOneInv(), challenges.xiMinusOmegaInv());
    }

    public static ProofCompressed compressProofWithInverses(
            PlonKProofBLS381 proof,
            BigInteger xiMinusOneInv,
            BigInteger xiMinusOmegaInv) {
        return new ProofCompressed(
                g1Compress(proof.commitA()),
                g1Compress(proof.commitB()),
                g1Compress(proof.commitC()),
                g1Compress(proof.commitZ()),
                g1Compress(proof.commitT1()),
                g1Compress(proof.commitT2()),
                g1Compress(proof.commitT3()),
                g1Compress(proof.commitWxi()),
                g1Compress(proof.commitWxiw()),
                proof.evalA(),
                proof.evalB(),
                proof.evalC(),
                proof.evalS1(),
                proof.evalS2(),
                proof.evalZw(),
                xiMinusOneInv,
                xiMinusOmegaInv);
    }

    public static VkCompressed compressVk(PlonKProvingKeyBLS381 pk) {
        int domainPower = Integer.numberOfTrailingZeros(pk.domainSize());
        return new VkCompressed(
                g1Compress(pk.qmCommit()),
                g1Compress(pk.qlCommit()),
                g1Compress(pk.qrCommit()),
                g1Compress(pk.qoCommit()),
                g1Compress(pk.qcCommit()),
                g1Compress(pk.s1Commit()),
                g1Compress(pk.s2Commit()),
                g1Compress(pk.s3Commit()),
                g2Compress(pk.x2()),
                BigInteger.valueOf(pk.domainSize()),
                BigInteger.valueOf(domainPower),
                pk.omega().toBigInteger(),
                pk.k1(),
                pk.k2(),
                pk.k1().multiply(pk.k2().modInverse(FR)).mod(FR),
                FR,
                BigInteger.valueOf(pk.domainSize()).modInverse(FR),
                Bls12381Codecs.g1ToCompressed(Bls12381Generators.G1),
                Bls12381Codecs.g2ToCompressed(Bls12381Generators.G2));
    }

    public static ChallengeScalars computeChallenges(
            VkCompressed vk,
            ProofCompressed proof,
            BigInteger[] publicInputs) {
        var transcript = new FiatShamirTranscript(FR, 32, 48);
        transcript.addBytes(vk.qm()); transcript.addBytes(vk.ql());
        transcript.addBytes(vk.qr()); transcript.addBytes(vk.qo());
        transcript.addBytes(vk.qc());
        transcript.addBytes(vk.s1()); transcript.addBytes(vk.s2());
        transcript.addBytes(vk.s3());
        for (BigInteger publicInput : publicInputs) {
            transcript.addScalar(publicInput);
        }
        transcript.addBytes(proof.cmA()); transcript.addBytes(proof.cmB());
        transcript.addBytes(proof.cmC());
        BigInteger beta = transcript.getChallenge();

        transcript.reset();
        transcript.addScalar(beta);
        BigInteger gamma = transcript.getChallenge();

        transcript.reset();
        transcript.addScalar(beta);
        transcript.addScalar(gamma);
        transcript.addBytes(proof.cmZ());
        BigInteger alpha = transcript.getChallenge();

        transcript.reset();
        transcript.addScalar(alpha);
        transcript.addBytes(proof.cmT1()); transcript.addBytes(proof.cmT2());
        transcript.addBytes(proof.cmT3());
        BigInteger xi = transcript.getChallenge();

        transcript.reset();
        transcript.addScalar(xi);
        transcript.addScalar(proof.evalA()); transcript.addScalar(proof.evalB());
        transcript.addScalar(proof.evalC()); transcript.addScalar(proof.evalS1());
        transcript.addScalar(proof.evalS2()); transcript.addScalar(proof.evalZw());
        BigInteger v = transcript.getChallenge();

        transcript.reset();
        transcript.addBytes(proof.wXi()); transcript.addBytes(proof.wXiw());
        BigInteger u = transcript.getChallenge();

        BigInteger xiMinusOneInv = xi.subtract(BigInteger.ONE).mod(FR).modInverse(FR);
        BigInteger xiMinusOmegaInv = xi.subtract(vk.omega()).mod(FR).modInverse(FR);
        return new ChallengeScalars(beta, gamma, alpha, xi, v, u, xiMinusOneInv, xiMinusOmegaInv);
    }

    public static byte[] g1Compress(JacobianG1BLS381.AffineG1 point) {
        return Bls12381Codecs.g1ToCompressed(toG1Point(point));
    }

    public static byte[] g2Compress(JacobianG2BLS381.AffineG2 point) {
        return Bls12381Codecs.g2ToCompressed(toG2Point(point));
    }

    private static G1Point toG1Point(JacobianG1BLS381.AffineG1 point) {
        if (point.isInfinity()) {
            return G1Point.INFINITY;
        }
        return new G1Point(Fp.of(point.xBigInt()), Fp.of(point.yBigInt()));
    }

    private static G2Point toG2Point(JacobianG2BLS381.AffineG2 point) {
        if (point.isInfinity()) {
            return G2Point.INFINITY;
        }
        return new G2Point(
                Fp2.of(Fp.of(point.x().reBigInt()), Fp.of(point.x().imBigInt())),
                Fp2.of(Fp.of(point.y().reBigInt()), Fp.of(point.y().imBigInt())));
    }

    public record ProofCompressed(
            byte[] cmA, byte[] cmB, byte[] cmC, byte[] cmZ,
            byte[] cmT1, byte[] cmT2, byte[] cmT3,
            byte[] wXi, byte[] wXiw,
            BigInteger evalA, BigInteger evalB, BigInteger evalC,
            BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
            BigInteger xiMinusOneInv, BigInteger xiMinusOmegaInv) {}

    public record VkCompressed(
            byte[] qm, byte[] ql, byte[] qr, byte[] qo, byte[] qc,
            byte[] s1, byte[] s2, byte[] s3,
            byte[] x2,
            BigInteger domainSize,
            BigInteger domainPower,
            BigInteger omega,
            BigInteger k1,
            BigInteger k2,
            BigInteger k1OverK2,
            BigInteger fr,
            BigInteger nInv,
            byte[] g1Gen,
            byte[] g2Gen) {}

    public record ChallengeScalars(
            BigInteger beta,
            BigInteger gamma,
            BigInteger alpha,
            BigInteger xi,
            BigInteger v,
            BigInteger u,
            BigInteger xiMinusOneInv,
            BigInteger xiMinusOmegaInv) {}
}
