package com.bloxbean.cardano.zeroj.crypto.snarkjs;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFTBLS381;

import java.math.BigInteger;
import java.util.LinkedHashMap;

/**
 * Exports ZeroJ PlonK BLS12-381 artifacts in the exact JSON snarkjs v0.7.6 reads and writes for
 * {@code plonk} ({@code proof.json}, {@code verification_key.json}, {@code public.json}), so a
 * proof from {@code PlonKProverBLS381.prove} (the snarkjs-transcript prover) can be checked by
 * {@code snarkjs plonk verify} (ADR-0047, issue #31).
 *
 * <p>Same egress rules as {@link SnarkjsGroth16Json}: nothing is reduced or rewritten; every
 * commitment must be a non-infinity, on-curve, prime-order G1 point, {@code X_2} a valid G2 point,
 * and every evaluation / {@code k1} / {@code k2} / {@code w} canonical in {@code [0, r)}. The one
 * deliberate exception is the five selector commitments {@code Qm/Ql/Qr/Qo/Qc}: a selector
 * polynomial that is identically zero (e.g. {@code Qr} and {@code Qc} of a bare multiplier) commits
 * to the identity, which snarkjs writes as {@code ["0", "1", "0"]}; the ZeroJ PlonK verifier
 * accepts infinity in exactly those positions, and so does this exporter.</p>
 *
 * <h2>Format (pinned to snarkjs v0.7.6)</h2>
 * <ul>
 *   <li>{@code proof.json}: {@code {A, B, C, Z, T1, T2, T3, Wxi, Wxiw, eval_a, eval_b, eval_c,
 *       eval_s1, eval_s2, eval_zw, protocol: "plonk", curve: "bls12381"}}</li>
 *   <li>{@code verification_key.json}: {@code {protocol, curve, nPublic, power, k1, k2, Qm, Ql,
 *       Qr, Qo, Qc, S1, S2, S3, X_2, w}} where {@code power = log2(domainSize)} and {@code w} is
 *       the domain generator {@code omega}, required to be the canonical root snarkjs derives</li>
 *   <li>{@code public.json}: a JSON array of decimal strings in public-input order</li>
 * </ul>
 *
 * <p>Exporting a key does not change what it proves: the b10/b11 blinding gap of the PlonK prover
 * tracked by issue #30 is unaffected by this exporter, which only serializes the key's public
 * half and the proof the prover already produced.</p>
 */
public final class SnarkjsPlonkJson {

    private SnarkjsPlonkJson() {}

    /** The {@code protocol} string snarkjs writes and checks. */
    public static final String PROTOCOL = "plonk";

    /** The {@code curve} string snarkjs v0.7.6 writes for BLS12-381. */
    public static final String CURVE = SnarkjsGroth16Json.CURVE;

    /** {@code proof.json} for a ZeroJ PlonK proof. */
    public static String proofJson(PlonKProofBLS381 proof) {
        if (proof == null) throw new IllegalArgumentException("proof must not be null");
        var tree = new LinkedHashMap<String, Object>();
        tree.put("A", SnarkjsJsonWriter.g1("A", proof.commitA()));
        tree.put("B", SnarkjsJsonWriter.g1("B", proof.commitB()));
        tree.put("C", SnarkjsJsonWriter.g1("C", proof.commitC()));
        tree.put("Z", SnarkjsJsonWriter.g1("Z", proof.commitZ()));
        tree.put("T1", SnarkjsJsonWriter.g1("T1", proof.commitT1()));
        tree.put("T2", SnarkjsJsonWriter.g1("T2", proof.commitT2()));
        tree.put("T3", SnarkjsJsonWriter.g1("T3", proof.commitT3()));
        tree.put("Wxi", SnarkjsJsonWriter.g1("Wxi", proof.commitWxi()));
        tree.put("Wxiw", SnarkjsJsonWriter.g1("Wxiw", proof.commitWxiw()));
        tree.put("eval_a", SnarkjsJsonWriter.scalar("eval_a", proof.evalA()));
        tree.put("eval_b", SnarkjsJsonWriter.scalar("eval_b", proof.evalB()));
        tree.put("eval_c", SnarkjsJsonWriter.scalar("eval_c", proof.evalC()));
        tree.put("eval_s1", SnarkjsJsonWriter.scalar("eval_s1", proof.evalS1()));
        tree.put("eval_s2", SnarkjsJsonWriter.scalar("eval_s2", proof.evalS2()));
        tree.put("eval_zw", SnarkjsJsonWriter.scalar("eval_zw", proof.evalZw()));
        tree.put("protocol", PROTOCOL);
        tree.put("curve", CURVE);
        return SnarkjsJsonWriter.write(tree);
    }

    /** {@code verification_key.json}: the public half of a ZeroJ PlonK proving key. */
    public static String verificationKeyJson(PlonKProvingKeyBLS381 pk) {
        if (pk == null) throw new IllegalArgumentException("proving key must not be null");
        if (pk.omega() == null) throw new IllegalArgumentException("omega must not be null");
        return verificationKeyJson(pk.domainSize(), pk.nPublic(), pk.k1(), pk.k2(), pk.omega().toBigInteger(),
                pk.qmCommit(), pk.qlCommit(), pk.qrCommit(), pk.qoCommit(), pk.qcCommit(),
                pk.s1Commit(), pk.s2Commit(), pk.s3Commit(), pk.x2());
    }

    /**
     * {@code verification_key.json} from its components.
     *
     * @param domainSize evaluation-domain size {@code n}, a power of two; exported as {@code power = log2(n)}
     * @param nPublic    number of public inputs
     * @param omega      generator of the size-{@code n} domain, exported as {@code w}; must equal the
     *                   canonical root {@code FieldFFTBLS381.rootOfUnity(log2 n)}, which is what
     *                   snarkjs' verifier derives on its own ({@code Fr.w[power]}) and ignores {@code w} for
     */
    public static String verificationKeyJson(int domainSize, int nPublic, BigInteger k1, BigInteger k2,
                                             BigInteger omega,
                                             AffineG1 qm, AffineG1 ql, AffineG1 qr, AffineG1 qo, AffineG1 qc,
                                             AffineG1 s1, AffineG1 s2, AffineG1 s3, AffineG2 x2) {
        if (domainSize < 2 || Integer.bitCount(domainSize) != 1) {
            throw new IllegalArgumentException("domainSize must be a power of two >= 2, got " + domainSize);
        }
        if (nPublic < 0) throw new IllegalArgumentException("nPublic must be >= 0, got " + nPublic);
        int power = Integer.numberOfTrailingZeros(domainSize);
        // snarkjs' verifier ignores vk.w and uses its own canonical 2^power-th root (Fr.w[power]),
        // while ZeroJ's verifier reads w from the file. Exporting a non-canonical generator would
        // therefore produce a key snarkjs accepts and ZeroJ rejects; fail closed instead.
        BigInteger canonical = FieldFFTBLS381.rootOfUnity(power).toBigInteger();
        if (omega == null || !omega.equals(canonical)) {
            throw new IllegalArgumentException("w must be the canonical 2^" + power
                    + "-th root of unity snarkjs derives for this domain (" + canonical + "), got " + omega);
        }

        var tree = new LinkedHashMap<String, Object>();
        tree.put("protocol", PROTOCOL);
        tree.put("curve", CURVE);
        tree.put("nPublic", nPublic);
        tree.put("power", power);
        tree.put("k1", SnarkjsJsonWriter.scalar("k1", k1));
        tree.put("k2", SnarkjsJsonWriter.scalar("k2", k2));
        tree.put("Qm", SnarkjsJsonWriter.g1AllowingInfinity("Qm", qm));
        tree.put("Ql", SnarkjsJsonWriter.g1AllowingInfinity("Ql", ql));
        tree.put("Qr", SnarkjsJsonWriter.g1AllowingInfinity("Qr", qr));
        tree.put("Qo", SnarkjsJsonWriter.g1AllowingInfinity("Qo", qo));
        tree.put("Qc", SnarkjsJsonWriter.g1AllowingInfinity("Qc", qc));
        tree.put("S1", SnarkjsJsonWriter.g1("S1", s1));
        tree.put("S2", SnarkjsJsonWriter.g1("S2", s2));
        tree.put("S3", SnarkjsJsonWriter.g1("S3", s3));
        tree.put("X_2", SnarkjsJsonWriter.g2("X_2", x2));
        tree.put("w", SnarkjsJsonWriter.scalar("w", omega));
        return SnarkjsJsonWriter.write(tree);
    }

    /** {@code public.json} in public-input order, each canonical in {@code [0, r)}. */
    public static String publicJson(BigInteger[] publicInputs) {
        return SnarkjsJsonWriter.write(SnarkjsJsonWriter.scalars("public", publicInputs));
    }
}
