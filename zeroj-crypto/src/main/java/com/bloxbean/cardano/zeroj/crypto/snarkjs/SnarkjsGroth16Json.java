package com.bloxbean.cardano.zeroj.crypto.snarkjs;

import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp12;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp6;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Keys;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * Exports ZeroJ Groth16 BLS12-381 artifacts in the exact JSON that snarkjs v0.7.6 reads and
 * writes ({@code proof.json}, {@code verification_key.json}, {@code public.json}), so that a proof
 * produced by {@code Groth16ProverBLS381} can be checked by {@code snarkjs groth16 verify} and a
 * ZeroJ-native setup can be consumed by snarkjs as a verification key (ADR-0047, issue #31).
 *
 * <p>This is a serialization boundary in the egress direction. It never reduces, rewrites or
 * substitutes a value: every point is required to be a non-infinity, on-curve, prime-order point
 * and every scalar to be canonical in {@code [0, r)}, and anything else throws
 * {@link IllegalArgumentException}. It does not compute or alter proofs.</p>
 *
 * <h2>Format (pinned to snarkjs v0.7.6)</h2>
 * <ul>
 *   <li>{@code proof.json}: {@code {pi_a, pi_b, pi_c, protocol: "groth16", curve: "bls12381"}}</li>
 *   <li>{@code verification_key.json}: {@code {protocol, curve, nPublic, vk_alpha_1, vk_beta_2,
 *       vk_gamma_2, vk_delta_2, vk_alphabeta_12, IC}} with {@code nPublic = IC.length - 1}</li>
 *   <li>{@code public.json}: a JSON array of decimal strings, index {@code i} = public wire {@code i+1}</li>
 * </ul>
 * <p>Points are affine with the projective marker snarkjs emits ({@code "1"} / {@code ["1","0"]}),
 * numbers are decimal strings, and the text is what snarkjs' {@code bfj.write(..., {space: 1})}
 * produces (one-space indent, no trailing newline, {@code "[\n]"} for an empty {@code public.json}),
 * byte-identical to what snarkjs writes for the same values.</p>
 *
 * <h2>{@code vk_alphabeta_12}</h2>
 * <p>snarkjs fills this field with {@code e(alpha, beta)} from ffjavascript/wasmcurves and its
 * verifier does not read it, but ZeroJ's {@code SnarkjsJsonCodec} parser requires it. wasmcurves'
 * BLS12-381 final exponentiation is the Hayashida–Hayasaka–Teruya cyclotomic variant, which
 * raises to {@code 3·(p^12−1)/r} rather than {@code (p^12−1)/r}; ZeroJ's
 * {@link BLS12381Pairing#finalExponentiation} computes the exact exponent. The two are both valid
 * pairings and differ by a cube, so this exporter emits {@code e_ZeroJ(alpha, beta)^3}, laid out
 * as {@code [[c0.c0, c0.c1, c0.c2], [c1.c0, c1.c1, c1.c2]]} over {@code Fp12 = Fp6[w] / Fp6 =
 * Fp2[v] / Fp2 = Fp[u]} with each {@code Fp2} as {@code [c0, c1]}. The relation is pinned by a
 * known-answer test against every snarkjs-generated BLS12-381 verification key in the repository.</p>
 */
public final class SnarkjsGroth16Json {

    private SnarkjsGroth16Json() {}

    /** The {@code protocol} string snarkjs writes and checks. */
    public static final String PROTOCOL = "groth16";

    /** The {@code curve} string snarkjs v0.7.6 writes for BLS12-381 (its reader also accepts "bls12-381"). */
    public static final String CURVE = "bls12381";

    /** {@code proof.json} for a ZeroJ proof. */
    public static String proofJson(Groth16ProofBLS381 proof) {
        if (proof == null) throw new IllegalArgumentException("proof must not be null");
        var tree = new LinkedHashMap<String, Object>();
        tree.put("pi_a", SnarkjsJsonWriter.g1("pi_a", proof.a()));
        tree.put("pi_b", SnarkjsJsonWriter.g2("pi_b", proof.b()));
        tree.put("pi_c", SnarkjsJsonWriter.g1("pi_c", proof.c()));
        tree.put("protocol", PROTOCOL);
        tree.put("curve", CURVE);
        return SnarkjsJsonWriter.write(tree);
    }

    /** {@code verification_key.json} for the verification half of a ZeroJ-native setup. */
    public static String verificationKeyJson(Groth16SetupBLS381.SetupResult setup) {
        if (setup == null) throw new IllegalArgumentException("setup must not be null");
        var pk = setup.provingKey();
        return verificationKeyJson(pk.alphaG1(), pk.betaG2(), setup.gammaG2(), pk.deltaG2(), setup.ic());
    }

    /** {@code verification_key.json} for the verification half of a {@link Groth16Keys} bundle. */
    public static String verificationKeyJson(Groth16Keys keys) {
        if (keys == null) throw new IllegalArgumentException("keys must not be null");
        var pk = keys.pk();
        return verificationKeyJson(pk.alphaG1(), pk.betaG2(), keys.gammaG2(), pk.deltaG2(), keys.ic());
    }

    /**
     * {@code verification_key.json} from the five verification-key components.
     *
     * @param ic {@code IC[0..nPublic]}, {@code IC[i]} bound to public wire {@code i} (wire 0 is the constant one)
     */
    public static String verificationKeyJson(AffineG1 alphaG1, AffineG2 betaG2, AffineG2 gammaG2,
                                             AffineG2 deltaG2, AffineG1[] ic) {
        if (ic == null || ic.length == 0) throw new IllegalArgumentException("IC must contain at least IC[0]");
        var alpha = SnarkjsJsonWriter.g1("vk_alpha_1", alphaG1);
        var beta = SnarkjsJsonWriter.g2("vk_beta_2", betaG2);
        var gamma = SnarkjsJsonWriter.g2("vk_gamma_2", gammaG2);
        var delta = SnarkjsJsonWriter.g2("vk_delta_2", deltaG2);
        var icList = new ArrayList<List<String>>(ic.length);
        for (int i = 0; i < ic.length; i++) icList.add(SnarkjsJsonWriter.g1("IC[" + i + "]", ic[i]));

        var tree = new LinkedHashMap<String, Object>();
        tree.put("protocol", PROTOCOL);
        tree.put("curve", CURVE);
        tree.put("nPublic", ic.length - 1);
        tree.put("vk_alpha_1", alpha);
        tree.put("vk_beta_2", beta);
        tree.put("vk_gamma_2", gamma);
        tree.put("vk_delta_2", delta);
        tree.put("vk_alphabeta_12", alphaBeta12(alphaG1, betaG2));
        tree.put("IC", icList);
        return SnarkjsJsonWriter.write(tree);
    }

    /** {@code public.json}: {@code publicInputs[i]} is public wire {@code i + 1}, canonical in {@code [0, r)}. */
    public static String publicJson(BigInteger[] publicInputs) {
        return SnarkjsJsonWriter.write(SnarkjsJsonWriter.scalars("public", publicInputs));
    }

    /**
     * The snarkjs {@code vk_alphabeta_12} value for {@code (alpha, beta)}: {@code e(alpha, beta)}
     * under wasmcurves' final exponentiation, i.e. the cube of ZeroJ's pairing (see class docs).
     * Points must already have passed the egress checks.
     */
    static List<List<List<String>>> alphaBeta12(AffineG1 alphaG1, AffineG2 betaG2) {
        var a = new G1Point(Fp.of(alphaG1.x().toBigInteger()), Fp.of(alphaG1.y().toBigInteger()));
        var b = new G2Point(
                Fp2.of(Fp.of(betaG2.x().reBigInt()), Fp.of(betaG2.x().imBigInt())),
                Fp2.of(Fp.of(betaG2.y().reBigInt()), Fp.of(betaG2.y().imBigInt())));
        Fp12 e = BLS12381Pairing.finalExponentiation(BLS12381Pairing.millerLoop(a, b));
        Fp12 cubed = e.square().mul(e);
        return List.of(fp6(cubed.c0()), fp6(cubed.c1()));
    }

    private static List<List<String>> fp6(Fp6 f) {
        return List.of(fp2(f.c0()), fp2(f.c1()), fp2(f.c2()));
    }

    private static List<String> fp2(Fp2 f) {
        return List.of(f.c0().value().toString(), f.c1().value().toString());
    }
}
