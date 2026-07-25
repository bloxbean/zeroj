package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.circuit.BitDecomposition;
import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.lib.PoseidonN;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;

/**
 * In-circuit EdDSA-Jubjub verification, matching the off-circuit {@link EdDSAJubjub} scheme.
 *
 * <p>Use case: a credential holder proves "I have a signature from issuer {@code pk} over
 * message {@code msg}" without revealing the signature. The gadget emits
 * {@code [S]·G == R + [k]·pk} where {@code k = Poseidon(R.u, R.v, pk.u, pk.v, msg) mod l},
 * plus the range, canonicality, and well-formedness constraints described below.
 *
 * <h2>There is no public {@code verify} here yet</h2>
 * The historical {@code verify(api, Point pk, ..., Point R, ...)} overload took raw
 * extended-coordinate wires and was <b>forgeable</b>: nothing tied {@code T} to {@code U·V/Z},
 * nothing asserted the curve equation, and nothing forbade {@code Z = 0}. A prover could pick
 * {@code R.u}/{@code R.v} freely, solve the verification equation for {@code R.z}/{@code R.t},
 * and obtain an accepted proof for a message that was never signed — with an {@code R} that is
 * not on the curve. That overload is removed rather than patched.
 *
 * <p>{@link #verifyCore} below is the fixed relation, and it is deliberately <b>not public</b>.
 * Verification depends on a trust assumption about {@code pk} that the gadget cannot infer, so
 * the public entry points are named for that assumption — {@code verifyStrict} and
 * {@code verifyWithRegisteredKey} — and arrive in ADR-0037 M3. An unqualified public
 * {@code verify} is never re-exposed, because its key-trust contract would be ambiguous.
 *
 * <h2>What {@code verifyCore} enforces</h2>
 * <ol>
 *   <li>{@code pk} and {@code R} are bound with {@link InCircuitJubjub#witnessAffine}: on the
 *       curve, {@code Z = 1}, {@code T = u·v}. Because {@code Z} is constant, the challenge
 *       hash is taken over genuinely affine coordinates and cannot be ground by rescaling.</li>
 *   <li>{@code S < l} and {@code kModL < l}, on operands that are range-constrained.</li>
 *   <li>The challenge reduction is <b>canonical and complete</b>: {@code q <= 8},
 *       {@code kModL < l}, and {@code q == 8 ⇒ kModL < δ}. See {@link #verifyCore}.</li>
 *   <li>{@code [S]·G == R + [kModL]·pk}, cofactorless.</li>
 * </ol>
 *
 * <h2>What it does not enforce</h2>
 * Prime-order subgroup membership of {@code pk}. Cofactorless verification forces the accepted
 * {@code R} into the subgroup algebraically, but {@code pk} is unconstrained here: a
 * small-order {@code pk} (including the identity) makes {@code [k]·pk = O} and turns the
 * equation into {@code [S]·G == R}, a universal forgery. The M3 entry points close this — one
 * with a real subgroup check, the other by requiring {@code pk} to be verifier-visible.
 *
 * @see <a href="../../../../../../../../../docs/adr/0037-jubjub-soundness-and-hardening.md">ADR-0037</a>
 */
public final class InCircuitEdDSAJubjub {

    private InCircuitEdDSAJubjub() {}

    /** Jubjub scalars are 252 bits; both {@code S} and {@code kModL} live in {@code [0, l)}. */
    static final int SCALAR_BITS = 252;

    /**
     * Maximum quotient in the canonical challenge reduction. {@code kRaw < p = 8l + δ}, so
     * {@code floor(kRaw / l) <= 8}.
     */
    static final int MAX_K_QUOTIENT = 8;

    /**
     * The verification relation, without any assumption about where {@code pk} came from.
     *
     * <p>Package-private on purpose: see the class Javadoc. Callers reach this through a
     * named public entry point that also discharges the {@code pk} trust assumption.
     *
     * <h3>Canonical, complete challenge reduction</h3>
     * The circuit asserts {@code kRaw == kQuotient·l + kModL} over the field. That alone does
     * not pin {@code (kQuotient, kModL)}: since {@code p = 8l + δ}, the pair
     * {@code (q + 8, kModL + δ)} satisfies the same field equation, so a prover could choose
     * between two different challenges for one transcript. Constraining
     * {@code kQuotient <= 8} and {@code kModL < l} is still not enough — {@code q = 8} with a
     * large {@code kModL} makes {@code q·l + kModL} exceed {@code p} and wrap. Adding
     * {@code q == 8 ⇒ kModL < δ} forces {@code q·l + kModL < p} unconditionally, which makes
     * the decomposition unique.
     *
     * <p>It is also <em>complete</em>: every {@code kRaw ∈ [0, p)} has a satisfying witness,
     * namely the true integer quotient and remainder. A flat 3-bit quotient bound would also
     * be sound but would reject the {@code kRaw >= 8l} tail — a completeness hole at
     * probability {@code δ/p ≈ 2^-129} that no randomized test could ever exercise.
     *
     * @param pkU  affine u of the public key (bound and curve-checked here)
     * @param pkV  affine v of the public key
     * @param msg  message field element
     * @param rU   affine u of the signature point R
     * @param rV   affine v of the signature point R
     * @param s    signature scalar S, asserted {@code < l}
     * @param kModL     challenge witness, asserted {@code < l} and canonical
     * @param kQuotient reduction quotient witness, asserted {@code <= 8} and canonical
     * @return the bound public-key point, so callers can add their own {@code pk} checks
     *         without re-binding it
     */
    static InCircuitJubjub.Point verifyCore(CircuitAPI api,
                                            Variable pkU, Variable pkV,
                                            Variable msg,
                                            Variable rU, Variable rV,
                                            Variable s,
                                            Variable kModL,
                                            Variable kQuotient) {
        api.requireField(PoseidonParamsBLS12_381T3.INSTANCE.field());

        // 0. Bind both witness points: on the curve, Z = 1, T = u*v.
        //    Z = 1 is what makes the challenge hash below affine by construction.
        InCircuitJubjub.Point pk = InCircuitJubjub.witnessAffine(api, pkU, pkV);
        InCircuitJubjub.Point rPoint = InCircuitJubjub.witnessAffine(api, rU, rV);

        Variable lConstant = api.constant(JubjubCurve.SUBGROUP_ORDER);

        // 1. Decompose both scalars once. The bits serve the range checks below and the
        //    scalar multiplications in step 5, so neither scalar is decomposed twice.
        BitDecomposition sBits = api.decompose(s, SCALAR_BITS);
        BitDecomposition kBits = api.decompose(kModL, SCALAR_BITS);

        // 2. S < l  (malleability: rejects the S + l alias).
        api.assertEqual(api.lessThan(s, lConstant, SCALAR_BITS), api.constant(1));

        // 3. Recompute the challenge over the affine coordinates. Including pk defends
        //    against key substitution; the arity matches EdDSAJubjub.computeChallenge.
        Variable kRaw = PoseidonN.hash(api, PoseidonParamsBLS12_381T3.INSTANCE,
                rPoint.u(), rPoint.v(), pk.u(), pk.v(), msg);
        api.assertEqual(kRaw, api.add(api.mul(kQuotient, lConstant), kModL));

        // 4. Canonical + complete reduction (see method Javadoc).
        api.decompose(kQuotient, 4);                                    // q < 16
        api.assertEqual(                                                 // q <= 8
                api.lessThan(kQuotient, api.constant(MAX_K_QUOTIENT + 1), 4), api.constant(1));
        api.assertEqual(                                                 // kModL < l
                api.lessThan(kModL, lConstant, SCALAR_BITS), api.constant(1));
        Variable qIsMax = api.isEqual(kQuotient, api.constant(MAX_K_QUOTIENT));
        Variable kLtDelta = api.lessThan(
                kModL, api.constant(JubjubCurve.P_MINUS_EIGHT_L), SCALAR_BITS);
        // q == 8  =>  kModL < delta, i.e. NOT(q == 8 AND kModL >= delta)
        api.assertEqual(api.mul(qIsMax, api.sub(api.constant(1), kLtDelta)), api.constant(0));

        // 5. [S]·G and [kModL]·pk, reusing the decompositions from step 1.
        InCircuitJubjub.Point sG = InCircuitJubjub.scalarMulFixedBase(
                api, JubjubPoint.SUBGROUP_GENERATOR, sBits);
        InCircuitJubjub.Point kPk = InCircuitJubjub.scalarMulVariableBase(api, pk, kBits);

        // 6. [S]·G == R + [k]·pk, projectively. Cofactorless: this forces the accepted R
        //    into the prime-order subgroup, since both sides' other terms lie there.
        InCircuitJubjub.Point rPlusKPk = InCircuitJubjub.add(api, rPoint, kPk);
        api.assertEqual(api.mul(sG.u(), rPlusKPk.z()), api.mul(rPlusKPk.u(), sG.z()));
        api.assertEqual(api.mul(sG.v(), rPlusKPk.z()), api.mul(rPlusKPk.v(), sG.z()));

        return pk;
    }

    /**
     * Witness values required by the verification relation: {@code kModL} is the challenge
     * scalar {@code Poseidon(...) mod l}, and {@code kQuotient} is the integer quotient the
     * in-circuit canonicality assertion needs.
     */
    public record KReduction(BigInteger kModL, BigInteger kQuotient) {}

    /**
     * Computes the {@link KReduction} witnesses for a given transcript.
     *
     * <p>The returned pair is the unique canonical one: {@code kQuotient ∈ [0, 8]} and
     * {@code kModL ∈ [0, l)} with {@code kQuotient·l + kModL == kRaw} over the integers.
     * Because {@code kRaw < p = 8l + δ}, the quotient can only reach 8 when
     * {@code kRaw >= 8l}, in which case {@code kModL < δ} automatically — so the witness
     * always satisfies the in-circuit constraints.
     */
    public static KReduction witnessComputeKReduction(
            JubjubPoint rPoint, JubjubPoint pk, BigInteger msg) {
        BigInteger kRaw = PoseidonHash.hashN(PoseidonParamsBLS12_381T3.INSTANCE,
                rPoint.affineU(), rPoint.affineV(), pk.affineU(), pk.affineV(), msg);
        BigInteger[] qr = kRaw.divideAndRemainder(JubjubCurve.SUBGROUP_ORDER);
        BigInteger q = qr[0];
        if (q.compareTo(BigInteger.valueOf(MAX_K_QUOTIENT)) > 0) {
            // Unreachable for kRaw < p; a violation means the Poseidon output was not
            // reduced into the base field, which would silently break the circuit.
            throw new IllegalStateException(
                    "Challenge quotient " + q + " exceeds " + MAX_K_QUOTIENT
                            + "; Poseidon output was not reduced mod p");
        }
        return new KReduction(qr[1], q);
    }
}
