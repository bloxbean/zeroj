package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.lib.Comparators;
import com.bloxbean.cardano.zeroj.circuit.lib.PoseidonN;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * In-circuit EdDSA-Jubjub verification gadget, matching the off-circuit
 * {@link EdDSAJubjub} scheme.
 *
 * <p>Use case: a credential holder proves "I have a signature {@code sig}
 * from issuer {@code pk} over message {@code msg}", without revealing the
 * signature itself. Inside the SNARK, the gadget emits the constraints
 * {@code [S]·G == R + [k]·pk} where {@code k = Poseidon(R.u, R.v, msg) mod l},
 * plus range / malleability checks.
 *
 * <h2>Security checklist</h2>
 * Enforced by this gadget:
 * <ol>
 *   <li>{@code S < l} — malleability prevention (rejects the {@code S + l} alias).</li>
 *   <li>Challenge {@code k} recomputed in-circuit via Poseidon.</li>
 *   <li>Verification equation {@code [S]·G == R + [k]·pk}.</li>
 * </ol>
 *
 * <p><b>IMPORTANT — subgroup-check contract</b>: this gadget does <b>not</b>
 * perform in-circuit subgroup checks on {@code pk} or {@code R} (doing so
 * would add ~5000 constraints per check — the cost of an {@code [l]·P}
 * scalar-mul). Both points must therefore come from a trusted source:
 * <ul>
 *   <li>{@code pk}: check {@link JubjubPoint#isInSubgroup} <b>off-circuit</b>
 *       at issuer-registration time. Afterwards treat pk as a trusted
 *       circuit constant or public input.</li>
 *   <li>{@code R}: comes from the issued signature. An attacker who controls
 *       the signer can substitute a small-order R and fabricate a matching
 *       S. For credential schemes where the issuer is trusted, this is
 *       acceptable. For adversarial-signer protocols, add an explicit
 *       subgroup-check gadget around this verify (see {@link #verify}).</li>
 * </ul>
 */
public final class InCircuitEdDSAJubjub {

    private InCircuitEdDSAJubjub() {}

    /**
     * Asserts that {@code (R, S)} is a valid EdDSA-Jubjub signature of
     * {@code msg} under public key {@code pk}. Throws a witness-evaluation
     * error if not.
     *
     * <p>The {@code scalarBits} parameter is the width in bits used for
     * fixed/variable-base scalar-mul. For Jubjub use {@code 252}.
     *
     * @param api         circuit API
     * @param pk          issuer public key (asserted in-subgroup by caller)
     * @param msg         message digest as a field element
     * @param rPoint      signature component R (asserted in-subgroup by caller)
     * @param s           signature scalar S (asserted {@code < l} by this gadget)
     * @param scalarBits  bits for scalar-mul (typically 252)
     */
    public static void verify(CircuitAPI api,
                              InCircuitJubjub.Point pk,
                              Variable msg,
                              InCircuitJubjub.Point rPoint,
                              Variable s,
                              Variable kModL,
                              Variable kQuotient) {
        api.requireField(PoseidonParamsBLS12_381T3.INSTANCE.field());

        Variable lConstant = api.constant(JubjubCurve.SUBGROUP_ORDER);

        // 1. Enforce S < l (malleability prevention).
        Variable sLtL = Comparators.lessThan(api, s, lConstant, 252);
        api.assertEqual(sLtL, api.constant(1));

        // 2. Recompute k_raw = Poseidon(R.u, R.v, pk.u, pk.v, msg) and assert
        //    it equals kQuotient · l + kModL. Including pk in the challenge
        //    prevents key-substitution attacks; matching the 5-input Poseidon
        //    of the off-circuit EdDSAJubjub.computeChallenge.
        Variable kRaw = PoseidonN.hash(api, PoseidonParamsBLS12_381T3.INSTANCE,
                rPoint.u(), rPoint.v(), pk.u(), pk.v(), msg);
        Variable reconstructed = api.add(api.mul(kQuotient, lConstant), kModL);
        api.assertEqual(kRaw, reconstructed);

        // 3. Range checks:
        //    kModL < l (canonical reduction);
        //    kQuotient < 16 (4 bits). p / l ≈ 8.000028, so kRaw ∈ [0, p) admits
        //    q ∈ [0, 9] in the worst case; 4 bits (q < 16) gives safe headroom.
        Variable kLtL = Comparators.lessThan(api, kModL, lConstant, 252);
        api.assertEqual(kLtL, api.constant(1));
        api.toBinary(kQuotient, 4); // asserts kQuotient ∈ [0, 2^4)

        // 4. [S]·G (252 bits) and [kModL]·pk (252 bits).
        InCircuitJubjub.Point sG = InCircuitJubjub.scalarMulFixedBase(
                api, JubjubPoint.SUBGROUP_GENERATOR, s, 252);
        InCircuitJubjub.Point kPk = InCircuitJubjub.scalarMulVariableBase(
                api, pk, kModL, 252);

        // 5. R + [k]·pk
        InCircuitJubjub.Point rPlusKPk = InCircuitJubjub.add(api, rPoint, kPk);

        // 6. Assert [S]·G == R + [k]·pk (projective equality).
        api.assertEqual(api.mul(sG.u(), rPlusKPk.z()), api.mul(rPlusKPk.u(), sG.z()));
        api.assertEqual(api.mul(sG.v(), rPlusKPk.z()), api.mul(rPlusKPk.v(), sG.z()));
    }

    /**
     * Witness-helper result from {@link #witnessComputeKReduction}:
     * {@code kModL} is the challenge scalar (≡ {@code Poseidon(...) mod l});
     * {@code kQuotient} is the integer quotient needed by the in-circuit
     * consistency assertion.
     */
    public record KReduction(java.math.BigInteger kModL, java.math.BigInteger kQuotient) {}

    /**
     * Helper for callers: computes the {@link KReduction} witnesses that
     * {@link #verify} requires as secret inputs. {@code kQuotient} is
     * guaranteed to be in {@code [0, 16)}; {@code kModL} is in {@code [0, l)}.
     */
    public static KReduction witnessComputeKReduction(
            JubjubPoint rPoint, JubjubPoint pk, java.math.BigInteger msg) {
        java.math.BigInteger kRaw = com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash
                .hashN(PoseidonParamsBLS12_381T3.INSTANCE,
                        rPoint.affineU(), rPoint.affineV(),
                        pk.affineU(), pk.affineV(), msg);
        java.math.BigInteger[] qr = kRaw.divideAndRemainder(JubjubCurve.SUBGROUP_ORDER);
        return new KReduction(qr[1], qr[0]);
    }
}
