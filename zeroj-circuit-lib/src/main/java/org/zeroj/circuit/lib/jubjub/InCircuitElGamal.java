package org.zeroj.circuit.lib.jubjub;

import org.zeroj.circuit.BitDecomposition;
import org.zeroj.circuit.CircuitAPI;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.lang.ref.WeakReference;
import java.math.BigInteger;
import java.util.Objects;

/**
 * In-circuit relations of {@code elgamal-jubjub-v1} (spec §9, ADR-0052 D3), at the
 * {@link CircuitAPI} level. The typed annotation adapter is
 * {@code org.zeroj.circuit.lib.zk.ZkElGamal}.
 *
 * <h2>Encryption, {@code R_enc(w)}</h2>
 * {@link #encrypt} proves {@code A = [k]·G} and {@code B = [m]·G + [k]·PK}:
 * <ul>
 *   <li>the message decomposition has width {@code 1 ≤ w ≤ 64}. A wider declaration is refused
 *       when the circuit is defined, since at width 252 the witness {@code m = l} satisfies the
 *       same constraints as {@code m = 0};</li>
 *   <li>the randomness decomposition has width exactly 252, and its source wire must not be a
 *       public input or a constant, nor range-confined below 252 bits. That decomposition is
 *       consumed by <b>both</b> scalar multiplications (invariant I5);</li>
 *   <li>the key enters only as a {@link Key}: either verifier-fixed public coordinates
 *       ({@link #keyFromVerifierFixedPublic}) or a witness proved in the subgroup
 *       ({@link #keyWitnessedInSubgroup}). Both assert the curve equation and {@code PK ≠ O}
 *       (invariant I8). A key is bound to the circuit that admitted it. Its constraints live
 *       there, so it is refused anywhere else, like a foreign {@code BitDecomposition}
 *       (ADR-0038 Decision 1).</li>
 * </ul>
 * Cost at width 1: 6,558 rows, pinned in {@code ZkElGamalTest}. That is 505 for the shared
 * decomposition, 1,001 fixed-base, 5,023 variable-base, the key, a select, one addition, and the
 * affine bindings.
 *
 * <p>The guard rails catch authoring mistakes: a randomness wire that is public or constant, or
 * range-confined below 252 bits through its own decomposition or one of its bits. They cannot
 * see every derivation. Randomness computed from public data (for example {@code pub + 0})
 * passes them, as ADR-0051 D2 also notes for Pedersen.
 *
 * <p>Proof generation puts {@code m}, {@code k} and the DLEQ secret in the witness as field
 * elements, so proving is compatibility/offline class (ADR-0039), like host encryption.
 *
 * <h2>Discrete-log equality, {@code R_dleq}</h2>
 * {@link #assertDiscreteLogEquality} proves {@code P = [x]·G} and {@code D = [x]·X} with one
 * decomposition of {@code x}. All six coordinates must be <b>public inputs</b>, so the prover can
 * never choose the base (invariant I9). If {@code X} were a private witness, a trustee who
 * knows {@code x} could set {@code X = [x⁻¹]·D} and "prove" any share. {@code X ∈ 𝔾} is the
 * verifier's precondition. {@code P} and {@code D} may be the identity.
 */
public final class InCircuitElGamal {

    /** The widest message, in bits (spec §4). */
    public static final int MAX_MESSAGE_BITS = 64;

    private InCircuitElGamal() {}

    /**
     * An encryption key admitted through one of the two constructors (invariant I8), bound to
     * the circuit that admitted it.
     */
    public static final class Key {
        private final InCircuitJubjub.Point point;
        private final WeakReference<CircuitAPI> owner;

        private Key(CircuitAPI owner, InCircuitJubjub.Point point) {
            this.owner = new WeakReference<>(owner);
            this.point = point;
        }

        /** The key as an extended point with {@code Z = 1}. */
        public InCircuitJubjub.Point point() {
            return point;
        }
    }

    /**
     * A ciphertext computed in-circuit: an unchecked output carrier like
     * {@link InCircuitJubjub.Point}. Bind it to the statement with {@link #assertAffineEquals}.
     */
    public record Ciphertext(InCircuitJubjub.Point handle, InCircuitJubjub.Point blinded) {}

    /**
     * A key whose affine coordinates are public inputs fixed by the verifier. Asserts the curve
     * equation and {@code PK ≠ O}. Subgroup membership is the <b>verifier's obligation</b>,
     * discharged when it fixes the key (spec §9.1, §9.3).
     *
     * @throws IllegalArgumentException if a coordinate is not a declared public input
     */
    public static Key keyFromVerifierFixedPublic(CircuitAPI api, Variable u, Variable v) {
        requireBls12381(api);
        api.requirePublicInput(u);
        api.requirePublicInput(v);
        InCircuitJubjub.Point point = InCircuitJubjub.witnessAffine(api, u, v);
        assertNotIdentityAffine(api, point);
        return new Key(api, point);
    }

    /**
     * A key supplied by the prover, proved in the prime-order subgroup in-circuit (one 252-bit
     * multiplication by {@code l}) and asserted non-identity.
     */
    public static Key keyWitnessedInSubgroup(CircuitAPI api, Variable u, Variable v) {
        requireBls12381(api);
        InCircuitJubjub.Point point = InCircuitJubjub.witnessAffine(api, u, v);
        InCircuitJubjub.assertInPrimeOrderSubgroup(api, point);
        assertNotIdentityAffine(api, point);
        return new Key(api, point);
    }

    /**
     * Proves the encryption relation and returns {@code (A, B)} as computed points. Bind them to
     * the statement with {@link #assertAffineEquals}.
     *
     * @throws IllegalArgumentException if the message width is outside {@code [1, 64]}, the
     *         randomness width is not 252, or the key or a decomposition belongs to another
     *         circuit
     */
    public static Ciphertext encrypt(CircuitAPI api, Key key, BitDecomposition message,
                                     BitDecomposition randomness) {
        requireBls12381(api);
        Objects.requireNonNull(key, "key");
        if (key.owner.get() != api) {
            throw new IllegalArgumentException("the ElGamal key was admitted in a different circuit; its "
                    + "curve, identity and subgroup constraints do not exist in this one");
        }
        Objects.requireNonNull(message, "message");
        requireMessageWidth(message.width());
        requireHidingScalar(api, randomness);
        api.requireOwned(message);

        InCircuitJubjub.Point handle =
                InCircuitJubjub.scalarMulFixedBase(api, JubjubPoint.SUBGROUP_GENERATOR, randomness);
        InCircuitJubjub.Point mask = InCircuitJubjub.scalarMulVariableBase(api, key.point, randomness);
        InCircuitJubjub.Point encoded = message.width() == 1
                ? InCircuitJubjub.select(api, message.bit(0),
                        InCircuitJubjub.constant(api, JubjubPoint.SUBGROUP_GENERATOR),
                        InCircuitJubjub.identity(api))
                : InCircuitJubjub.scalarMulFixedBase(api, JubjubPoint.SUBGROUP_GENERATOR, message);
        return new Ciphertext(handle, InCircuitJubjub.add(api, encoded, mask));
    }

    /**
     * Proves {@code P = [x]·G} and {@code D = [x]·X} (spec §9.2) with one decomposition of
     * {@code x}. All six coordinates must be declared public inputs.
     *
     * @throws IllegalArgumentException if a coordinate is not a public input, or if {@code x} is
     *         not a 252-bit owned decomposition of a private, unconfined wire
     */
    public static void assertDiscreteLogEquality(CircuitAPI api, BitDecomposition x,
                                                 Variable baseU, Variable baseV,
                                                 Variable keyU, Variable keyV,
                                                 Variable shareU, Variable shareV) {
        requireBls12381(api);
        for (Variable coordinate : new Variable[]{baseU, baseV, keyU, keyV, shareU, shareV}) {
            api.requirePublicInput(Objects.requireNonNull(coordinate, "coordinate"));
        }
        requireHidingScalar(api, x);
        InCircuitJubjub.Point base = InCircuitJubjub.witnessAffine(api, baseU, baseV);
        InCircuitJubjub.Point key =
                InCircuitJubjub.scalarMulFixedBase(api, JubjubPoint.SUBGROUP_GENERATOR, x);
        InCircuitJubjub.Point share = InCircuitJubjub.scalarMulVariableBase(api, base, x);
        assertAffineEquals(api, key, keyU, keyV);
        assertAffineEquals(api, share, shareU, shareV);
    }

    /**
     * Asserts that a computed point has the given affine coordinates: {@code Z ≠ 0},
     * {@code u·Z = U} and {@code v·Z = V}.
     */
    public static void assertAffineEquals(CircuitAPI api, InCircuitJubjub.Point point,
                                          Variable affineU, Variable affineV) {
        requireBls12381(api);
        api.assertNotEqual(point.z(), api.constant(BigInteger.ZERO));
        api.assertEqual(api.mul(affineU, point.z()), point.u());
        api.assertEqual(api.mul(affineV, point.z()), point.v());
    }

    static void requireMessageWidth(int width) {
        if (width < 1 || width > MAX_MESSAGE_BITS) {
            throw new IllegalArgumentException("ElGamal message width must satisfy 1 <= w <= "
                    + MAX_MESSAGE_BITS + "; got " + width
                    + " (a width-252 message admits m = l, which aliases m = 0)");
        }
    }

    private static void requireHidingScalar(CircuitAPI api, BitDecomposition scalar) {
        Objects.requireNonNull(scalar, "scalar");
        if (scalar.width() != JubjubCurve.SCALAR_BITS) {
            throw new IllegalArgumentException("ElGamal secret scalars must be decomposed at "
                    + JubjubCurve.SCALAR_BITS + " bits; got " + scalar.width());
        }
        api.requireOwned(scalar);
        api.requireNotPublicOrConstant(scalar.source());
        api.requireHidingRange(scalar.source(), JubjubCurve.SCALAR_BITS);
        api.requireHidingBits(scalar.bits(), JubjubCurve.SCALAR_BITS);
    }

    /**
     * {@code u ≠ 0} for an affine curve point. On the curve {@code u = 0} forces
     * {@code v = ±1}, so this excludes exactly the identity and the order-2 point
     * {@code (0, −1)}, which is not a valid key either.
     */
    private static void assertNotIdentityAffine(CircuitAPI api, InCircuitJubjub.Point point) {
        api.assertNotEqual(point.u(), api.constant(BigInteger.ZERO));
    }

    private static void requireBls12381(CircuitAPI api) {
        Objects.requireNonNull(api, "api");
        api.requireField(PoseidonParamsBLS12_381T3.INSTANCE.field());
    }
}
