package org.zeroj.circuit.lib.zk;

import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.InCircuitElGamal;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;

import java.util.Objects;

/**
 * Typed annotation adapter for the {@code elgamal-jubjub-v1} relations (ADR-0052 D3; spec §9).
 *
 * <h2>Encryption</h2>
 * {@link #encrypt} proves {@code A = [k]·G} and {@code B = [m]·G + [k]·PK}:
 * <ul>
 *   <li>the message is a {@link ZkUInt} declared {@code 1..64} bits wide. A wider declaration is
 *       refused when the circuit is defined;</li>
 *   <li>the randomness is a {@link ZkUInt} declared exactly 252 bits wide. Its wire must not be
 *       a public input or a constant, and its one decomposition drives both scalar
 *       multiplications;</li>
 *   <li>the key is a {@link ZkElGamalPublicKey}.</li>
 * </ul>
 * Bind the result to the statement with {@link ZkElGamalCiphertext#assertAffineEquals}.
 *
 * <pre>{@code
 * @Prove
 * void prove(ZkContext zk,
 *            @Public ZkField keyU, @Public ZkField keyV,
 *            @Public ZkField aU, @Public ZkField aV, @Public ZkField bU, @Public ZkField bV,
 *            @Secret @UInt(bits = 1) ZkUInt vote,
 *            @Secret @UInt(bits = 252) ZkUInt randomness) {
 *     var key = ZkElGamalPublicKey.fromVerifierFixedPublic(zk, keyU, keyV);
 *     ZkElGamal.encrypt(zk, vote, randomness, key).assertAffineEquals(zk, aU, aV, bU, bV);
 * }
 * }</pre>
 *
 * <h2>Discrete-log equality</h2>
 * {@link #assertDiscreteLogEquality} proves {@code P = [x]·G} and {@code D = [x]·X}. All six
 * coordinates must be declared public inputs (spec §9.2), so the verifier, never the prover,
 * chooses the base:
 * <ul>
 *   <li>{@code X = G}, {@code D = P} for a proof of possession;</li>
 *   <li>{@code X} = the admitted ciphertext's handle for a decryption share.</li>
 * </ul>
 * {@code X ∈ 𝔾} is the verifier's precondition. On the host, {@code DleqStatement} supplies the
 * six values in this order.
 *
 * <p>Proofs over these relations need a trusted setup when proved with Groth16 (ADR-0052 D4).
 * The prover's witness holds the secrets as field elements, so proof generation is
 * compatibility/offline class (ADR-0039).
 */
public final class ZkElGamal {

    private ZkElGamal() {}

    private static void requirePrivateFullWidth(ZkContext zk, ZkUInt scalar, String what) {
        if (scalar.bits() != JubjubCurve.SCALAR_BITS) {
            throw new IllegalArgumentException("ElGamal " + what + " must be declared "
                    + JubjubCurve.SCALAR_BITS + " bits wide; got "
                    + scalar.bits());
        }
        zk.builder().api().requireNotPublicOrConstant(scalar.signal().variable());
    }

    /**
     * Encrypts {@code message} under {@code key} with {@code randomness}.
     *
     * @throws IllegalArgumentException if the message width is outside {@code [1, 64]}, the
     *         randomness width is not 252, or the randomness wire is public or constant
     */
    public static ZkElGamalCiphertext encrypt(ZkContext zk, ZkUInt message, ZkUInt randomness,
                                              ZkElGamalPublicKey key) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(randomness, "randomness");
        Objects.requireNonNull(key, "key");
        zk.requireSignal(message.signal());
        zk.requireSignal(randomness.signal());
        key.requireSameContext(zk);
        // Validate before minting any decomposition (the ZkPedersen convention).
        if (message.bits() < 1 || message.bits() > InCircuitElGamal.MAX_MESSAGE_BITS) {
            throw new IllegalArgumentException("ElGamal message width must satisfy 1 <= w <= "
                    + InCircuitElGamal.MAX_MESSAGE_BITS + "; got " + message.bits());
        }
        requirePrivateFullWidth(zk, randomness, "randomness");
        InCircuitElGamal.Ciphertext ciphertext = InCircuitElGamal.encrypt(
                zk.builder().api(), key.key(), message.decomposition(), randomness.decomposition());
        return new ZkElGamalCiphertext(zk, ciphertext);
    }

    /**
     * Proves {@code log_G P = log_X D} with witness {@code secret} (spec §9.2).
     *
     * @throws IllegalArgumentException if a coordinate is not a declared public input, or if
     *         {@code secret} is not a private 252-bit value
     */
    public static void assertDiscreteLogEquality(ZkContext zk, ZkUInt secret,
                                                 ZkField baseU, ZkField baseV,
                                                 ZkField keyU, ZkField keyV,
                                                 ZkField shareU, ZkField shareV) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(secret, "secret");
        zk.requireSignal(secret.signal());
        requirePrivateFullWidth(zk, secret, "secret");
        for (ZkField coordinate : new ZkField[]{baseU, baseV, keyU, keyV, shareU, shareV}) {
            zk.requireSignal(Objects.requireNonNull(coordinate, "coordinate").signal());
            // Checked before the secret's decomposition is minted (validate before emitting).
            zk.builder().api().requirePublicInput(coordinate.signal().variable());
        }
        InCircuitElGamal.assertDiscreteLogEquality(zk.builder().api(), secret.decomposition(),
                baseU.signal().variable(), baseV.signal().variable(),
                keyU.signal().variable(), keyV.signal().variable(),
                shareU.signal().variable(), shareV.signal().variable());
    }
}
