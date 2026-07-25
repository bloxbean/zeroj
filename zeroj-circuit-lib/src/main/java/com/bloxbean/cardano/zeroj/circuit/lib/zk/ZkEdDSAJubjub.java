package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubPoint;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Symbolic EdDSA-Jubjub verification adapter for annotation-based circuits.
 *
 * <p>Two entry points, named for the assumption they make about the public key. There is no
 * unqualified {@code verify}: which one is correct depends on whether the prover chooses
 * {@code pk}, and that is not something the gadget can infer.
 *
 * <ul>
 *   <li>{@link #verifyStrict} — subgroup-checks {@code pk} inside the circuit. Correct
 *       whenever {@code pk} is prover-supplied. Costs ~8.5k extra constraints.</li>
 *   <li>{@link #verifyWithRegisteredKey} — requires {@code pk} to be a public input or
 *       constant, enforced by the DSL, and leaves registry binding to the final verifier.</li>
 * </ul>
 *
 * <p>Points are passed as affine coordinates and bound by the gadget; there is no way to hand
 * it raw extended coordinates, because unconstrained {@code Z}/{@code T} wires were solvable
 * against the verification equation and produced accepted proofs for never-signed messages.
 *
 * @see <a href="../../../../../../../../../docs/specs/jubjub-eddsa-v1.md">docs/specs/jubjub-eddsa-v1.md</a>
 * @see <a href="../../../../../../../../../docs/adr/0037-jubjub-soundness-and-hardening.md">ADR-0037</a>
 */
public final class ZkEdDSAJubjub {

    private ZkEdDSAJubjub() {}

    public record KReduction(BigInteger kModL, BigInteger kQuotient) {}

    /**
     * Verifies with an in-circuit prime-order subgroup check on {@code pk}.
     *
     * <p>Use when the public key is a private witness or is selected by the prover.
     */
    public static void verifyStrict(
            ZkContext zk,
            ZkField publicKeyU,
            ZkField publicKeyV,
            ZkField message,
            ZkField rU,
            ZkField rV,
            ZkUInt s,
            ZkUInt kModL,
            ZkUInt kQuotient) {
        validateInputs(zk, publicKeyU, publicKeyV, message, rU, rV, s, kModL, kQuotient);
        InCircuitEdDSAJubjub.verifyStrict(
                zk.builder().api(),
                publicKeyU.signal().variable(), publicKeyV.signal().variable(),
                message.signal().variable(),
                rU.signal().variable(), rV.signal().variable(),
                s.signal().variable(),
                kModL.signal().variable(),
                kQuotient.signal().variable());
    }

    /**
     * Verifies where {@code pk} is a public input or circuit constant.
     *
     * <p>The DSL rejects a secret or derived {@code pk} wire at circuit-definition time.
     * Binding that public value to a subgroup-checked registry entry remains the final
     * verifier's obligation — being verifier-visible is not the same as being a valid key.
     */
    public static void verifyWithRegisteredKey(
            ZkContext zk,
            ZkField publicKeyU,
            ZkField publicKeyV,
            ZkField message,
            ZkField rU,
            ZkField rV,
            ZkUInt s,
            ZkUInt kModL,
            ZkUInt kQuotient) {
        validateInputs(zk, publicKeyU, publicKeyV, message, rU, rV, s, kModL, kQuotient);
        InCircuitEdDSAJubjub.verifyWithRegisteredKey(
                zk.builder().api(),
                publicKeyU.signal().variable(), publicKeyV.signal().variable(),
                message.signal().variable(),
                rU.signal().variable(), rV.signal().variable(),
                s.signal().variable(),
                kModL.signal().variable(),
                kQuotient.signal().variable());
    }

    /**
     * Computes the {@code (kModL, kQuotient)} witnesses the verification relation requires.
     *
     * <p>The pair is canonical: {@code kQuotient ∈ [0, 8]}, {@code kModL ∈ [0, l)}, and
     * {@code kQuotient·l + kModL == kRaw} over the integers.
     */
    public static KReduction witnessComputeKReduction(
            JubjubPoint rPoint,
            JubjubPoint publicKey,
            BigInteger message) {
        var reduction = InCircuitEdDSAJubjub.witnessComputeKReduction(rPoint, publicKey, message);
        return new KReduction(reduction.kModL(), reduction.kQuotient());
    }

    private static void validateInputs(
            ZkContext zk,
            ZkField publicKeyU,
            ZkField publicKeyV,
            ZkField message,
            ZkField rU,
            ZkField rV,
            ZkUInt s,
            ZkUInt kModL,
            ZkUInt kQuotient) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(publicKeyU, "publicKeyU");
        Objects.requireNonNull(publicKeyV, "publicKeyV");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(rU, "rU");
        Objects.requireNonNull(rV, "rV");
        Objects.requireNonNull(s, "s");
        Objects.requireNonNull(kModL, "kModL");
        Objects.requireNonNull(kQuotient, "kQuotient");
        zk.requireSignal(publicKeyU.signal());
        zk.requireSignal(publicKeyV.signal());
        zk.requireSignal(message.signal());
        zk.requireSignal(rU.signal());
        zk.requireSignal(rV.signal());
        zk.requireSignal(s.signal());
        zk.requireSignal(kModL.signal());
        zk.requireSignal(kQuotient.signal());
        if (s.bits() > ZkPedersen.MAX_SCALAR_BITS || kModL.bits() > ZkPedersen.MAX_SCALAR_BITS) {
            throw new IllegalArgumentException("s and kModL must use at most 252 bits");
        }
        if (kQuotient.bits() > 4) {
            throw new IllegalArgumentException("kQuotient must use at most 4 bits");
        }
    }
}
