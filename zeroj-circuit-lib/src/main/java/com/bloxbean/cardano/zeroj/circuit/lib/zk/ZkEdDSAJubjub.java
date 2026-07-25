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
 * <p>Public key and signature points must be curve-valid subgroup points before
 * they are bound with {@link ZkJubjubPoint#fromTrustedAffine}. This verifier
 * additionally rejects the identity public key in-circuit.
 */
public final class ZkEdDSAJubjub {

    private ZkEdDSAJubjub() {}

    public record KReduction(BigInteger kModL, BigInteger kQuotient) {}

    /**
     * @deprecated <b>Withdrawn — this verifier was forgeable.</b> Nothing constrained the
     *         {@code Z}/{@code T} wires of the bound points, so a prover could solve them
     *         against the verification equation and obtain an accepted proof for a message
     *         that was never signed. There was also no small-order check on the public key,
     *         making {@code pk = IDENTITY} a universal forgery.
     *
     *         <p>The fixed relation exists but is deliberately not public yet: verification
     *         depends on a trust assumption about {@code pk} that this API cannot infer.
     *         ADR-0037 M3 replaces this method with two entry points named for that
     *         assumption — {@code verifyStrict} (subgroup-checks {@code pk} in-circuit; use
     *         when {@code pk} is prover-supplied) and {@code verifyWithRegisteredKey}
     *         (requires {@code pk} to be a public input or constant). An unqualified
     *         {@code verify} is not coming back.
     *
     *         <p>{@link #witnessComputeKReduction} is unaffected and still correct.
     * @throws UnsupportedOperationException always
     */
    @Deprecated(forRemoval = true, since = "0.1.0")
    public static void verify(
            ZkContext zk,
            ZkJubjubPoint publicKey,
            ZkField message,
            ZkJubjubPoint rPoint,
            ZkUInt s,
            ZkUInt kModL,
            ZkUInt kQuotient) {
        throw new UnsupportedOperationException(
                "ZkEdDSAJubjub.verify is withdrawn: the in-circuit verifier it called was "
                        + "forgeable (ADR-0037 Decision 1). Use verifyStrict(...) or "
                        + "verifyWithRegisteredKey(...), landing in ADR-0037 M3.");
    }

    public static KReduction witnessComputeKReduction(
            JubjubPoint rPoint,
            JubjubPoint publicKey,
            BigInteger message) {
        var reduction = InCircuitEdDSAJubjub.witnessComputeKReduction(rPoint, publicKey, message);
        return new KReduction(reduction.kModL(), reduction.kQuotient());
    }

    private static void validateInputs(
            ZkContext zk,
            ZkJubjubPoint publicKey,
            ZkField message,
            ZkJubjubPoint rPoint,
            ZkUInt s,
            ZkUInt kModL,
            ZkUInt kQuotient) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(rPoint, "rPoint");
        Objects.requireNonNull(s, "s");
        Objects.requireNonNull(kModL, "kModL");
        Objects.requireNonNull(kQuotient, "kQuotient");
        publicKey.requireSameContext(zk);
        rPoint.requireSameContext(zk);
        zk.requireSignal(message.signal());
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
