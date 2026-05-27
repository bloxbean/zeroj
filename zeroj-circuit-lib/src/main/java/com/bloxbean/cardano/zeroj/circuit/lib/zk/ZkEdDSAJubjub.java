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

    public static void verify(
            ZkContext zk,
            ZkJubjubPoint publicKey,
            ZkField message,
            ZkJubjubPoint rPoint,
            ZkUInt s,
            ZkUInt kModL,
            ZkUInt kQuotient) {
        validateInputs(zk, publicKey, message, rPoint, s, kModL, kQuotient);
        publicKey.assertNotIdentity(zk);
        InCircuitEdDSAJubjub.verify(
                zk.builder().api(),
                publicKey.asPoint(),
                message.signal().variable(),
                rPoint.asPoint(),
                s.signal().variable(),
                kModL.signal().variable(),
                kQuotient.signal().variable());
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
