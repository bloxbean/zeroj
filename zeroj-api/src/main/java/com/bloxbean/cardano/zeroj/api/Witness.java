package com.bloxbean.cardano.zeroj.api;

import java.util.Arrays;
import java.util.Objects;

/**
 * Opaque witness data used by provers.
 *
 * <p>The witness contains private inputs that are known only to the prover.
 * Verifiers never see witness data — it is consumed during proof generation
 * and is not part of the verification flow.</p>
 *
 * @param data the raw witness bytes (must not be null)
 */
public record Witness(byte[] data) {

    public Witness {
        Objects.requireNonNull(data, "witness data must not be null");
        data = data.clone(); // defensive copy
    }

    @Override
    public byte[] data() {
        return data.clone(); // defensive copy on read
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Witness w && Arrays.equals(data, w.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }

    @Override
    public String toString() {
        return "Witness[" + data.length + " bytes]";
    }
}
