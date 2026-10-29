package org.zeroj.bls12381.wasm;

import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.Bls12381ProviderConformance;
import org.zeroj.bls12381.spi.Bls12381ProviderConformance.Encoding;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0062 I8: the shared provider corpus against the zkcrypto WASM oracle, and the
 * malformed-encoding corpus against zkcrypto's own checked uncompressed decoder (reached through the
 * raw scalar-multiplication export, which decodes its point argument first).
 */
class WasmProviderConformanceTest {
    private static final Bls12381Provider PROVIDER = WasmBls12381Provider.createDefault();
    private final Bls12381WasmClient client = Bls12381WasmClient.createDefault();

    @Test
    void scalarMultiplication() {
        Bls12381ProviderConformance.scalarMultiplication(PROVIDER, 256, 0x0062_0701L);
    }

    @Test
    void pairingProducts() {
        Bls12381ProviderConformance.pairingProducts(PROVIDER, 64, 0x0062_0702L);
    }

    @Test
    void invalidPointsRejected() {
        Bls12381ProviderConformance.invalidPointsRejected(PROVIDER);
    }

    @Test
    void malformedEncodingsAgreeWithZkcrypto() {
        for (Encoding e : Bls12381ProviderConformance.g1Encodings()) {
            assertEquals(e.valid(), accepts("zeroj_bls12381_g1_scalar_mul", e.bytes()), "G1 " + e);
        }
        for (Encoding e : Bls12381ProviderConformance.g2Encodings()) {
            assertEquals(e.valid(), accepts("zeroj_bls12381_g2_scalar_mul", e.bytes()), "G2 " + e);
        }
    }

    /** Request = point || 32-byte little-endian scalar 1. */
    private boolean accepts(String export, byte[] point) {
        byte[] request = Arrays.copyOf(point, point.length + 32);
        request[point.length] = 1;
        try {
            client.invokeRawForTesting(export, request);
            return true;
        } catch (Bls12381WasmException rejected) {
            return false;
        }
    }
}
