package org.zeroj.bls12381.spi;

import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.spi.Bls12381ProviderConformance.Encoding;

import static org.junit.jupiter.api.Assertions.*;

/** ADR-0062 I8: the shared provider corpus against the pure-Java provider and codecs. */
class PureJavaProviderConformanceTest {
    private static final Bls12381Provider PROVIDER = Bls12381Providers.pureJava();

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
    void malformedEncodings() {
        for (Encoding e : Bls12381ProviderConformance.g1Encodings()) {
            assertEquals(e.valid(), accepts(() -> Bls12381Codecs.g1FromUncompressed(e.bytes())), "G1 " + e);
        }
        for (Encoding e : Bls12381ProviderConformance.g2Encodings()) {
            assertEquals(e.valid(), accepts(() -> Bls12381Codecs.g2FromUncompressed(e.bytes())), "G2 " + e);
        }
    }

    private static boolean accepts(Runnable decode) {
        try {
            decode.run();
            return true;
        } catch (IllegalArgumentException rejected) {
            return false;
        }
    }
}
