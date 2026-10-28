package org.zeroj.blst;

import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.Bls12381ProviderConformance;
import org.zeroj.bls12381.spi.Bls12381ProviderConformance.Encoding;
import org.zeroj.blst.ffm.BlstCurve;
import org.zeroj.blst.ffm.BlstCurve.PointStatus;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0062 I8: the shared provider corpus against the blst provider, and the malformed-encoding
 * corpus against blst's own decoder ({@code blst_p*_deserialize} + subgroup check).
 */
class BlstProviderConformanceTest {
    private static final Bls12381Provider PROVIDER = BlstBls12381Provider.createDefault();
    private static final Set<PointStatus> ACCEPTED = Set.of(PointStatus.VALID, PointStatus.IDENTITY);

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
    void malformedEncodingsAgreeWithTheStrictDecoder() {
        for (Encoding e : Bls12381ProviderConformance.g1Encodings()) {
            assertEquals(e.valid(), ACCEPTED.contains(BlstCurve.g1Status(e.bytes())), "G1 " + e);
        }
        for (Encoding e : Bls12381ProviderConformance.g2Encodings()) {
            assertEquals(e.valid(), ACCEPTED.contains(BlstCurve.g2Status(e.bytes())), "G2 " + e);
        }
    }
}
