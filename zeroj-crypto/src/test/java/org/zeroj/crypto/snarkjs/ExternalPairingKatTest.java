package org.zeroj.crypto.snarkjs;

import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.field.Fp12;
import org.zeroj.bls12381.pairing.BLS12381Pairing;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Reproduced only with locked ffjavascript, never by regenerating from ZeroJ. */
class ExternalPairingKatTest {
    @Test void allTwelveGeneratorCoefficientsMatchExternalConvention() throws Exception {
        String expected;
        try (var in = getClass().getResourceAsStream(
                "/test-vectors/pairing-bls12381/ffjavascript-0.3.1-generator.txt")) {
            assertNotNull(in);
            expected = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
        }
        Fp12 e = BLS12381Pairing.finalExponentiation(BLS12381Pairing.millerLoop(
                Bls12381Generators.G1, Bls12381Generators.G2));
        // ADR-0047: ffjavascript final exponent convention is 3 * ZeroJ's exponent.
        Fp12 cubed = e.square().mul(e);
        assertEquals(expected.lines().toList(), coefficients(cubed));
        assertNotEquals(expected.lines().toList(), coefficients(e));
    }

    private static List<String> coefficients(Fp12 e) {
        return List.of(e.c0().c0().c0(), e.c0().c0().c1(), e.c0().c1().c0(), e.c0().c1().c1(),
                e.c0().c2().c0(), e.c0().c2().c1(), e.c1().c0().c0(), e.c1().c0().c1(),
                e.c1().c1().c0(), e.c1().c1().c1(), e.c1().c2().c0(), e.c1().c2().c1())
                .stream().map(fp -> fp.value().toString()).toList();
    }
}
