package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0055 I13: every secret multiplication of {@code confidential-note-jubjub-v1} uses the
 * blinded fixed schedule, and none reaches a variable-time multiplication
 * ({@link JubjubPoint#scalarMul} or {@code FastJubjubPoint.scalarMulPublic}). The observer counts
 * both kinds. The only variable-time multiplication on these paths is the public subgroup check
 * {@code [l]·E} of a received ephemeral key, so a stray {@link PedersenCommitment#verify} (which
 * multiplies the secret opening unblinded) or a secret sent down the fast path fails these tests.
 */
class NoteScheduleTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static NoteViewingKey key;
    private static NoteViewingKey other;
    private static NoteScanner scanner;
    private static NoteOpening opening;
    private static JubjubPoint commitment;
    private static byte[] delivery;

    @BeforeAll
    static void setUp() {
        key = NoteViewingKey.generate(RANDOM);
        other = NoteViewingKey.generate(RANDOM);
        scanner = NoteScanner.of(key);
        opening = NoteOpening.random(BigInteger.valueOf(4242), RANDOM);
        commitment = opening.commitment(); // also initializes the Pedersen bases before observing
        delivery = ConfidentialNotes.seal(opening, List.of(key.readerKey()), RANDOM).get(0);
    }

    @Test
    @DisplayName("A full acceptance: three blinded schedules (Agree, then commit's two) and no unblinded multiplication")
    void acceptance() {
        Counter c = observe(() -> scanner.open(delivery, commitment).orElseThrow());
        assertBlinded(c, 3);
        assertEquals(1, c.publicMultiplications, "only the public subgroup check [l]·E; the opening never reaches scalarMul");
    }

    @Test
    @DisplayName("A failed trial decryption (another reader's key): one blinded schedule, no commitment recomputation")
    void failedTrial() {
        NoteScanner otherScanner = NoteScanner.of(other);
        Counter c = observe(() -> otherScanner.open(delivery, commitment));
        assertBlinded(c, 1);
        assertEquals(1, c.publicMultiplications, "only the public subgroup check [l]·E");
    }

    @Test
    @DisplayName("An invalid ephemeral key (identity, mixed order) or a wrong length: no secret work at all")
    void publicChecksFirst() {
        byte[] identityE = delivery.clone();
        System.arraycopy(JubjubPoint.IDENTITY.toBytes(), 0, identityE, 0, 32);
        Counter c = observe(() -> scanner.open(identityE, commitment));
        assertBlinded(c, 0);
        assertEquals(0, c.publicMultiplications, "the identity is refused before the subgroup check");
        Counter shortDelivery = observe(() -> scanner.open(new byte[88], commitment));
        assertBlinded(shortDelivery, 0);
        // E plus a small-order component: still a curve point, so only the subgroup check stops it.
        JubjubPoint order2 = JubjubPoint.fromAffine(BigInteger.ZERO,
                JubjubCurve.BASE_FIELD_PRIME.subtract(BigInteger.ONE));
        byte[] mixed = delivery.clone();
        JubjubPoint e = JubjubPoint.fromBytes(Arrays.copyOf(delivery, 32));
        System.arraycopy(e.add(order2).toBytes(), 0, mixed, 0, 32);
        Counter mixedOrder = observe(() -> scanner.open(mixed, commitment));
        assertBlinded(mixedOrder, 0);
        assertEquals(1, mixedOrder.publicMultiplications, "the subgroup check refuses it");
        assertTrue(scanner.open(mixed, commitment).isEmpty());
    }

    @Test
    @DisplayName("Sealing: two blinded schedules per reader ([e]·G and [8·e]·P); key generation: one")
    void sealing() {
        NoteReaderKey a = NoteViewingKey.generate(RANDOM).readerKey();
        NoteReaderKey b = NoteViewingKey.generate(RANDOM).readerKey();
        NoteReaderKey d = NoteViewingKey.generate(RANDOM).readerKey();
        Counter c = observe(() -> ConfidentialNotes.seal(opening, List.of(a, b, d), RANDOM));
        assertBlinded(c, 6);
        assertEquals(0, c.publicMultiplications);
        Counter g = observe(() -> NoteViewingKey.generate(RANDOM));
        assertBlinded(g, 1);
        assertEquals(0, g.publicMultiplications);
    }

    @Test
    @DisplayName("Control: the observer does see PedersenCommitment.verify's unblinded multiplications")
    void controlVerifyIsVisible() {
        Counter c = observe(() -> PedersenCommitment.verify(commitment, opening.value(), opening.blinding()));
        assertTrue(c.publicMultiplications >= 2, "verify multiplies by the opening unblinded: " + c.publicMultiplications);
        assertFalse(c.schedules.size() > 0, "verify uses no blinded schedule");
    }

    static Counter observe(Supplier<?> operation) {
        Counter counter = new Counter();
        JubjubPoint.installSecretScheduleObserverForTesting(counter);
        try {
            operation.get();
            return counter;
        } finally {
            JubjubPoint.clearSecretScheduleObserverForTesting();
        }
    }

    private static void assertBlinded(Counter counter, int expectedSchedules) {
        assertEquals(expectedSchedules, counter.schedules.size(), "blinded schedules");
        assertTrue(counter.schedules.stream().allMatch(bits -> bits == JubjubPoint.SECRET_SCALAR_BLINDED_SCHEDULE_BITS),
                "a secret multiplication used an unblinded or variable-length schedule: " + counter.schedules);
    }

    static final class Counter implements JubjubPoint.SecretScheduleObserver {
        final List<Integer> schedules = new ArrayList<>();
        int publicMultiplications;

        @Override
        public void scheduleStarted(int iterations) {
            schedules.add(iterations);
        }

        @Override
        public void addition() {
        }

        @Override
        public void doubling() {
        }

        @Override
        public void publicMultiplication() {
            publicMultiplications++;
        }
    }
}
