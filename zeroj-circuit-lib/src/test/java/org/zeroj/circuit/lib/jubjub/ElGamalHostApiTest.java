package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0052 M1: the {@code elgamal-jubjub-v1} host API. Covers the M1 exit criteria
 * (invariants I1–I4, I6, I7, I10, I11, I13–I16) and every M1 negative listed in the ADR,
 * verbatim.
 *
 * <p>Proofs do not exist at this layer (the circuits are M2), so two test doubles stand in for
 * the caller-supplied verifiers. Each checks the statement against secrets or openings known
 * to the test, so a passing verification is a true statement, not a stub returning
 * {@code true}.
 */
class ElGamalHostApiTest {

    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;
    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final JubjubPoint ORDER_2 = JubjubPoint.fromAffine(
            BigInteger.ZERO, JubjubCurve.BASE_FIELD_PRIME.subtract(BigInteger.ONE));
    private static final SecureRandom RNG = new SecureRandom();

    @AfterEach
    void clearObserver() {
        JubjubPoint.clearSecretScheduleObserverForTesting();
    }

    // ------------------------------------------------------------------ test doubles

    /** Accepts a DLEQ statement iff it knows an {@code x} with {@code P = [x]G} and {@code D = [x]X}. */
    static final class KnownSecretsDleqVerifier implements DleqStatementVerifier {
        private final List<BigInteger> secrets = new ArrayList<>();
        final List<DleqStatement> seen = new ArrayList<>();

        KnownSecretsDleqVerifier know(BigInteger... xs) {
            secrets.addAll(Arrays.asList(xs));
            return this;
        }

        @Override
        public boolean verify(DleqStatement s) {
            seen.add(s);
            for (BigInteger x : secrets) {
                if (G.scalarMul(x).projectiveEquals(s.publicKey())) {
                    return s.base().scalarMul(x).projectiveEquals(s.share());
                }
            }
            return false;
        }
    }

    /** Accepts an encryption statement iff a known opening {@code (m, k)} reproduces it with {@code m < 2^w}. */
    static final class OpeningCheckingVerifier implements EncryptionStatementVerifier {
        private final Map<String, BigInteger[]> openings = new HashMap<>();

        void open(JubjubPoint handle, BigInteger m, BigInteger k) {
            openings.put(Arrays.toString(handle.toBytes()), new BigInteger[]{m, k});
        }

        @Override
        public boolean verify(EncryptionStatement s) {
            BigInteger[] opening = openings.get(Arrays.toString(s.handle().toBytes()));
            if (opening == null) return false;
            BigInteger m = opening[0];
            BigInteger k = opening[1];
            if (m.signum() < 0 || m.bitLength() > s.width()) return false;
            return G.scalarMul(k).projectiveEquals(s.handle())
                    && G.scalarMul(m).add(s.key().point().scalarMul(k)).projectiveEquals(s.blinded());
        }
    }

    private static NOfNKeyContext context(BigInteger... secrets) {
        List<VerifiedKeyShare> shares = new ArrayList<>();
        for (BigInteger s : secrets) {
            shares.add(VerifiedKeyShare.fromSecret(ElGamalSecretKey.of(s)));
        }
        return ElGamalPublicKey.aggregate(shares);
    }

    private static RawElGamalCiphertext rawEncrypt(BigInteger m, BigInteger k, JubjubPoint pk) {
        return RawElGamalCiphertext.of(G.scalarMul(k), G.scalarMul(m).add(pk.scalarMul(k)));
    }

    // ------------------------------------------------------------------ round trips

    @Nested
    @DisplayName("Round trips and homomorphism")
    class RoundTrips {

        @Test
        @DisplayName("Single key: encrypt then decrypt at several widths, including 0 and 2^w − 1")
        void singleKey() {
            ElGamalSecretKey sk = ElGamalSecretKey.generate(RNG);
            NOfNKeyContext ctx = NOfNKeyContext.singleKey(sk);
            for (int w : new int[]{1, 2, 8, 16}) {
                for (long m : new long[]{0, 1, (1L << w) - 1}) {
                    ElGamalCiphertext c = ElGamal.encrypt(ctx, m, w, RNG);
                    assertEquals(BigInteger.ONE.shiftLeft(w).subtract(BigInteger.ONE), c.bound());
                    assertEquals(m, ElGamal.decryptWithSecret(c, sk, c.bound().longValueExact()));
                }
            }
        }

        @Test
        @DisplayName("Property: random sums and scalings decrypt to the integer result (n-of-n, 1–5 trustees)")
        void homomorphism() {
            Random rnd = new Random(57);
            for (int round = 0; round < 6; round++) {
                int n = 1 + rnd.nextInt(5);
                List<ElGamalSecretKey> keys = new ArrayList<>();
                List<VerifiedKeyShare> shares = new ArrayList<>();
                for (int j = 0; j < n; j++) {
                    ElGamalSecretKey k = ElGamalSecretKey.generate(RNG);
                    keys.add(k);
                    shares.add(VerifiedKeyShare.fromSecret(k));
                }
                NOfNKeyContext ctx = ElGamalPublicKey.aggregate(shares);
                long expected = 0;
                List<ElGamalCiphertext> cts = new ArrayList<>();
                for (int i = 0; i < 1 + rnd.nextInt(6); i++) {
                    long m = rnd.nextInt(1000);
                    expected += m;
                    cts.add(ElGamal.encrypt(ctx, m, 10, RNG));
                }
                long factor = 1 + rnd.nextInt(5);
                ElGamalCiphertext total = ElGamalCiphertext.sum(cts).scale(factor);
                List<VerifiedDecryptionShare> ds = new ArrayList<>();
                for (ElGamalSecretKey k : keys) {
                    ds.add(ElGamal.decryptionShare(k, total));
                }
                long maxPlaintext = total.bound().longValueExact();
                assertEquals(expected * factor, ElGamal.decrypt(total, ds, maxPlaintext));
                // Pairwise add agrees with the one-pass sum.
                ElGamalCiphertext folded = cts.get(0);
                for (int i = 1; i < cts.size(); i++) folded = folded.add(cts.get(i));
                assertArrayEquals(ElGamalCiphertext.sum(cts).encode(), folded.encode());
            }
        }

        @Test
        @DisplayName("I4: encryption randomness is 64 bytes reduced mod l, as pedersen-jubjub-v1 §3.1")
        void randomnessSampling() {
            byte[] fixed = new byte[64];
            Arrays.fill(fixed, (byte) 0xA5);
            SecureRandom stub = new SecureRandom() {
                @Override
                public void nextBytes(byte[] bytes) {
                    System.arraycopy(fixed, 0, bytes, 0, bytes.length);
                }
            };
            ElGamalSecretKey sk = ElGamalSecretKey.of(BigInteger.valueOf(9));
            ElGamalCiphertext c = ElGamal.encrypt(NOfNKeyContext.singleKey(sk), 3, 4, stub);
            BigInteger k = new BigInteger(1, fixed).mod(L);
            assertTrue(G.scalarMul(k).projectiveEquals(c.handle()));
            assertTrue(G.scalarMul(BigInteger.valueOf(3)).add(sk.publicKey().point().scalarMul(k))
                    .projectiveEquals(c.blinded()));
        }

        @Test
        @DisplayName("Secret multiplications run the blinded 316-iteration schedule (encryption ×3, share ×1)")
        void secretSchedule() {
            AtomicInteger schedules = new AtomicInteger();
            List<Integer> lengths = new ArrayList<>();
            ElGamalSecretKey sk = ElGamalSecretKey.of(BigInteger.valueOf(11));
            NOfNKeyContext ctx = NOfNKeyContext.singleKey(sk);
            JubjubPoint.installSecretScheduleObserverForTesting(new JubjubPoint.SecretScheduleObserver() {
                @Override public void scheduleStarted(int iterations) {
                    schedules.incrementAndGet();
                    lengths.add(iterations);
                }
                @Override public void addition() {}
                @Override public void doubling() {}
            });
            ElGamalCiphertext c = ElGamal.encrypt(ctx, 0, 1, RNG);
            assertEquals(3, schedules.get(), "[k]G, [k]PK and [m]G, even for m = 0");
            ElGamal.decryptionShare(sk, c);
            assertEquals(4, schedules.get());
            assertTrue(lengths.stream().allMatch(n -> n == 316), "blinded schedule length: " + lengths);
        }
    }

    // ------------------------------------------------------------------ keys (I1, I2)

    @Nested
    @DisplayName("Keys and aggregation (I1, I2)")
    class Keys {

        @Test
        @DisplayName("Secret keys are canonical and non-zero; toString redacts the secret")
        void secretKeyRange() {
            assertThrows(IllegalArgumentException.class, () -> ElGamalSecretKey.of(BigInteger.ZERO));
            assertThrows(IllegalArgumentException.class, () -> ElGamalSecretKey.of(L));
            assertThrows(IllegalArgumentException.class, () -> ElGamalSecretKey.of(BigInteger.ONE.negate()));
            ElGamalSecretKey sk = ElGamalSecretKey.of(BigInteger.valueOf(12345));
            assertFalse(sk.toString().contains("12345"));
            assertTrue(sk.toString().contains("redacted"));
        }

        @Test
        @DisplayName("Aggregation refuses empty, duplicate and cancelling share sets")
        void aggregationRefusals() {
            assertThrows(IllegalArgumentException.class, () -> ElGamalPublicKey.aggregate(List.of()));
            VerifiedKeyShare a = VerifiedKeyShare.fromSecret(ElGamalSecretKey.of(BigInteger.valueOf(3)));
            VerifiedKeyShare aAgain = VerifiedKeyShare.fromSecret(ElGamalSecretKey.of(BigInteger.valueOf(3)));
            assertThrows(IllegalArgumentException.class, () -> ElGamalPublicKey.aggregate(List.of(a, aAgain)));
            VerifiedKeyShare minusA = VerifiedKeyShare.fromSecret(ElGamalSecretKey.of(L.subtract(BigInteger.valueOf(3))));
            assertThrows(IllegalArgumentException.class, () -> ElGamalPublicKey.aggregate(List.of(a, minusA)),
                    "an identity sum is refused");
        }

        @Test
        @DisplayName("Partial cancellation (P, −P, Q) aggregates to Q: one party knowing both cancelling secrets gains nothing, and Q's holder alone can decrypt")
        void partialCancellation() {
            VerifiedKeyShare p = VerifiedKeyShare.fromSecret(ElGamalSecretKey.of(BigInteger.valueOf(3)));
            VerifiedKeyShare minusP = VerifiedKeyShare.fromSecret(ElGamalSecretKey.of(L.subtract(BigInteger.valueOf(3))));
            VerifiedKeyShare q = VerifiedKeyShare.fromSecret(ElGamalSecretKey.of(BigInteger.valueOf(7)));
            NOfNKeyContext ctx = ElGamalPublicKey.aggregate(List.of(p, minusP, q));
            assertTrue(ctx.jointKey().point().projectiveEquals(G.scalarMul(BigInteger.valueOf(7))));
            assertEquals(3, ctx.size(), "all three stay registered for distributed decryption");
            // Documented consequence (spec §3.2): Q's holder knows the joint secret on its own.
            ElGamalCiphertext c = ElGamal.encrypt(ctx, 5, 3, RNG);
            assertThrows(IllegalArgumentException.class,
                    () -> ElGamal.decryptWithSecret(c, ElGamalSecretKey.of(BigInteger.valueOf(3)), 7));
        }

        @Test
        @DisplayName("I1: identity, small-order and malformed key shares are refused before the verifier runs")
        void keyShareValidation() {
            AtomicInteger calls = new AtomicInteger();
            DleqStatementVerifier counting = s -> { calls.incrementAndGet(); return true; };
            assertThrows(IllegalArgumentException.class, () -> VerifiedKeyShare.verify(JubjubPoint.IDENTITY, counting));
            assertThrows(IllegalArgumentException.class, () -> VerifiedKeyShare.verify(ORDER_2, counting));
            assertThrows(IllegalArgumentException.class,
                    () -> VerifiedKeyShare.verify(G.add(ORDER_2), counting), "mixed-order point");
            assertThrows(IllegalArgumentException.class, () -> VerifiedKeyShare.verify(new byte[31], counting));
            byte[] nonCanonical = new byte[32];
            Arrays.fill(nonCanonical, (byte) 0xFF);
            nonCanonical[31] = 0x7F;
            assertThrows(IllegalArgumentException.class, () -> VerifiedKeyShare.verify(nonCanonical, counting));
            assertEquals(0, calls.get());
        }

        @Test
        @DisplayName("I2, rogue key: a key nobody can prove possession of is refused")
        void rogueKey() {
            BigInteger honest = BigInteger.valueOf(5);
            KnownSecretsDleqVerifier verifier = new KnownSecretsDleqVerifier().know(honest, BigInteger.valueOf(11));
            VerifiedKeyShare honestShare = VerifiedKeyShare.verify(G.scalarMul(honest), verifier);
            DleqStatement pop = verifier.seen.get(0);
            assertEquals(DleqStatement.Kind.POSSESSION, pop.kind());
            assertTrue(pop.base().projectiveEquals(G));
            assertTrue(pop.share().projectiveEquals(pop.publicKey()));
            // PK_rogue = [x]G − PK_honest: the attacker knows x but not log_G PK_rogue.
            JubjubPoint rogue = G.scalarMul(BigInteger.valueOf(42)).add(honestShare.publicKey().point().negate());
            assertThrows(IllegalArgumentException.class, () -> VerifiedKeyShare.verify(rogue, verifier));
            assertThrows(IllegalArgumentException.class,
                    () -> VerifiedKeyShare.verify(G.scalarMul(BigInteger.valueOf(6)), s -> false));
        }

        @Test
        @DisplayName("Contexts compare by joint key and sorted share set, independent of input order")
        void contextEquality() {
            NOfNKeyContext ab = context(BigInteger.valueOf(3), BigInteger.valueOf(5));
            NOfNKeyContext ba = context(BigInteger.valueOf(5), BigInteger.valueOf(3));
            NOfNKeyContext single = context(BigInteger.valueOf(8));
            assertEquals(ab, ba);
            assertEquals(ab.hashCode(), ba.hashCode());
            assertEquals(ab.jointKey(), single.jointKey(), "same joint key 8G");
            assertNotEquals(ab, single, "different share sets are different contexts");
        }
    }

    // ------------------------------------------------------------------ decoding (I3, I11)

    @Nested
    @DisplayName("Decoding and encodings (I3, I11)")
    class Decoding {

        @Test
        @DisplayName("Ciphertext decoding: wrong length, non-canonical and small-order refused; identity accepted (non-square: reference vectors)")
        void ciphertextDecoding() {
            ElGamalSecretKey sk = ElGamalSecretKey.of(BigInteger.valueOf(17));
            byte[] good = ElGamal.encrypt(NOfNKeyContext.singleKey(sk), 1, 1, RNG).encode();
            assertEquals(64, good.length);
            assertArrayEquals(good, RawElGamalCiphertext.decode(good).encode());
            assertThrows(IllegalArgumentException.class, () -> RawElGamalCiphertext.decode(Arrays.copyOf(good, 63)));
            assertThrows(IllegalArgumentException.class, () -> RawElGamalCiphertext.decode(Arrays.copyOf(good, 65)));
            byte[] nonCanonical = good.clone();
            Arrays.fill(nonCanonical, 0, 31, (byte) 0xFF);
            nonCanonical[31] = (byte) 0x7F;
            assertThrows(IllegalArgumentException.class, () -> RawElGamalCiphertext.decode(nonCanonical));
            byte[] smallOrder = good.clone();
            System.arraycopy(ORDER_2.toBytes(), 0, smallOrder, 32, 32);
            assertThrows(IllegalArgumentException.class, () -> RawElGamalCiphertext.decode(smallOrder));
            byte[] identities = new byte[64];
            System.arraycopy(JubjubPoint.IDENTITY.toBytes(), 0, identities, 0, 32);
            System.arraycopy(JubjubPoint.IDENTITY.toBytes(), 0, identities, 32, 32);
            assertTrue(RawElGamalCiphertext.decode(identities).handle().isIdentity());
        }

        @Test
        @DisplayName("Affine import: coordinates must be canonical without reduction, on-curve and in the subgroup")
        void affineImport() {
            JubjubPoint g = G.normalized();
            BigInteger p = JubjubCurve.BASE_FIELD_PRIME;
            assertThrows(IllegalArgumentException.class,
                    () -> RawElGamalCiphertext.fromAffine(g.u().add(p), g.v(), g.u(), g.v()));
            assertThrows(IllegalArgumentException.class,
                    () -> RawElGamalCiphertext.fromAffine(g.u(), g.v(), BigInteger.ONE, BigInteger.ONE));
            assertThrows(IllegalArgumentException.class,
                    () -> RawElGamalCiphertext.fromAffine(BigInteger.ZERO, p.subtract(BigInteger.ONE), g.u(), g.v()));
            RawElGamalCiphertext ok = RawElGamalCiphertext.fromAffine(g.u(), g.v(), g.u(), g.v());
            assertEquals(List.of(g.u(), g.v(), g.u(), g.v()), ok.publicInputs());
        }

        @Test
        @DisplayName("I11: public-input orders are exactly those of spec §8")
        void publicInputOrders() {
            ElGamalSecretKey sk = ElGamalSecretKey.of(BigInteger.valueOf(19));
            NOfNKeyContext ctx = NOfNKeyContext.singleKey(sk);
            BigInteger k = BigInteger.valueOf(23);
            ElGamalCiphertext c = ElGamal.encryptWithRandomness(ctx, BigInteger.ONE, 1, k);
            JubjubPoint a = c.handle();
            JubjubPoint b = c.blinded();
            JubjubPoint pk = ctx.jointKey().point();
            assertEquals(List.of(a.u(), a.v(), b.u(), b.v()), c.publicInputs());
            assertEquals(List.of(pk.u(), pk.v()), ctx.jointKey().publicInputs());
            AtomicReference<EncryptionStatement> captured = new AtomicReference<>();
            ElGamal.admit(c.raw(), ctx, 1, s -> { captured.set(s); return true; });
            assertEquals(List.of(pk.u(), pk.v(), a.u(), a.v(), b.u(), b.v()), captured.get().publicInputs());
            assertEquals(1, captured.get().width());
            VerifiedDecryptionShare share = ElGamal.decryptionShare(sk, c);
            JubjubPoint d = share.share();
            assertEquals(List.of(a.u(), a.v(), pk.u(), pk.v(), d.u(), d.v()), share.statement().publicInputs());
            JubjubPoint g = G.normalized();
            assertEquals(List.of(g.u(), g.v(), pk.u(), pk.v(), pk.u(), pk.v()), sk.possessionStatement().publicInputs());
        }
    }

    // ------------------------------------------------------------------ bounds and admission (I6, I7, I16)

    @Nested
    @DisplayName("Messages, bounds and admission (I6, I7, I10, I16)")
    class Bounds {

        private final ElGamalSecretKey sk = ElGamalSecretKey.of(BigInteger.valueOf(29));
        private final NOfNKeyContext ctx = NOfNKeyContext.singleKey(sk);

        @Test
        @DisplayName("I6: widths outside 1..64 and messages outside [0, 2^w) are refused; m = l is never admitted")
        void messageRange() {
            assertThrows(IllegalArgumentException.class, () -> ElGamal.encrypt(ctx, 0, 0, RNG));
            assertThrows(IllegalArgumentException.class, () -> ElGamal.encrypt(ctx, 0, 65, RNG));
            assertThrows(IllegalArgumentException.class, () -> ElGamal.encrypt(ctx, 2, 1, RNG));
            assertThrows(IllegalArgumentException.class, () -> ElGamal.encrypt(ctx, -1, 8, RNG));
            BigInteger max64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
            ElGamalCiphertext top = ElGamal.encrypt(ctx, max64, 64, RNG);
            assertEquals(max64, top.bound());
            assertThrows(IllegalArgumentException.class,
                    () -> ElGamal.encrypt(ctx, BigInteger.ONE.shiftLeft(64), 64, RNG));
            assertThrows(IllegalArgumentException.class, () -> ElGamal.encrypt(ctx, L, 64, RNG));
            assertThrows(IllegalArgumentException.class,
                    () -> ElGamal.admit(top.raw(), ctx, 65, s -> true));
        }

        @Test
        @DisplayName("I7: bounds combine on add and scale; a bound reaching l is refused")
        void boundArithmetic() {
            ElGamalCiphertext a = ElGamal.encrypt(ctx, 5, 3, RNG);
            ElGamalCiphertext b = ElGamal.encrypt(ctx, 9, 4, RNG);
            assertEquals(BigInteger.valueOf(7 + 15), a.add(b).bound());
            assertEquals(BigInteger.valueOf(7 * 6), a.scale(6).bound());
            assertThrows(IllegalArgumentException.class, () -> a.scale(0));
            assertThrows(IllegalArgumentException.class, () -> a.scale(L));
            ElGamalCiphertext wide = ElGamal.encrypt(ctx, 1, 64, RNG);
            assertThrows(IllegalArgumentException.class, () -> wide.scale(BigInteger.ONE.shiftLeft(190)),
                    "(2^64 − 1)·2^190 ≥ l");
            assertEquals(14, ElGamal.decryptWithSecret(a.add(b), sk, 22));
            assertThrows(IllegalArgumentException.class, () -> ElGamal.decryptWithSecret(a.add(b), sk, 21),
                    "the search limit must cover the established bound");
        }

        @Test
        @DisplayName("I16: admission builds the statement itself and accepts nothing on a failed check")
        void admission() {
            BigInteger k = BigInteger.valueOf(77);
            RawElGamalCiphertext raw = rawEncrypt(BigInteger.valueOf(6), k, ctx.jointKey().point());
            OpeningCheckingVerifier verifier = new OpeningCheckingVerifier();
            verifier.open(raw.handle(), BigInteger.valueOf(6), k);
            assertThrows(IllegalArgumentException.class, () -> ElGamal.admit(raw, ctx, 2, verifier),
                    "6 does not fit 2 bits");
            ElGamalCiphertext admitted = ElGamal.admit(raw, ctx, 3, verifier);
            assertEquals(BigInteger.valueOf(7), admitted.bound());
            assertEquals(6, ElGamal.decryptWithSecret(admitted, sk, 7));
            // Under another context the same bytes are a different statement and fail.
            NOfNKeyContext other = NOfNKeyContext.singleKey(ElGamalSecretKey.of(BigInteger.valueOf(31)));
            assertThrows(IllegalArgumentException.class, () -> ElGamal.admit(raw, other, 3, verifier));
        }

        @Test
        @DisplayName("Serialising drops key and bound: a re-decoded ciphertext is raw and must be admitted again")
        void serialisationIsRaw() {
            ElGamalCiphertext c = ElGamal.encrypt(ctx, 3, 2, RNG);
            RawElGamalCiphertext again = RawElGamalCiphertext.decode(c.encode());
            assertArrayEquals(c.encode(), again.encode());
            // RawElGamalCiphertext has no bound, no context and no decrypt path: only admission.
            assertThrows(IllegalArgumentException.class, () -> ElGamal.admit(again, ctx, 2, s -> false));
        }

        @Test
        @DisplayName("Wrapped terms: Enc(l−1) + Enc(1) decrypts to 0 raw, and Enc(l−1) cannot be admitted at any width ≤ 64")
        void wrapCannotBeAdmitted() {
            JubjubPoint pk = ctx.jointKey().point();
            BigInteger k1 = BigInteger.valueOf(101);
            BigInteger k2 = BigInteger.valueOf(202);
            RawElGamalCiphertext big = rawEncrypt(L.subtract(BigInteger.ONE), k1, pk);
            RawElGamalCiphertext one = rawEncrypt(BigInteger.ONE, k2, pk);
            RawElGamalCiphertext wrapped = big.add(one);
            JubjubPoint m = RawElGamalCiphertext.unmask(wrapped.blinded(),
                    List.of(wrapped.handle().scalarMul(sk.secretScalar())));
            assertTrue(m.isIdentity(), "the raw sum decrypts to 0, an in-range lie");
            OpeningCheckingVerifier verifier = new OpeningCheckingVerifier();
            verifier.open(big.handle(), L.subtract(BigInteger.ONE), k1);
            verifier.open(one.handle(), BigInteger.ONE, k2);
            for (int w = 1; w <= 64; w++) {
                int width = w;
                assertThrows(IllegalArgumentException.class, () -> ElGamal.admit(big, ctx, width, verifier));
            }
            assertEquals(BigInteger.ONE, ElGamal.admit(one, ctx, 1, verifier).bound());
        }

        @Test
        @DisplayName("I10: decryption fails closed when no plaintext in [0, bound] matches")
        void failsClosed() {
            // A lying verifier admits Enc(100) at width 3: the bound is false, so the search fails.
            RawElGamalCiphertext lie = rawEncrypt(BigInteger.valueOf(100), BigInteger.valueOf(5), ctx.jointKey().point());
            ElGamalCiphertext admitted = ElGamal.admit(lie, ctx, 3, s -> true);
            assertThrows(ElGamalDecryptionException.class, () -> ElGamal.decryptWithSecret(admitted, sk, 7));
        }
    }

    // ------------------------------------------------------------------ keys vs contexts (I13)

    @Nested
    @DisplayName("Key contexts (I13)")
    class Contexts {

        @Test
        @DisplayName("Mixed-key add is refused: Enc(1;1,3G) + Enc(1;1,2G)")
        void mixedKeyAdd() {
            NOfNKeyContext three = context(BigInteger.valueOf(3));
            NOfNKeyContext two = context(BigInteger.valueOf(2));
            ElGamalCiphertext c1 = ElGamal.encryptWithRandomness(three, BigInteger.ONE, 1, BigInteger.ONE);
            ElGamalCiphertext c2 = ElGamal.encryptWithRandomness(two, BigInteger.ONE, 1, BigInteger.ONE);
            assertThrows(IllegalArgumentException.class, () -> c1.add(c2));
            assertThrows(IllegalArgumentException.class, () -> ElGamalCiphertext.sum(List.of(c1, c2)));
            // Raw, the same sum decrypts to the wrong in-range value 1 under secret 3.
            RawElGamalCiphertext raw = c1.raw().add(c2.raw());
            JubjubPoint m = RawElGamalCiphertext.unmask(raw.blinded(),
                    List.of(raw.handle().scalarMul(BigInteger.valueOf(3))));
            assertTrue(m.projectiveEquals(G));
        }

        @Test
        @DisplayName("decryptWithSecret refuses secret 4 for (G, 4G) under PK = 3G")
        void wrongSecret() {
            NOfNKeyContext ctx = context(BigInteger.valueOf(3));
            ElGamalCiphertext c = ElGamal.encryptWithRandomness(ctx, BigInteger.ONE, 1, BigInteger.ONE);
            assertTrue(c.handle().projectiveEquals(G));
            assertTrue(c.blinded().projectiveEquals(G.scalarMul(BigInteger.valueOf(4))));
            assertThrows(IllegalArgumentException.class,
                    () -> ElGamal.decryptWithSecret(c, ElGamalSecretKey.of(BigInteger.valueOf(4)), 1));
            assertEquals(1, ElGamal.decryptWithSecret(c, ElGamalSecretKey.of(BigInteger.valueOf(3)), 1));
        }

        @Test
        @DisplayName("A trustee share passed as the full secret is refused, and an unregistered secret cannot make a share")
        void trusteeShareIsNotTheSecret() {
            ElGamalSecretKey s1 = ElGamalSecretKey.of(BigInteger.valueOf(3));
            ElGamalSecretKey s2 = ElGamalSecretKey.of(BigInteger.valueOf(5));
            NOfNKeyContext ctx = ElGamalPublicKey.aggregate(
                    List.of(VerifiedKeyShare.fromSecret(s1), VerifiedKeyShare.fromSecret(s2)));
            ElGamalCiphertext c = ElGamal.encrypt(ctx, 1, 1, RNG);
            assertThrows(IllegalArgumentException.class, () -> ElGamal.decryptWithSecret(c, s1, 1));
            assertThrows(IllegalArgumentException.class,
                    () -> ElGamal.decryptionShare(ElGamalSecretKey.of(BigInteger.valueOf(8)), c),
                    "8 = 3 + 5 is the joint secret, not a registered share");
            assertThrows(IllegalArgumentException.class,
                    () -> ElGamal.decryptionShare(ElGamalSecretKey.of(BigInteger.valueOf(6)), c));
        }
    }

    // ------------------------------------------------------------------ shares (I14, I15)

    @Nested
    @DisplayName("Verified decryption shares (I14, I15)")
    class Shares {

        private final ElGamalSecretKey s1 = ElGamalSecretKey.of(BigInteger.valueOf(3));
        private final ElGamalSecretKey s2 = ElGamalSecretKey.of(BigInteger.valueOf(5));
        private final NOfNKeyContext ctx = ElGamalPublicKey.aggregate(
                List.of(VerifiedKeyShare.fromSecret(s1), VerifiedKeyShare.fromSecret(s2)));
        private final KnownSecretsDleqVerifier verifier =
                new KnownSecretsDleqVerifier().know(BigInteger.valueOf(3), BigInteger.valueOf(5));

        @Test
        @DisplayName("The forged in-range share (D2 = 36G for 35G; keys 3G, 5G; m = 1, k = 7) is refused")
        void forgedShare() {
            ElGamalCiphertext c = ElGamal.encryptWithRandomness(ctx, BigInteger.ONE, 1, BigInteger.valueOf(7));
            assertTrue(c.handle().projectiveEquals(G.scalarMul(BigInteger.valueOf(7))));
            JubjubPoint honest1 = G.scalarMul(BigInteger.valueOf(21));
            JubjubPoint honest2 = G.scalarMul(BigInteger.valueOf(35));
            JubjubPoint forged2 = G.scalarMul(BigInteger.valueOf(36));
            // Raw, the forgery decrypts to 0, an in-range lie.
            assertTrue(RawElGamalCiphertext.unmask(c.blinded(), List.of(honest1, forged2)).isIdentity());
            VerifiedDecryptionShare d1 = VerifiedDecryptionShare.verify(c, s1.publicKey(), honest1, verifier);
            assertThrows(IllegalArgumentException.class,
                    () -> VerifiedDecryptionShare.verify(c, s2.publicKey(), forged2, verifier));
            VerifiedDecryptionShare d2 = VerifiedDecryptionShare.verify(c, s2.publicKey(), honest2.toBytes(), verifier);
            assertEquals(1, ElGamal.decrypt(c, List.of(d1, d2), 1));
            DleqStatement checked = verifier.seen.get(verifier.seen.size() - 1);
            assertEquals(DleqStatement.Kind.DECRYPTION_SHARE, checked.kind());
            assertTrue(checked.base().projectiveEquals(c.handle()), "X is the admitted handle");
            assertTrue(checked.publicKey().projectiveEquals(s2.publicKey().point()), "P is the registered key");
        }

        @Test
        @DisplayName("Missing, repeated, foreign-key, wrong-handle and invalid-proof shares are refused")
        void malformedShareSets() {
            ElGamalCiphertext c = ElGamal.encryptWithRandomness(ctx, BigInteger.ONE, 1, BigInteger.valueOf(7));
            VerifiedDecryptionShare d1 = ElGamal.decryptionShare(s1, c);
            VerifiedDecryptionShare d2 = ElGamal.decryptionShare(s2, c);
            assertThrows(IllegalArgumentException.class, () -> ElGamal.decrypt(c, List.of(d1), 1), "missing");
            assertThrows(IllegalArgumentException.class, () -> ElGamal.decrypt(c, List.of(d1, d1), 1), "repeated");
            assertThrows(IllegalArgumentException.class, () -> ElGamal.decrypt(c, List.of(d1, d2, d2), 1), "extra");
            ElGamalSecretKey foreign = ElGamalSecretKey.of(BigInteger.valueOf(9));
            assertThrows(IllegalArgumentException.class, () -> VerifiedDecryptionShare.verify(c, foreign.publicKey(),
                    c.handle().scalarMul(BigInteger.valueOf(9)), new KnownSecretsDleqVerifier().know(BigInteger.valueOf(9))),
                    "foreign key");
            // Same handle (same k), different B: a share for c does not decrypt c2.
            ElGamalCiphertext c2 = ElGamal.encryptWithRandomness(ctx, BigInteger.ZERO, 1, BigInteger.valueOf(7));
            assertTrue(c2.handle().projectiveEquals(c.handle()));
            VerifiedDecryptionShare e2 = ElGamal.decryptionShare(s2, c2);
            assertThrows(IllegalArgumentException.class, () -> ElGamal.decrypt(c2, List.of(d1, e2), 1),
                    "a share is bound to the exact (A, B, context)");
            assertThrows(IllegalArgumentException.class,
                    () -> VerifiedDecryptionShare.verify(c, s1.publicKey(), c.handle().scalarMul(BigInteger.valueOf(3)), s -> false),
                    "invalid proof");
            assertThrows(IllegalArgumentException.class,
                    () -> VerifiedDecryptionShare.verify(c, s1.publicKey(), ORDER_2, s -> true),
                    "a share outside the subgroup");
            assertEquals(1, ElGamal.decrypt(c, List.of(d2, d1), 1), "order of shares does not matter");
        }

        @Test
        @DisplayName("I15: a share is computed only on an admitted handle; the verified share proves its own statement")
        void sharesOnAdmittedHandles() {
            ElGamalCiphertext c = ElGamal.encrypt(ctx, 1, 1, RNG);
            VerifiedDecryptionShare d1 = ElGamal.decryptionShare(s1, c);
            assertTrue(verifier.verify(d1.statement()), "a locally computed share satisfies its DLEQ statement");
            assertSame(c, d1.ciphertext());
            assertArrayEquals(d1.share().toBytes(), d1.encode());
        }
    }

    // ------------------------------------------------------------------ review round 1 additions

    @Nested
    @DisplayName("Openings, wrong handles, bound properties")
    class ReviewAdditions {

        @Test
        @DisplayName("encryptWithOpening: the opening reproduces (A, B); statement() equals what admit builds; refusals; redacted")
        void opening() {
            ElGamalSecretKey sk = ElGamalSecretKey.of(BigInteger.valueOf(41));
            NOfNKeyContext ctx = NOfNKeyContext.singleKey(sk);
            ElGamalEncryption e = ElGamal.encryptWithOpening(ctx, BigInteger.valueOf(9), 4, RNG);
            JubjubPoint pk = ctx.jointKey().point();
            assertTrue(G.scalarMul(e.randomness()).projectiveEquals(e.ciphertext().handle()));
            assertTrue(G.scalarMul(e.message()).add(pk.scalarMul(e.randomness())).projectiveEquals(e.ciphertext().blinded()));
            assertEquals(4, e.width());
            AtomicReference<EncryptionStatement> built = new AtomicReference<>();
            ElGamal.admit(e.ciphertext().raw(), ctx, 4, s -> { built.set(s); return true; });
            assertEquals(built.get().publicInputs(), e.statement().publicInputs());
            assertEquals(built.get().width(), e.statement().width());
            assertFalse(e.toString().contains(e.randomness().toString()));
            assertFalse(e.toString().contains(e.randomness().toString(16)));
            assertThrows(IllegalArgumentException.class, () -> ElGamal.encryptWithOpening(ctx, BigInteger.ONE, 65, RNG));
            assertThrows(IllegalArgumentException.class, () -> ElGamal.encryptWithOpening(ctx, BigInteger.valueOf(16), 4, RNG));
            assertThrows(IllegalArgumentException.class, () -> ElGamal.encryptWithOpening(ctx, L, 64, RNG));
            assertEquals(9, ElGamal.decryptWithSecret(e.ciphertext(), sk, 15));
        }

        @Test
        @DisplayName("secretScalar round-trips and is the witness of the possession statement")
        void secretScalar() {
            ElGamalSecretKey sk = ElGamalSecretKey.generate(RNG);
            assertEquals(sk.publicKey(), ElGamalSecretKey.of(sk.secretScalar()).publicKey());
            assertTrue(new KnownSecretsDleqVerifier().know(sk.secretScalar()).verify(sk.possessionStatement()));
        }

        @Test
        @DisplayName("Wrong handle: a share computed on another ciphertext's A fails verification; a share verified for another A is refused")
        void wrongHandle() {
            ElGamalSecretKey s1 = ElGamalSecretKey.of(BigInteger.valueOf(3));
            ElGamalSecretKey s2 = ElGamalSecretKey.of(BigInteger.valueOf(5));
            NOfNKeyContext ctx = ElGamalPublicKey.aggregate(
                    List.of(VerifiedKeyShare.fromSecret(s1), VerifiedKeyShare.fromSecret(s2)));
            ElGamalCiphertext c = ElGamal.encryptWithRandomness(ctx, BigInteger.ONE, 1, BigInteger.valueOf(7));
            ElGamalCiphertext other = ElGamal.encryptWithRandomness(ctx, BigInteger.ONE, 1, BigInteger.valueOf(8));
            KnownSecretsDleqVerifier verifier = new KnownSecretsDleqVerifier().know(BigInteger.valueOf(3), BigInteger.valueOf(5));
            JubjubPoint onOtherHandle = other.handle().scalarMul(BigInteger.valueOf(5));
            assertThrows(IllegalArgumentException.class,
                    () -> VerifiedDecryptionShare.verify(c, s2.publicKey(), onOtherHandle, verifier),
                    "D = [sk]A' is not a share of c: the statement uses c's own handle");
            VerifiedDecryptionShare forOther = VerifiedDecryptionShare.verify(other, s2.publicKey(), onOtherHandle, verifier);
            VerifiedDecryptionShare d1 = ElGamal.decryptionShare(s1, c);
            assertThrows(IllegalArgumentException.class, () -> ElGamal.decrypt(c, List.of(d1, forOther), 1),
                    "a share verified for a different handle is refused");
        }

        @Test
        @DisplayName("Property: bounds follow the integer model exactly and are refused exactly at ≥ l")
        void boundProperty() {
            Random rnd = new Random(65);
            NOfNKeyContext ctx = NOfNKeyContext.singleKey(ElGamalSecretKey.of(BigInteger.valueOf(43)));
            ElGamalCiphertext base = ElGamal.encrypt(ctx, 1, 64, RNG);
            BigInteger b = base.bound();
            BigInteger limit = L.subtract(BigInteger.ONE).divide(b); // largest c with c·b < l
            assertEquals(b.multiply(limit), base.scale(limit).bound());
            assertThrows(IllegalArgumentException.class, () -> base.scale(limit.add(BigInteger.ONE)));
            for (int i = 0; i < 40; i++) {
                int w1 = 1 + rnd.nextInt(64);
                int w2 = 1 + rnd.nextInt(64);
                ElGamalCiphertext a = ElGamal.encrypt(ctx, 0, w1, RNG);
                ElGamalCiphertext c = ElGamal.encrypt(ctx, 0, w2, RNG);
                BigInteger model = BigInteger.ONE.shiftLeft(w1).subtract(BigInteger.ONE)
                        .add(BigInteger.ONE.shiftLeft(w2).subtract(BigInteger.ONE));
                assertEquals(model, a.add(c).bound());
                BigInteger factor = new BigInteger(1 + rnd.nextInt(250), rnd).add(BigInteger.ONE);
                if (factor.compareTo(L) >= 0) continue;
                BigInteger scaled = a.bound().multiply(factor);
                if (scaled.compareTo(L) < 0) {
                    assertEquals(scaled, a.scale(factor).bound());
                } else {
                    assertThrows(IllegalArgumentException.class, () -> a.scale(factor));
                }
            }
        }
    }
}
