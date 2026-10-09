package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.IntFunction;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0054 M2: {@code dkg-share-delivery-hpke-v1} through the real {@link DkgParticipant} state
 * machine, one nested class per invariant group. The board model is {@link DkgEncryptedHarness}.
 */
class DkgShareDeliveryTest {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;

    private static DkgConfig config(int t, int n, long attempt) {
        return DkgHarness.config(t, n, "dkg-share-delivery-test", attempt);
    }

    private static List<ThresholdVss.Dealing> dealings(int t, int n) {
        return DkgHarness.dealings(t, n, 54_000 + 10L * t + n);
    }

    private static ThresholdKeyContext context(DkgParticipant p) {
        return p.result().context();
    }

    // ------------------------------------------------------------------ I3

    @Nested
    @DisplayName("I3: the key generation is unchanged")
    class Unchanged {

        @Test
        @DisplayName("Encrypted delivery gives the same transcript digest, QUAL, y, Y_j and x_j as private channels")
        void sameAsPrivateChannels() {
            for (int[] tn : new int[][]{{1, 3}, {2, 5}, {3, 7}}) {
                DkgConfig config = config(tn[0], tn[1], 1);
                List<ThresholdVss.Dealing> d = dealings(tn[0], tn[1]);
                DkgEncryptedHarness enc = DkgEncryptedHarness.fixed(config, d, DkgEncryptedHarness.HONEST).run();
                DkgHarness plain = DkgHarness.fixed(config, d, DkgHarness.HONEST).run();
                assertTrue(enc.aborted.isEmpty(), "aborts: " + enc.aborted);
                assertArrayEquals(DkgTranscript.of(config, plain.transcriptMessages()).digest(),
                        DkgTranscript.of(config, enc.transcriptMessages()).digest(), "digest " + Arrays.toString(tn));
                for (int j = 1; j <= config.n(); j++) {
                    assertEquals(context(plain.participant(j)), context(enc.participant(j)));
                    assertEquals(plain.participant(j).result().secretScalar(), enc.participant(j).result().secretScalar());
                }
                assertEquals(config.n() * (config.n() - 1), enc.sealed.size(), "n(n − 1) envelopes");
            }
        }

        @Test
        @DisplayName("A bad SHARE sealed by dealer 1 draws the same complaint, answer and outcome as over private channels")
        void badShareSameAsPrivateChannels() {
            DkgConfig config = config(2, 5, 1);
            List<ThresholdVss.Dealing> d = dealings(2, 5);
            DkgMessage honest12 = DkgMessage.pair(config, DkgMessage.Kind.SHARE, 1, 2, d.get(0).share(2), d.get(0).sharePrime(2));
            byte[] bad = DkgShareDelivery.sealOne(config, 1, 2, publicKeyOf(2), bump(config, honest12),
                    DkgEncryptedHarness.testKey("ephemeral.1.2"));
            DkgEncryptedHarness enc = DkgEncryptedHarness.fixed(config, d, new DkgEncryptedHarness.Hooks() {
                @Override
                public List<byte[]> envelope(int i, int j, byte[] envelope) {
                    return i == 1 && j == 2 ? List.of(bad) : List.of(envelope);
                }
            }).run();
            DkgHarness plain = DkgHarness.fixed(config, d, (m, honest) ->
                    m.kind() == DkgMessage.Kind.SHARE && m.sender() == 1 && m.subject() == 2
                            ? List.of(new DkgHarness.Delivery(1, 2, bump(config, m).encode())) : honest).run();
            assertArrayEquals(DkgTranscript.of(config, plain.transcriptMessages()).digest(),
                    DkgTranscript.of(config, enc.transcriptMessages()).digest());
            assertEquals(1, enc.posted(2, DkgMessage.Kind.COMPLAINT).size());
            assertEquals(1, enc.posted(3, DkgMessage.Kind.ANSWER).size());
            assertEquals(Set.of(1, 2, 3, 4, 5), context(enc.participant(3)).qual());
        }
    }

    // ------------------------------------------------------------------ I3 under attack (review X-7)

    /**
     * ADR-0053's adversarial suites that can be expressed on an agreed board, rerun over encrypted
     * delivery and compared with the same attack over private channels (ADR-0054 M2 exit
     * criterion). Suites that need different views per recipient (A6, A7, A9) cannot be posted on
     * an agreed board and are not transport-dependent.
     */
    @Nested
    @DisplayName("I3 under attack: board-expressible ADR-0053 adversarial suites give the same outcome as private channels")
    class AdversarialSuites {

        /** The same attack on the board: a tampered SHARE is sealed in its envelope; broadcasts are posted once each. */
        private DkgEncryptedHarness.Hooks onBoard(DkgConfig config, List<ThresholdVss.Dealing> d, DkgHarness.Adversary adversary) {
            DkgHarness bridge = DkgHarness.fixed(config, d, DkgHarness.HONEST);
            return new DkgEncryptedHarness.Hooks() {
                @Override
                public List<byte[]> envelope(int i, int j, byte[] envelope) {
                    DkgMessage share = DkgMessage.pair(config, DkgMessage.Kind.SHARE, i, j, d.get(i - 1).share(j), d.get(i - 1).sharePrime(j));
                    List<byte[]> out = new ArrayList<>();
                    for (DkgHarness.Delivery x : adversary.deliver(share, bridge.honestDeliveries(share))) {
                        out.add(Arrays.equals(x.bytes(), share.encode()) ? envelope
                                : DkgShareDelivery.sealOne(config, i, j, publicKeyOf(j), DkgMessage.decode(config, x.bytes()),
                                DkgEncryptedHarness.testKey("ephemeral." + i + "." + j)));
                    }
                    return out;
                }

                @Override
                public List<byte[]> broadcast(DkgMessage m) {
                    List<byte[]> out = new ArrayList<>();
                    for (DkgHarness.Delivery x : adversary.deliver(m, bridge.honestDeliveries(m))) {
                        if (out.stream().noneMatch(b -> Arrays.equals(b, x.bytes()))) out.add(x.bytes());
                    }
                    return out;
                }
            };
        }

        private void sameOutcome(DkgConfig config, List<ThresholdVss.Dealing> d, DkgHarness.Adversary adversary) {
            DkgHarness plain = DkgHarness.fixed(config, d, adversary).run();
            DkgEncryptedHarness enc = DkgEncryptedHarness.fixed(config, d, onBoard(config, d, adversary)).run();
            assertArrayEquals(DkgTranscript.of(config, plain.transcriptMessages()).digest(),
                    DkgTranscript.of(config, enc.transcriptMessages()).digest(), "transcript digest");
            assertEquals(plain.aborted.keySet(), enc.aborted.keySet(), "aborted participants");
            for (int id : plain.aborted.keySet()) {
                assertEquals(plain.aborted.get(id).reason(), enc.aborted.get(id).reason(), "abort reason of " + id);
            }
            for (int j = 1; j <= config.n(); j++) {
                if (plain.aborted.containsKey(j)) continue;
                assertEquals(context(plain.participant(j)), context(enc.participant(j)), "context of " + j);
                assertEquals(plain.participant(j).result().secretScalar(), enc.participant(j).result().secretScalar(), "x_" + j);
            }
        }

        @Test
        @DisplayName("More than t complaints disqualify the dealer (A2 for it)")
        void tooManyComplaints() {
            DkgConfig config = config(2, 5, 1);
            List<ThresholdVss.Dealing> d = dealings(2, 5);
            sameOutcome(config, d, (m, honest) -> m.kind() == DkgMessage.Kind.SHARE && m.sender() == 1 && m.subject() >= 3
                    ? List.of(new DkgHarness.Delivery(1, m.subject(), bump(config, m).encode())) : honest);
        }

        @Test
        @DisplayName("A complaint answered with a failing pair disqualifies the dealer")
        void badAnswer() {
            DkgConfig config = config(1, 3, 1);
            List<ThresholdVss.Dealing> d = dealings(1, 3);
            sameOutcome(config, d, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.SHARE && m.sender() == 1 && m.subject() == 2) {
                    return List.of(new DkgHarness.Delivery(1, 2, bump(config, m).encode()));
                }
                if (m.kind() == DkgMessage.Kind.ANSWER && m.sender() == 1) {
                    byte[] bad = DkgMessage.pair(config, DkgMessage.Kind.ANSWER, 1, m.subject(), m.s().add(BigInteger.ONE).mod(L), m.sPrime()).encode();
                    List<DkgHarness.Delivery> out = new ArrayList<>();
                    for (DkgHarness.Delivery x : honest) out.add(new DkgHarness.Delivery(1, x.recipient(), bad));
                    return out;
                }
                return honest;
            });
        }

        @Test
        @DisplayName("Phase-2 Feldman cheat: the dealer is marked and reconstructed (A8 for it); the key is unchanged")
        void feldmanCheat() {
            DkgConfig config = config(1, 3, 1);
            List<ThresholdVss.Dealing> d = dealings(1, 3);
            sameOutcome(config, d, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.EXTRACTION && m.sender() == 3) {
                    List<JubjubPoint> forged = new ArrayList<>(m.points());
                    forged.set(1, forged.get(1).add(JubjubPoint.SUBGROUP_GENERATOR).normalized());
                    byte[] bytes = DkgMessage.points(config, DkgMessage.Kind.EXTRACTION, 3, forged).encode();
                    List<DkgHarness.Delivery> out = new ArrayList<>();
                    for (DkgHarness.Delivery x : honest) out.add(new DkgHarness.Delivery(3, x.recipient(), bytes));
                    return out;
                }
                return honest;
            });
        }

        @Test
        @DisplayName("Conflicting COMMITMENTS disqualify; conflicting or withheld EXTRACTION is reconstructed")
        void conflictsAndWithholding() {
            DkgConfig config = config(1, 3, 1);
            List<ThresholdVss.Dealing> d = dealings(1, 3);
            List<ThresholdVss.Dealing> alt = DkgHarness.dealings(1, 3, 54_999);
            for (DkgMessage.Kind kind : List.of(DkgMessage.Kind.COMMITMENTS, DkgMessage.Kind.EXTRACTION)) {
                sameOutcome(config, d, (m, honest) -> {
                    if (m.kind() == kind && m.sender() == 3) {
                        List<JubjubPoint> second = kind == DkgMessage.Kind.COMMITMENTS ? alt.get(2).commitments() : alt.get(2).extraction();
                        byte[] bytes = DkgMessage.points(config, kind, 3, second).encode();
                        List<DkgHarness.Delivery> out = new ArrayList<>(honest);
                        for (DkgHarness.Delivery x : honest) out.add(new DkgHarness.Delivery(3, x.recipient(), bytes));
                        return out;
                    }
                    return honest;
                });
            }
            sameOutcome(config, d, (m, honest) -> m.kind() == DkgMessage.Kind.EXTRACTION && m.sender() == 2 ? List.of() : honest);
        }

        @Test
        @DisplayName("A5: constant terms summing to 0 abort everyone")
        void identityKey() {
            DkgConfig config = config(1, 3, 1);
            List<ThresholdVss.Dealing> d = List.of(
                    ThresholdVss.dealWithCoefficients(new BigInteger[]{BigInteger.ONE, BigInteger.TWO}, new BigInteger[]{BigInteger.ONE, BigInteger.ONE}),
                    ThresholdVss.dealWithCoefficients(new BigInteger[]{BigInteger.TWO, BigInteger.ONE}, new BigInteger[]{BigInteger.TWO, BigInteger.ONE}),
                    ThresholdVss.dealWithCoefficients(new BigInteger[]{L.subtract(BigInteger.valueOf(3)), BigInteger.TEN}, new BigInteger[]{BigInteger.TEN, BigInteger.ONE}));
            sameOutcome(config, d, DkgHarness.HONEST);
            assertEquals(FaultAssumptionViolatedException.Reason.IDENTITY_JOINT_KEY,
                    DkgEncryptedHarness.fixed(config, d, DkgEncryptedHarness.HONEST).run().aborted.get(1).reason());
        }
    }

    static byte[] publicKeyOf(int j) {
        try {
            return X25519Bytes.publicFromPrivate(DkgEncryptedHarness.testKey("recipient." + j));
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }

    static DkgMessage bump(DkgConfig config, DkgMessage share) {
        return DkgMessage.pair(config, DkgMessage.Kind.SHARE, share.sender(), share.subject(), share.s().add(BigInteger.ONE).mod(L), share.sPrime());
    }

    // ------------------------------------------------------------------ I2, I4, I6

    @Nested
    @DisplayName("I2, I4, I6: binding, uniform failure and canonical encodings")
    class Binding {

        /** Runs n = 3, t = 1 with dealer 1's envelope to 2 replaced by {@code forged}; returns 2's complaints. */
        private List<DkgMessage> complaintsOf2(byte[] forged) {
            DkgConfig config = config(1, 3, 1);
            DkgEncryptedHarness h = DkgEncryptedHarness.fixed(config, dealings(1, 3), new DkgEncryptedHarness.Hooks() {
                @Override
                public List<byte[]> envelope(int i, int j, byte[] envelope) {
                    return i == 1 && j == 2 ? (forged == null ? List.of() : List.of(forged)) : List.of(envelope);
                }
            }).run();
            List<DkgMessage> out = new ArrayList<>();
            for (DkgMessage m : h.posted(2, DkgMessage.Kind.COMPLAINT)) if (m.sender() == 2) out.add(m);
            return out;
        }

        private byte[] honestEnvelope(DkgConfig config, int i, int j) {
            DkgEncryptedHarness h = DkgEncryptedHarness.fixed(config, dealings(config.t(), config.n()), DkgEncryptedHarness.HONEST);
            h.run();
            for (Object[] e : h.sealed) if ((int) e[0] == i && (int) e[1] == j) return ((byte[]) e[2]).clone();
            throw new AssertionError("no envelope " + i + "→" + j);
        }

        @Test
        @DisplayName("Every failure kind is equivalent to absence: exactly one complaint by 2 against 1, nothing else")
        void uniformFailure() {
            DkgConfig config = config(1, 3, 1);
            byte[] good = honestEnvelope(config, 1, 2);
            int encAt = DkgShareDeliveryCodec.TAG_E.length + 34;
            int ctAt = encAt + 32;
            List<byte[]> forgeries = new ArrayList<>();
            forgeries.add(null);                                            // missing
            forgeries.add(flip(good, ctAt + 5));                            // tampered ct
            forgeries.add(flip(good, ctAt + 115));                          // tampered tag
            forgeries.add(flip(good, encAt + 3));                           // tampered enc
            byte[] nonCanonical = good.clone();
            nonCanonical[encAt + 31] ^= (byte) 0x80;                        // same u mod p, non-canonical
            forgeries.add(nonCanonical);
            byte[] smallOrder = good.clone();
            Arrays.fill(smallOrder, encAt, encAt + 32, (byte) 0);           // small-order enc
            forgeries.add(smallOrder);
            forgeries.add(Arrays.copyOf(good, good.length - 1));             // truncated
            forgeries.add(Arrays.copyOf(good, good.length + 1));             // extended
            byte[] otherSession = honestEnvelope(config(1, 3, 2), 1, 2);    // replay from another attempt
            forgeries.add(otherSession);
            byte[] toThree = good.clone();
            toThree[DkgShareDeliveryCodec.TAG_E.length + 33] = 3;           // header recipient changed
            forgeries.add(toThree);
            forgeries.add(sealedTo(config, 2, 3, 1, 2));                    // SHARE 1→3 sealed to 2
            forgeries.add(sealedTo(config, 3, 2, 1, 2));                    // SHARE 1→2 sealed to 3's key
            for (int k = 0; k < forgeries.size(); k++) {
                List<DkgMessage> complaints = complaintsOf2(forgeries.get(k));
                assertEquals(1, complaints.size(), "forgery " + k);
                assertEquals(1, complaints.get(0).subject(), "forgery " + k);
            }
            assertEquals(List.of(), complaintsOf2(good), "the genuine envelope draws no complaint");
        }

        /** An envelope from 1 addressed (header) to {@code headerTo}, sealed to {@code keyOf}'s key, carrying SHARE 1→{@code shareTo}. */
        private byte[] sealedTo(DkgConfig config, int shareTo, int keyOf, int sender, int headerTo) {
            ThresholdVss.Dealing d = dealings(config.t(), config.n()).get(sender - 1);
            DkgMessage share = DkgMessage.pair(config, DkgMessage.Kind.SHARE, sender, shareTo, d.share(shareTo), d.sharePrime(shareTo));
            try {
                byte[] pk = X25519Bytes.publicFromPrivate(DkgEncryptedHarness.testKey("recipient." + keyOf));
                Hpke.Sealed s = Hpke.sealBase(pk, DkgShareDeliveryCodec.info(config, sender, headerTo), new byte[0], share.encode(), new SecureRandom());
                return DkgShareDeliveryCodec.envelope(config, sender, headerTo, s.enc(), s.ct());
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        }

        @Test
        @DisplayName("An envelope posted under another author fails authentication and is absent")
        void impersonation() {
            DkgConfig config = config(1, 3, 1);
            byte[] good = honestEnvelope(config, 1, 2);
            DkgEncryptedHarness h = DkgEncryptedHarness.fixed(config, dealings(1, 3), new DkgEncryptedHarness.Hooks() {
                @Override
                public List<byte[]> envelope(int i, int j, byte[] envelope) {
                    return i == 1 && j == 2 ? List.of() : List.of(envelope);
                }

                @Override
                public List<DkgEncryptedHarness.Post> extra(int round) {
                    return round == 1 ? List.of(new DkgEncryptedHarness.Post(3, good)) : List.of();
                }
            }).run();
            assertEquals(1, h.posted(2, DkgMessage.Kind.COMPLAINT).stream().filter(m -> m.sender() == 2).count());
        }

        @Test
        @DisplayName("Codec: exact lengths, tags, session, identifiers and canonical values; profile messages never decode as DKG messages")
        void codec() {
            DkgConfig config = config(1, 3, 1);
            byte[] good = honestEnvelope(config, 1, 2);
            assertEquals(223, good.length);
            assertThrows(IllegalArgumentException.class, () -> DkgMessage.decode(config, good));
            DkgShareDeliveryKeys k = DkgShareDeliveryKeys.fromSecret(config, 2, DkgEncryptedHarness.testKey("recipient.2"));
            byte[] a = k.announcement();
            assertEquals(106, a.length);
            assertThrows(IllegalArgumentException.class, () -> DkgMessage.decode(config, a));
            assertEquals(2, DkgShareDeliveryCodec.decodeAnnouncement(config, a).participant());
            assertEquals(null, DkgShareDeliveryCodec.decodeAnnouncement(config(1, 3, 2), a), "other session");
            byte[] zeroKey = a.clone();
            Arrays.fill(zeroKey, a.length - 32, a.length, (byte) 0);
            assertEquals(null, DkgShareDeliveryCodec.decodeAnnouncement(config, zeroKey), "small-order key");
            byte[] highBit = a.clone();
            highBit[a.length - 1] |= (byte) 0x80;
            assertEquals(null, DkgShareDeliveryCodec.decodeAnnouncement(config, highBit), "non-canonical key");
            byte[] badId = a.clone();
            badId[DkgShareDeliveryCodec.TAG_A.length + 32] = 4;
            assertEquals(null, DkgShareDeliveryCodec.decodeAnnouncement(config, badId), "j = n + 1");
            byte[] self = good.clone();
            self[DkgShareDeliveryCodec.TAG_E.length + 33] = 1;
            assertEquals(null, DkgShareDeliveryCodec.decodeEnvelope(config, self), "i = j");
            assertEquals(71, DkgShareDeliveryCodec.info(config, 1, 2).length);
        }
    }

    static byte[] flip(byte[] b, int at) {
        byte[] out = b.clone();
        out[at] ^= 1;
        return out;
    }

    // ------------------------------------------------------------------ I5, I12

    @Nested
    @DisplayName("I5, I12: the directory and abort T1")
    class Directory {

        @Test
        @DisplayName("T1: a participant whose announcement is missing aborts before round 1, receives no envelope and never complains")
        void t1Missing() {
            DkgConfig config = config(2, 5, 1);
            DkgEncryptedHarness h = DkgEncryptedHarness.fixed(config, dealings(2, 5), new DkgEncryptedHarness.Hooks() {
                @Override
                public List<byte[]> announcement(int j, byte[] announcement) {
                    return j == 2 ? List.of() : List.of(announcement);
                }
            }).run();
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_KEY_ANNOUNCEMENT_MISSING, h.aborted.get(2).reason());
            assertTrue(h.sealed.stream().noneMatch(e -> (int) e[1] == 2), "no envelope to 2");
            for (int r = 1; r <= 7; r++) {
                assertTrue(h.board.get(r).stream().noneMatch(p -> p.author() == 2), "2 posts nothing in round " + r);
            }
            assertTrue(h.posted(2, DkgMessage.Kind.COMPLAINT).isEmpty(), "no complaints at all");
            assertEquals(Set.of(1, 3, 4, 5), context(h.participant(1)).qual());
        }

        @Test
        @DisplayName("Directory: conflicts give no key (T1), byte-identical duplicates count once, unauthenticated and malformed posts are ignored")
        void directoryRules() {
            DkgConfig config = config(1, 3, 1);
            DkgShareDeliveryKeys k1 = DkgShareDeliveryKeys.fromSecret(config, 1, DkgEncryptedHarness.testKey("recipient.1"));
            DkgShareDeliveryKeys k1b = DkgShareDeliveryKeys.fromSecret(config, 1, DkgEncryptedHarness.testKey("other.1"));
            DkgShareDeliveryKeys k2 = DkgShareDeliveryKeys.fromSecret(config, 2, DkgEncryptedHarness.testKey("recipient.2"));
            DkgShareDeliveryKeys k3 = DkgShareDeliveryKeys.fromSecret(config, 3, DkgEncryptedHarness.testKey("recipient.3"));
            List<AuthenticatedDkgMessage> window = List.of(
                    post(config, 1, k1.announcement()), post(config, 1, k1b.announcement()),     // conflict for 1
                    post(config, 2, k2.announcement()), post(config, 2, k2.announcement()),      // duplicate for 2
                    post(config, 1, k3.announcement()),                                  // 3's announcement under 1's authenticator
                    post(config, 3, Arrays.copyOf(k3.announcement(), 105)));             // malformed
            DkgKeyDirectory dir = DkgKeyDirectory.fromRound0(config, window, DkgEncryptedHarness.AUTH);
            assertFalse(dir.hasKey(1));
            assertArrayEquals(k2.publicKey(), dir.key(2).orElseThrow());
            assertFalse(dir.hasKey(3));
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_KEY_ANNOUNCEMENT_MISSING,
                    assertThrows(FaultAssumptionViolatedException.class, () -> dir.requireOwn(k1)).reason());
            dir.requireOwn(k2);
            // A participant whose delivered key is not its own keys' public key is T1 too.
            DkgShareDeliveryKeys k2b = DkgShareDeliveryKeys.fromSecret(config, 2, DkgEncryptedHarness.testKey("other.2"));
            assertThrows(FaultAssumptionViolatedException.class, () -> dir.requireOwn(k2b));
            DkgParticipant p1 = DkgParticipant.create(config, 1, new SecureRandom());
            assertThrows(FaultAssumptionViolatedException.class, () -> DkgShareDelivery.start(p1, dir, k1, new SecureRandom()));
            assertThrows(FaultAssumptionViolatedException.class, p1::closeRound, "T1 is sticky");
            assertTrue(k1.isDestroyed(), "T1 destroys the keys");
        }
    }

    static AuthenticatedDkgMessage post(DkgConfig config, int author, byte[] bytes) {
        return new AuthenticatedDkgMessage(bytes, DkgEncryptedHarness.tag(config.rosterKey(author), bytes));
    }

    // ------------------------------------------------------------------ I7

    @Nested
    @DisplayName("I7: key lifecycle and fail-closed use of the API")
    class Lifecycle {

        private DkgKeyDirectory directoryOf(DkgConfig config, DkgShareDeliveryKeys... ks) {
            List<AuthenticatedDkgMessage> window = new ArrayList<>();
            for (DkgShareDeliveryKeys k : ks) window.add(post(config, k.id(), k.announcement()));
            return DkgKeyDirectory.fromRound0(config, window, DkgEncryptedHarness.AUTH);
        }

        @Test
        @DisplayName("Keys are bound to one session and participant, destroyed after round 1, and redacted")
        void keys() {
            DkgConfig config = config(1, 3, 1);
            DkgConfig other = config(1, 3, 2);
            DkgShareDeliveryKeys keys = DkgShareDeliveryKeys.generate(config, 2, new SecureRandom());
            assertThrows(IllegalArgumentException.class, () -> keys.secretFor(other));
            assertFalse(keys.toString().contains(HexFormat.of().formatHex(keys.secretFor(config))));
            assertTrue(keys.toString().contains("redacted"));
            DkgKeyDirectory dir = directoryOf(config, keys);
            DkgParticipant p2 = DkgParticipant.create(config, 2, new SecureRandom());
            DkgShareDelivery.start(p2, dir, keys, new SecureRandom());
            DkgShareDelivery.closeRound1(p2, dir, keys, List.of(), DkgEncryptedHarness.AUTH);
            assertTrue(keys.isDestroyed(), "closeRound1 destroys the keys");
            assertThrows(IllegalStateException.class, () -> keys.secretFor(config));
            assertEquals(2, p2.openRound());
            assertThrows(IllegalStateException.class, () -> DkgShareDelivery.closeRound1(p2, dir, keys, List.of(), DkgEncryptedHarness.AUTH),
                    "only at round 1");
        }

        @Test
        @DisplayName("start returns exactly one COMMITMENTS to broadcast and one envelope per keyed other participant; no SHARE leaves in the clear (review X-2)")
        void sealedDealingShape() {
            DkgConfig config = config(2, 5, 1);
            List<DkgShareDeliveryKeys> ks = new ArrayList<>();
            for (int j = 1; j <= 4; j++) ks.add(DkgShareDeliveryKeys.generate(config, j, new SecureRandom())); // 5 has no key
            DkgKeyDirectory dir = directoryOf(config, ks.toArray(new DkgShareDeliveryKeys[0]));
            DkgParticipant p1 = DkgParticipant.create(config, 1, new SecureRandom());
            DkgShareDelivery.SealedDealing dealing = DkgShareDelivery.start(p1, dir, ks.get(0), new SecureRandom());
            assertEquals(1, dealing.broadcasts().size());
            assertEquals(DkgMessage.Kind.COMMITMENTS, dealing.broadcasts().get(0).kind());
            assertEquals(1, dealing.broadcasts().get(0).sender());
            Set<Integer> recipients = new TreeSet<>();
            for (byte[] e : dealing.envelopes()) {
                assertEquals(DkgShareDeliveryCodec.ENVELOPE_LENGTH, e.length);
                assertThrows(IllegalArgumentException.class, () -> DkgMessage.decode(config, e), "an envelope is no threshold message");
                recipients.add(DkgShareDeliveryCodec.decodeEnvelope(config, e).recipient());
            }
            assertEquals(Set.of(2, 3, 4), recipients);
        }

        @Test
        @DisplayName("generate draws the private key from the given generator: fresh keys differ, and a fixed generator gives X25519(k, 9) (review X-3)")
        void generateUsesRandom() throws Exception {
            DkgConfig config = config(1, 3, 1);
            DkgShareDeliveryKeys a = DkgShareDeliveryKeys.generate(config, 2, new SecureRandom());
            DkgShareDeliveryKeys b = DkgShareDeliveryKeys.generate(config, 2, new SecureRandom());
            assertFalse(Arrays.equals(a.publicKey(), b.publicKey()));
            assertFalse(Arrays.equals(a.secretFor(config), b.secretFor(config)));
            byte[] k = DkgEncryptedHarness.testKey("generate.fixed");
            SecureRandom fixed = new SecureRandom() {
                @Override
                public void nextBytes(byte[] bytes) {
                    System.arraycopy(k, 0, bytes, 0, bytes.length);
                }
            };
            DkgShareDeliveryKeys c = DkgShareDeliveryKeys.generate(config, 2, fixed);
            assertArrayEquals(k, c.secretFor(config));
            assertArrayEquals(X25519Bytes.publicFromPrivate(k), c.publicKey());
            // RFC 7748 §6.1 (Alice), independent of ZeroJ code.
            byte[] alice = HexFormat.of().parseHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            SecureRandom rfc = new SecureRandom() {
                @Override
                public void nextBytes(byte[] bytes) {
                    System.arraycopy(alice, 0, bytes, 0, bytes.length);
                }
            };
            assertArrayEquals(HexFormat.of().parseHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
                    DkgShareDeliveryKeys.generate(config, 2, rfc).publicKey());
        }

        @Test
        @DisplayName("Session and identifier must agree: participant, directory and keys of different runs are refused")
        void sameRun() {
            DkgConfig config = config(1, 3, 1);
            DkgConfig other = config(1, 3, 2);
            DkgShareDeliveryKeys k2 = DkgShareDeliveryKeys.generate(config, 2, new SecureRandom());
            DkgShareDeliveryKeys otherK2 = DkgShareDeliveryKeys.generate(other, 2, new SecureRandom());
            DkgKeyDirectory dir = directoryOf(config, k2);
            DkgKeyDirectory otherDir = directoryOf(other, otherK2);
            assertThrows(IllegalArgumentException.class,
                    () -> DkgShareDelivery.start(DkgParticipant.create(config, 2, new SecureRandom()), otherDir, k2, new SecureRandom()));
            assertThrows(IllegalArgumentException.class,
                    () -> DkgShareDelivery.start(DkgParticipant.create(other, 2, new SecureRandom()), dir, k2, new SecureRandom()));
            assertThrows(IllegalArgumentException.class,
                    () -> DkgShareDelivery.start(DkgParticipant.create(config, 3, new SecureRandom()), dir, k2, new SecureRandom()));
            DkgParticipant p2 = DkgParticipant.create(config, 2, new SecureRandom());
            DkgShareDelivery.start(p2, dir, k2, new SecureRandom());
            assertThrows(IllegalArgumentException.class,
                    () -> DkgShareDelivery.closeRound1(p2, dir, otherK2, List.of(), DkgEncryptedHarness.AUTH), "keys of another session");
            assertFalse(k2.isDestroyed(), "a refused argument leaves the keys");
            assertEquals(1, p2.openRound());
        }

        @Test
        @DisplayName("Binding: a started participant cannot close round 1 by itself; an unbound one cannot use closeRound1")
        void binding() {
            DkgConfig config = config(1, 3, 1);
            DkgShareDeliveryKeys k2 = DkgShareDeliveryKeys.generate(config, 2, new SecureRandom());
            DkgKeyDirectory dir = directoryOf(config, k2);
            DkgParticipant bound = DkgParticipant.create(config, 2, new SecureRandom());
            DkgShareDelivery.start(bound, dir, k2, new SecureRandom());
            assertThrows(IllegalStateException.class, bound::closeRound, "the public close refuses round 1");
            DkgParticipant unbound = DkgParticipant.create(config, 2, new SecureRandom());
            unbound.start();
            assertThrows(IllegalStateException.class,
                    () -> DkgShareDelivery.closeRound1(unbound, dir, k2, List.of(), DkgEncryptedHarness.AUTH));
            DkgParticipant already = DkgParticipant.create(config, 2, new SecureRandom());
            already.start();
            assertThrows(IllegalStateException.class, () -> DkgShareDelivery.start(already, dir, k2, new SecureRandom()));
        }

        @Test
        @DisplayName("closeRound1 needs the keys and directory instances given to start; a substitute is refused and changes nothing (review C-1)")
        void substitutedAtClose() {
            DkgConfig config = config(1, 3, 1);
            DkgShareDeliveryKeys k2 = DkgShareDeliveryKeys.generate(config, 2, new SecureRandom());
            DkgShareDeliveryKeys otherK2 = DkgShareDeliveryKeys.generate(config, 2, new SecureRandom());
            DkgKeyDirectory withKey = directoryOf(config, k2);
            DkgKeyDirectory sameContent = directoryOf(config, k2);
            DkgKeyDirectory withOther = directoryOf(config, otherK2);
            DkgKeyDirectory without = DkgKeyDirectory.fromRound0(config, List.of(), DkgEncryptedHarness.AUTH);
            DkgParticipant p2 = DkgParticipant.create(config, 2, new SecureRandom());
            DkgShareDelivery.start(p2, withKey, k2, new SecureRandom());
            assertThrows(IllegalArgumentException.class,
                    () -> DkgShareDelivery.closeRound1(p2, without, k2, List.of(), DkgEncryptedHarness.AUTH), "directory without the key");
            assertThrows(IllegalArgumentException.class,
                    () -> DkgShareDelivery.closeRound1(p2, sameContent, k2, List.of(), DkgEncryptedHarness.AUTH), "an equal but different directory");
            assertThrows(IllegalArgumentException.class,
                    () -> DkgShareDelivery.closeRound1(p2, withOther, otherK2, List.of(), DkgEncryptedHarness.AUTH), "other keys and their directory");
            assertThrows(IllegalArgumentException.class,
                    () -> DkgShareDelivery.closeRound1(p2, withKey, otherK2, List.of(), DkgEncryptedHarness.AUTH), "other keys");
            assertFalse(k2.isDestroyed());
            assertFalse(otherK2.isDestroyed());
            assertEquals(1, p2.openRound());
            DkgShareDelivery.closeRound1(p2, withKey, k2, List.of(), DkgEncryptedHarness.AUTH);
            assertEquals(2, p2.openRound(), "the bound pair still closes the round");
            assertTrue(k2.isDestroyed());
        }

        @Test
        @DisplayName("start() after a T1 abort throws the sticky abort and changes nothing (review S-7)")
        void startAfterAbort() {
            DkgConfig config = config(1, 3, 1);
            DkgShareDeliveryKeys k2 = DkgShareDeliveryKeys.generate(config, 2, new SecureRandom());
            DkgKeyDirectory without = DkgKeyDirectory.fromRound0(config, List.of(), DkgEncryptedHarness.AUTH);
            DkgParticipant p2 = DkgParticipant.create(config, 2, new SecureRandom());
            assertThrows(FaultAssumptionViolatedException.class, () -> DkgShareDelivery.start(p2, without, k2, new SecureRandom()));
            assertThrows(FaultAssumptionViolatedException.class, p2::start);
            assertEquals(0, p2.openRound());
        }

        @Test
        @DisplayName("A verifier that throws leaves the keys and round 1 open: no complaint, and a retry completes the round")
        void verifierThrowsFailsClosed() {
            DkgConfig config = config(1, 3, 1);
            List<ThresholdVss.Dealing> d = dealings(1, 3);
            DkgEncryptedHarness honest = DkgEncryptedHarness.fixed(config, d, DkgEncryptedHarness.HONEST);
            honest.run();
            DkgParticipant p2 = DkgParticipant.withDealing(config, 2, d.get(1));
            DkgShareDeliveryKeys k2 = DkgShareDeliveryKeys.fromSecret(config, 2, DkgEncryptedHarness.testKey("recipient.2"));
            DkgShareDelivery.start(p2, honest.directory, k2, new SecureRandom());
            List<AuthenticatedDkgMessage> window = honest.window(honest.board.get(1));
            DkgAdmissionVerifier flaky = new DkgAdmissionVerifier() {
                @Override
                public boolean authenticate(int sender, byte[] rosterKey, byte[] message, byte[] authenticator) {
                    throw new IllegalStateException("signature service unavailable");
                }

                @Override
                public boolean roundClosed(DkgConfig c, int round, List<byte[]> m, byte[] e) {
                    return true;
                }
            };
            assertThrows(IllegalStateException.class, () -> DkgShareDelivery.closeRound1(p2, honest.directory, k2, window, flaky));
            assertFalse(k2.isDestroyed());
            assertEquals(1, p2.openRound());
            assertThrows(IllegalStateException.class, p2::closeRound, "still no way to close round 1 but the barrier");
            assertEquals(List.of(), DkgShareDelivery.closeRound1(p2, honest.directory, k2, window, DkgEncryptedHarness.AUTH),
                    "the retry processes every envelope: no complaint");
            assertTrue(k2.isDestroyed());
        }

        @Test
        @DisplayName("A verifier that throws after accepting some envelopes: the retry adds no second copy and no complaint (review C-2)")
        void verifierThrowsAfterPartialProgress() {
            DkgConfig config = config(2, 5, 1);
            List<ThresholdVss.Dealing> d = dealings(2, 5);
            DkgEncryptedHarness honest = DkgEncryptedHarness.fixed(config, d, DkgEncryptedHarness.HONEST);
            honest.run();
            DkgParticipant p2 = DkgParticipant.withDealing(config, 2, d.get(1));
            DkgShareDeliveryKeys k2 = DkgShareDeliveryKeys.fromSecret(config, 2, DkgEncryptedHarness.testKey("recipient.2"));
            DkgShareDelivery.start(p2, honest.directory, k2, new SecureRandom());
            List<AuthenticatedDkgMessage> window = honest.window(honest.board.get(1));
            int[] calls = {0};
            DkgAdmissionVerifier flaky = new DkgAdmissionVerifier() {
                @Override
                public boolean authenticate(int sender, byte[] rosterKey, byte[] message, byte[] authenticator) {
                    if (++calls[0] > 3) throw new IllegalStateException("signature service unavailable");
                    return DkgEncryptedHarness.AUTH.authenticate(sender, rosterKey, message, authenticator);
                }

                @Override
                public boolean roundClosed(DkgConfig c, int round, List<byte[]> m, byte[] e) {
                    return true;
                }
            };
            assertThrows(IllegalStateException.class, () -> DkgShareDelivery.closeRound1(p2, honest.directory, k2, window, flaky));
            int partial = 0;
            for (int dealer = 1; dealer <= config.n(); dealer++) {
                if (dealer != 2) partial += p2.receivedShares(dealer).size();
            }
            assertTrue(partial >= 1, "the failed attempt accepted at least one share before throwing");
            assertFalse(k2.isDestroyed());
            assertEquals(1, p2.openRound());
            assertEquals(List.of(), DkgShareDelivery.closeRound1(p2, honest.directory, k2, window, DkgEncryptedHarness.AUTH),
                    "the identical retry: no complaint");
            for (int dealer = 1; dealer <= config.n(); dealer++) {
                if (dealer != 2) assertEquals(1, p2.receivedShares(dealer).size(), "one share from dealer " + dealer);
            }
            assertTrue(k2.isDestroyed());
        }
    }

    // ------------------------------------------------------------------ I11, I13, I15

    @Nested
    @DisplayName("I11, I13, I15: the barrier, commitments last and answer scope")
    class Timing {

        @Test
        @DisplayName("Review F1 negative control: without the barrier the corrupted participant recovers x; with it there are no complaints")
        void barrier() {
            DkgConfig config = config(1, 3, 1);
            List<ThresholdVss.Dealing> d = dealings(1, 3);
            DkgEncryptedHarness late = DkgEncryptedHarness.fixed(config, d, new DkgEncryptedHarness.Hooks() {
                @Override
                public boolean processedLate(int i, int j) {
                    return i == 1 && j == 2 || i == 2 && j == 1;
                }
            }).run();
            assertEquals(2, late.posted(2, DkgMessage.Kind.COMPLAINT).size(), "1 and 2 complain about each other");
            List<DkgMessage> answers = late.posted(3, DkgMessage.Kind.ANSWER);
            assertEquals(2, answers.size(), "both answers are public");
            // Corrupted participant 3: its own shares plus the two public answers (t + 1 = 2 points per dealer).
            BigInteger x = BigInteger.ZERO;
            for (int dealer = 1; dealer <= 3; dealer++) {
                if (dealer == 3) {
                    x = x.add(d.get(2).share(0)).mod(L);
                    continue;
                }
                TreeMap<Integer, BigInteger> points = new TreeMap<>();
                points.put(3, d.get(dealer - 1).share(3));
                for (DkgMessage a : answers) if (a.sender() == dealer) points.put(a.subject(), a.s());
                x = x.add(interpolateAtZero(points)).mod(L);
            }
            assertTrue(JubjubPoint.SUBGROUP_GENERATOR.scalarMul(x).projectiveEquals(context(late.participant(3)).jointKey().point()),
                    "the key is exposed without the barrier");

            DkgEncryptedHarness withBarrier = DkgEncryptedHarness.fixed(config, d, DkgEncryptedHarness.HONEST).run();
            assertTrue(withBarrier.posted(2, DkgMessage.Kind.COMPLAINT).isEmpty());
            assertTrue(withBarrier.posted(3, DkgMessage.Kind.ANSWER).isEmpty());
        }

        @Test
        @DisplayName("D7a: envelopes that miss the cutoff leave the dealer without COMMITMENTS, disqualified, with no honest complaint")
        void commitmentsLast() {
            DkgConfig config = config(2, 5, 1);
            DkgEncryptedHarness h = DkgEncryptedHarness.fixed(config, dealings(2, 5), new DkgEncryptedHarness.Hooks() {
                @Override
                public boolean missesCutoff(int i, int j) {
                    return i == 1 && j == 4;
                }
            }).run();
            assertTrue(h.posted(1, DkgMessage.Kind.COMMITMENTS).stream().noneMatch(m -> m.sender() == 1));
            assertTrue(h.posted(2, DkgMessage.Kind.COMPLAINT).isEmpty(), "no complaint by any honest participant");
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_DEALING_DISQUALIFIED, h.aborted.get(1).reason());
            assertEquals(Set.of(2, 3, 4, 5), context(h.participant(2)).qual());
            // Negative control: a dealer that ignores D7a draws a complaint, and its answer publishes 4's share.
            DkgEncryptedHarness ignored = DkgEncryptedHarness.fixed(config, dealings(2, 5), new DkgEncryptedHarness.Hooks() {
                @Override
                public boolean missesCutoff(int i, int j) {
                    return i == 1 && j == 4;
                }

                @Override
                public Set<Integer> ignoreCommitmentsLast() {
                    return Set.of(1);
                }
            }).run();
            assertEquals(1, ignored.posted(2, DkgMessage.Kind.COMPLAINT).size());
            assertEquals(4, ignored.posted(3, DkgMessage.Kind.ANSWER).get(0).subject(), "an honest index is published");
        }

        @Test
        @DisplayName("Authenticated junk in the round-1 window (a plaintext SHARE, an early COMPLAINT, garbage) is absent: no throw, no complaint, same transcript (review X-5)")
        void junkBroadcastsInRoundOne() {
            DkgConfig config = config(1, 3, 1);
            List<ThresholdVss.Dealing> d = dealings(1, 3);
            DkgMessage share31 = DkgMessage.pair(config, DkgMessage.Kind.SHARE, 3, 1, d.get(2).share(1), d.get(2).sharePrime(1));
            DkgEncryptedHarness junk = DkgEncryptedHarness.fixed(config, d, new DkgEncryptedHarness.Hooks() {
                @Override
                public List<DkgEncryptedHarness.Post> extra(int round) {
                    if (round != 1) return List.of();
                    return List.of(new DkgEncryptedHarness.Post(3, share31.encode()),
                            new DkgEncryptedHarness.Post(3, DkgMessage.complaint(config, 3, 1).encode()),
                            new DkgEncryptedHarness.Post(3, new byte[]{1, 2, 3}));
                }
            }).run();
            DkgEncryptedHarness honest = DkgEncryptedHarness.fixed(config, d, DkgEncryptedHarness.HONEST).run();
            assertTrue(junk.aborted.isEmpty(), "aborts: " + junk.aborted);
            assertTrue(junk.posted(2, DkgMessage.Kind.COMPLAINT).isEmpty());
            assertArrayEquals(DkgTranscript.of(config, honest.transcriptMessages()).digest(),
                    DkgTranscript.of(config, junk.transcriptMessages()).digest());
        }

        @Test
        @DisplayName("I15 (review F3): a corrupted complaint draws an answer at the corrupted index only, timely or with withheld commitments")
        void answerScope() {
            DkgConfig config = config(1, 3, 1);
            // (i) Timely delivery: corrupted 3 complains about honest qualified dealer 1.
            DkgEncryptedHarness timely = DkgEncryptedHarness.fixed(config, dealings(1, 3), new DkgEncryptedHarness.Hooks() {
                @Override
                public List<DkgEncryptedHarness.Post> extra(int round) {
                    return round == 2 ? List.of(new DkgEncryptedHarness.Post(3, DkgMessage.complaint(config, 3, 1).encode())) : List.of();
                }
            }).run();
            List<DkgMessage> answers = timely.posted(3, DkgMessage.Kind.ANSWER);
            assertEquals(1, answers.size());
            assertEquals(1, answers.get(0).sender());
            assertEquals(3, answers.get(0).subject(), "at the corrupted index");
            assertEquals(Set.of(1, 2, 3), context(timely.participant(1)).qual());
            // (ii) Dealer 1's envelope to 2 missed the cutoff, so it withheld COMMITMENTS; corrupted 3 complains anyway.
            DkgEncryptedHarness withheld = DkgEncryptedHarness.fixed(config, dealings(1, 3), new DkgEncryptedHarness.Hooks() {
                @Override
                public boolean missesCutoff(int i, int j) {
                    return i == 1 && j == 2;
                }

                @Override
                public List<DkgEncryptedHarness.Post> extra(int round) {
                    return round == 2 ? List.of(new DkgEncryptedHarness.Post(3, DkgMessage.complaint(config, 3, 1).encode())) : List.of();
                }
            }).run();
            List<DkgMessage> w = withheld.posted(3, DkgMessage.Kind.ANSWER);
            assertEquals(1, w.size());
            assertEquals(3, w.get(0).subject(), "answers the corrupted complainer before A2");
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_DEALING_DISQUALIFIED, withheld.aborted.get(1).reason());
            assertEquals(Set.of(2, 3), context(withheld.participant(2)).qual());
            assertTrue(withheld.posted(2, DkgMessage.Kind.COMPLAINT).stream().noneMatch(m -> m.sender() == 2), "honest 2 never complains");
        }
    }

    static BigInteger interpolateAtZero(TreeMap<Integer, BigInteger> points) {
        int[] xs = points.keySet().stream().mapToInt(Integer::intValue).toArray();
        BigInteger[] lambda = ThresholdMath.lagrangeAt(xs, 0);
        BigInteger acc = BigInteger.ZERO;
        int k = 0;
        for (BigInteger y : points.values()) acc = acc.add(lambda[k++].multiply(y)).mod(L);
        return acc;
    }

    // ------------------------------------------------------------------ review M-1 / S-1 and further negatives

    @Nested
    @DisplayName("Front-running and further binding negatives (reviews M-1, S-1, S-4, M-6)")
    class Hardening {

        @Test
        @DisplayName("Unauthentic byte-identical copies posted first shadow neither an envelope nor COMMITMENTS")
        void frontRunning() {
            DkgConfig config = config(1, 3, 1);
            List<ThresholdVss.Dealing> d = dealings(1, 3);
            DkgEncryptedHarness h = DkgEncryptedHarness.fixed(config, d, new DkgEncryptedHarness.Hooks() {
                @Override
                public List<DkgEncryptedHarness.Post> before(int round, DkgEncryptedHarness harness) {
                    if (round != 1) return List.of();
                    List<DkgEncryptedHarness.Post> copies = new ArrayList<>();
                    for (Object[] e : harness.sealed) {
                        int i = (int) e[0], j = (int) e[1];
                        if (i == 1 && j == 2 || i == 2 && j == 1) copies.add(new DkgEncryptedHarness.Post(3, (byte[]) e[2]));
                    }
                    ThresholdVss.Dealing d1 = d.get(0);
                    copies.add(new DkgEncryptedHarness.Post(3,
                            DkgMessage.points(config, DkgMessage.Kind.COMMITMENTS, 1, d1.commitments()).encode()));
                    return copies;
                }
            }).run();
            assertTrue(h.aborted.isEmpty(), "aborts: " + h.aborted);
            assertTrue(h.posted(2, DkgMessage.Kind.COMPLAINT).isEmpty(), "no complaints");
            assertEquals(Set.of(1, 2, 3), context(h.participant(1)).qual());
            DkgHarness plain = DkgHarness.fixed(config, d, DkgHarness.HONEST).run();
            assertArrayEquals(DkgTranscript.of(config, plain.transcriptMessages()).digest(),
                    DkgTranscript.of(config, h.transcriptMessages()).digest());
        }

        @Test
        @DisplayName("A forged, distinct COMMITMENTS for an honest dealer under another author is ignored (review M-9)")
        void forgedCommitmentsIgnored() {
            DkgConfig config = config(1, 3, 1);
            List<ThresholdVss.Dealing> d = dealings(1, 3);
            ThresholdVss.Dealing other = DkgHarness.dealings(1, 3, 999).get(0);
            byte[] forged = DkgMessage.points(config, DkgMessage.Kind.COMMITMENTS, 1, other.commitments()).encode();
            DkgEncryptedHarness h = DkgEncryptedHarness.fixed(config, d, new DkgEncryptedHarness.Hooks() {
                @Override
                public List<DkgEncryptedHarness.Post> before(int round, DkgEncryptedHarness harness) {
                    return round == 1 ? List.of(new DkgEncryptedHarness.Post(3, forged)) : List.of();
                }
            }).run();
            assertTrue(h.aborted.isEmpty(), "aborts: " + h.aborted);
            assertTrue(h.posted(2, DkgMessage.Kind.COMPLAINT).isEmpty());
            assertEquals(Set.of(1, 2, 3), context(h.participant(1)).qual());
        }

        @Test
        @DisplayName("A copied announcement key: the copier gets T1 (it is not its own), and nobody else is affected")
        void copiedKey() {
            DkgConfig config = config(1, 3, 1);
            DkgEncryptedHarness h = DkgEncryptedHarness.fixed(config, dealings(1, 3), new DkgEncryptedHarness.Hooks() {
                @Override
                public List<byte[]> announcement(int j, byte[] announcement) {
                    if (j != 3) return List.of(announcement);
                    return List.of(DkgShareDeliveryCodec.announcement(config, 3, publicKeyOf(2)));
                }
            }).run();
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_KEY_ANNOUNCEMENT_MISSING, h.aborted.get(3).reason());
            assertTrue(h.posted(2, DkgMessage.Kind.COMPLAINT).isEmpty());
            assertEquals(Set.of(1, 2), context(h.participant(1)).qual());
        }

        @Test
        @DisplayName("Cross-session replay with the header rewritten fails on info, even with the same recipient key")
        void crossSessionRewritten() {
            DkgConfig attempt1 = config(1, 3, 1);
            DkgConfig attempt2 = config(1, 3, 2);
            DkgEncryptedHarness other = DkgEncryptedHarness.fixed(attempt2, dealings(1, 3), DkgEncryptedHarness.HONEST).run();
            byte[] replay = null;
            for (Object[] e : other.sealed) if ((int) e[0] == 1 && (int) e[1] == 2) replay = ((byte[]) e[2]).clone();
            int at = DkgShareDeliveryCodec.TAG_E.length;
            System.arraycopy(attempt1.session(), 0, replay, at, 32); // header now names attempt 1
            assertTrue(DkgShareDeliveryCodec.decodeEnvelope(attempt1, replay) != null, "well-formed for attempt 1");
            byte[] forged = replay;
            DkgEncryptedHarness h = DkgEncryptedHarness.fixed(attempt1, dealings(1, 3), new DkgEncryptedHarness.Hooks() {
                @Override
                public List<byte[]> envelope(int i, int j, byte[] envelope) {
                    return i == 1 && j == 2 ? List.of(forged) : List.of(envelope);
                }
            }).run();
            assertEquals(1, h.posted(2, DkgMessage.Kind.COMPLAINT).size(), "the replayed share is absent");
        }

        @Test
        @DisplayName("info is exactly TAG_I ‖ session ‖ i ‖ j, and a non-canonical enc is refused by the codec")
        void infoAndCanonicalEnc() {
            DkgConfig config = config(1, 3, 1);
            byte[] info = DkgShareDeliveryCodec.info(config, 1, 2);
            assertArrayEquals(Hpke.concat(Hpke.ascii("zeroj.dkg-share-delivery-hpke.v1.info"), config.session(), new byte[]{1, 2}), info);
            DkgEncryptedHarness h = DkgEncryptedHarness.fixed(config, dealings(1, 3), DkgEncryptedHarness.HONEST).run();
            byte[] good = (byte[]) h.sealed.get(0)[2];
            byte[] high = good.clone();
            high[DkgShareDeliveryCodec.TAG_E.length + 34 + 31] |= (byte) 0x80;
            assertEquals(null, DkgShareDeliveryCodec.decodeEnvelope(config, high), "bit 255 set");
            byte[] bigU = good.clone();
            Arrays.fill(bigU, DkgShareDeliveryCodec.TAG_E.length + 34, DkgShareDeliveryCodec.TAG_E.length + 66, (byte) 0xFF);
            bigU[DkgShareDeliveryCodec.TAG_E.length + 65] = 0x7F; // u = 2^255 − 1 ≥ p
            assertEquals(null, DkgShareDeliveryCodec.decodeEnvelope(config, bigU), "u ≥ p");
        }

        @Test
        @DisplayName("The public start draws a fresh ephemeral for every envelope and every call")
        void freshEphemerals() {
            DkgConfig config = config(2, 5, 1);
            List<DkgShareDeliveryKeys> ks = new ArrayList<>();
            List<AuthenticatedDkgMessage> window = new ArrayList<>();
            for (int j = 1; j <= 5; j++) {
                ks.add(DkgShareDeliveryKeys.generate(config, j, new SecureRandom()));
                window.add(post(config, j, ks.get(j - 1).announcement()));
            }
            DkgKeyDirectory dir = DkgKeyDirectory.fromRound0(config, window, DkgEncryptedHarness.AUTH);
            Set<String> encs = new HashSet<>();
            for (int run = 0; run < 2; run++) {
                DkgParticipant p1 = DkgParticipant.withDealing(config, 1, dealings(2, 5).get(0));
                for (byte[] e : DkgShareDelivery.start(p1, dir, ks.get(0), new SecureRandom()).envelopes()) {
                    assertTrue(encs.add(HexFormat.of().formatHex(DkgShareDeliveryCodec.decodeEnvelope(config, e).enc())), "enc reused");
                }
            }
            assertEquals(8, encs.size());
        }
    }

    // ------------------------------------------------------------------ review Z-1, Z-4

    @Nested
    @DisplayName("Platform faults fail closed: never absence, never a complaint (review Z-1)")
    class PlatformFaults {

        @Test
        @DisplayName("HPKE: tag failure and small-order enc are input failures; a missing provider is not")
        void hpkeClassification() throws Exception {
            byte[] skR = DkgEncryptedHarness.testKey("recipient.2");
            byte[] pkR = X25519Bytes.publicFromPrivate(skR);
            byte[] info = Hpke.ascii("classification");
            Hpke.Sealed sealed = Hpke.sealBase(pkR, info, new byte[0], new byte[100], new SecureRandom());
            byte[] tampered = sealed.ct().clone();
            tampered[5] ^= 1;
            assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(sealed.enc(), skR, info, new byte[0], tampered));
            byte[] smallOrder = new byte[32];
            smallOrder[0] = 1;
            assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(smallOrder, skR, info, new byte[0], sealed.ct()));
            assertThrows(Hpke.HpkeException.class, () -> Hpke.sealBase(smallOrder, info, new byte[0], new byte[100], new SecureRandom()));
            assertThrows(Hpke.HpkeException.class, () -> Hpke.openBase(new byte[31], skR, info, new byte[0], sealed.ct()));
            DkgEncryptedHarness.withoutProvider("SunJCE", () -> {
                assertThrows(IllegalStateException.class, () -> Hpke.openBase(sealed.enc(), skR, pkR, info, new byte[0], sealed.ct()));
                assertThrows(IllegalStateException.class, () -> Hpke.sealBase(pkR, info, new byte[0], new byte[100], new SecureRandom()));
            });
            DkgEncryptedHarness.withoutProvider("SunEC", () -> {
                assertThrows(IllegalStateException.class, () -> Hpke.openBase(sealed.enc(), skR, pkR, info, new byte[0], sealed.ct()));
                assertThrows(IllegalStateException.class, () -> X25519Bytes.passesSmallOrderProbe(pkR),
                        "the probe never reports a fault as small order");
            });
            assertArrayEquals(new byte[100], Hpke.openBase(sealed.enc(), skR, info, new byte[0], sealed.ct()), "restored");
        }

        @Test
        @DisplayName("closeRound1 with a failing AEAD/HKDF provider: no complaint, keys kept, round 1 open; the retry succeeds")
        void closeRound1() {
            DkgConfig config = config(2, 5, 1);
            List<ThresholdVss.Dealing> d = dealings(2, 5);
            DkgEncryptedHarness honest = DkgEncryptedHarness.fixed(config, d, DkgEncryptedHarness.HONEST);
            honest.run();
            DkgParticipant p2 = DkgParticipant.withDealing(config, 2, d.get(1));
            DkgShareDeliveryKeys k2 = DkgShareDeliveryKeys.fromSecret(config, 2, DkgEncryptedHarness.testKey("recipient.2"));
            DkgShareDelivery.start(p2, honest.directory, k2, new SecureRandom());
            List<AuthenticatedDkgMessage> window = honest.window(honest.board.get(1));
            for (String provider : List.of("SunJCE", "SunEC")) {
                DkgEncryptedHarness.withoutProvider(provider, () -> assertThrows(IllegalStateException.class,
                        () -> DkgShareDelivery.closeRound1(p2, honest.directory, k2, window, DkgEncryptedHarness.AUTH), provider));
                assertFalse(k2.isDestroyed(), provider);
                assertEquals(1, p2.openRound(), provider);
            }
            assertEquals(List.of(), DkgShareDelivery.closeRound1(p2, honest.directory, k2, window, DkgEncryptedHarness.AUTH));
            assertTrue(k2.isDestroyed());
        }

        @Test
        @DisplayName("start with a failing provider changes nothing; the directory refuses to build rather than drop keys")
        void startAndDirectory() {
            DkgConfig config = config(1, 3, 1);
            DkgShareDeliveryKeys k2 = DkgShareDeliveryKeys.generate(config, 2, new SecureRandom());
            List<AuthenticatedDkgMessage> round0 = List.of(post(config, 2, k2.announcement()));
            DkgEncryptedHarness.withoutProvider("SunEC", () -> assertThrows(IllegalStateException.class,
                    () -> DkgKeyDirectory.fromRound0(config, round0, DkgEncryptedHarness.AUTH)));
            DkgKeyDirectory dir = DkgKeyDirectory.fromRound0(config, round0, DkgEncryptedHarness.AUTH);
            DkgParticipant p2 = DkgParticipant.create(config, 2, new SecureRandom());
            DkgEncryptedHarness.withoutProvider("SunJCE", () -> assertThrows(IllegalStateException.class,
                    () -> DkgShareDelivery.start(p2, dir, k2, new SecureRandom())));
            assertEquals(0, p2.openRound());
            assertFalse(p2.boundToEncryptedDelivery());
            assertFalse(k2.isDestroyed());
            DkgShareDelivery.start(p2, dir, k2, new SecureRandom());
            assertEquals(1, p2.openRound(), "the retry starts the participant");
        }
    }

    // ------------------------------------------------------------------ I14

    @Nested
    @DisplayName("I14: no self-envelope and exposure counting")
    class Exposure {

        @Test
        @DisplayName("No envelope is addressed to its sender; leaked recipient keys expose exactly the dealers the counting rule says")
        void countingRule() throws Exception {
            int t = 2, n = 5;
            DkgConfig config = config(t, n, 1);
            List<ThresholdVss.Dealing> d = dealings(t, n);
            DkgEncryptedHarness h = DkgEncryptedHarness.fixed(config, d, DkgEncryptedHarness.HONEST).run();
            assertTrue(h.sealed.stream().noneMatch(e -> (int) e[0] == (int) e[1]));
            for (Set<Integer> leaked : List.of(Set.of(1, 2, 3), Set.of(1, 2, 3, 4), Set.of(4, 5), Set.of(1, 2, 3, 4, 5))) {
                for (int dealer = 1; dealer <= n; dealer++) {
                    TreeMap<Integer, BigInteger> points = new TreeMap<>();
                    for (Object[] e : h.sealed) {
                        int i = (int) e[0], j = (int) e[1];
                        if (i != dealer || !leaked.contains(j)) continue;
                        DkgShareDeliveryCodec.Envelope env = DkgShareDeliveryCodec.decodeEnvelope(config, (byte[]) e[2]);
                        byte[] pt = Hpke.openBase(env.enc(), h.secrets.get(j), DkgShareDeliveryCodec.info(config, i, j), new byte[0], env.ct());
                        points.put(j, DkgMessage.decode(config, pt).s());
                    }
                    Set<Integer> rule = new TreeSet<>(leaked);
                    rule.remove(dealer);
                    assertEquals(rule, points.keySet(), "known indices for dealer " + dealer);
                    if (points.size() >= t + 1) {
                        assertEquals(d.get(dealer - 1).share(0), interpolateAtZero(points), "z_" + dealer + " reconstructed");
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------ API surface

    @Test
    @DisplayName("Public delivery types are final with no public constructor; HPKE, X25519 and the codec stay package-private")
    void apiSurface() {
        for (Class<?> c : List.of(DkgShareDelivery.class, DkgShareDeliveryKeys.class, DkgKeyDirectory.class,
                DkgShareDelivery.SealedDealing.class)) {
            assertTrue(Modifier.isFinal(c.getModifiers()), c + " final");
            assertFalse(c.isRecord(), c + " not a record");
            for (Constructor<?> k : c.getDeclaredConstructors()) {
                assertFalse(Modifier.isPublic(k.getModifiers()) || Modifier.isProtected(k.getModifiers()), c + " constructor");
            }
        }
        for (Class<?> c : List.of(Hpke.class, X25519Bytes.class, DkgShareDeliveryCodec.class)) {
            assertFalse(Modifier.isPublic(c.getModifiers()), c + " package-private");
        }
        // Deterministic seams stay package-private: production uses fresh randomness only.
        for (Method m : DkgShareDelivery.class.getDeclaredMethods()) {
            boolean seam = Arrays.asList(m.getParameterTypes()).contains(IntFunction.class)
                    || m.getName().equals("sealOne");
            if (seam) assertFalse(Modifier.isPublic(m.getModifiers()), m + " must not be public");
        }
        for (Method m : DkgShareDeliveryKeys.class.getDeclaredMethods()) {
            if (m.getName().equals("fromSecret") || m.getName().equals("secretFor")) {
                assertFalse(Modifier.isPublic(m.getModifiers()), m + " must not be public");
            }
        }
    }
}
