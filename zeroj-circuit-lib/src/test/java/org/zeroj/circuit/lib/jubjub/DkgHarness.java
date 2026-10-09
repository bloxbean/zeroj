package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;

/**
 * A simulated bulletin board for {@link DkgParticipant} tests. Every broadcast goes to every
 * participant, the sender included, and every {@code SHARE} to its recipient. An adversary
 * hook can rewrite, drop, duplicate or misroute any message, so a test can script corrupt
 * participants and broken transports.
 */
final class DkgHarness {

    /** One delivery: {@code bytes} from {@code sender} to {@code recipient}. */
    record Delivery(int sender, int recipient, byte[] bytes) {}

    /** Rewrites one outgoing message into the deliveries that actually happen. */
    interface Adversary {
        List<Delivery> deliver(DkgMessage message, List<Delivery> honest);
    }

    static final Adversary HONEST = (m, honest) -> honest;

    final DkgConfig config;
    final List<DkgParticipant> participants = new ArrayList<>();
    final Map<Integer, FaultAssumptionViolatedException> aborted = new HashMap<>();
    /** Every broadcast message actually posted, by round (index 1–7). */
    final List<List<byte[]>> board = new ArrayList<>();
    private final Adversary adversary;
    private final Map<Integer, List<DkgMessage>> injected = new HashMap<>();

    DkgHarness(DkgConfig config, Function<Integer, DkgParticipant> factory, Adversary adversary) {
        this.config = config;
        this.adversary = adversary;
        for (int r = 0; r <= 7; r++) board.add(new ArrayList<>());
        for (int i = 1; i <= config.n(); i++) participants.add(factory.apply(i));
    }

    static DkgConfig config(int t, int n, String context, long attempt) {
        List<byte[]> roster = new ArrayList<>();
        for (int j = 1; j <= n; j++) {
            byte[] key = new byte[32];
            Arrays.fill(key, (byte) j);
            roster.add(key);
        }
        return DkgConfig.create(t, n, roster, context.getBytes(StandardCharsets.UTF_8), attempt);
    }

    static DkgHarness random(DkgConfig config, Adversary adversary) {
        SecureRandom rng = new SecureRandom();
        return new DkgHarness(config, id -> DkgParticipant.create(config, id, rng), adversary);
    }

    static DkgHarness fixed(DkgConfig config, List<ThresholdVss.Dealing> dealings, Adversary adversary) {
        return new DkgHarness(config, id -> DkgParticipant.withDealing(config, id, dealings.get(id - 1)), adversary);
    }

    /** Broadcasts an extra message in {@code round}, as if its sender had posted it. */
    DkgHarness inject(DkgMessage message) {
        injected.computeIfAbsent(message.round(), r -> new ArrayList<>()).add(message);
        return this;
    }

    DkgParticipant participant(int id) {
        return participants.get(id - 1);
    }

    /** Runs all seven rounds. Aborts are recorded per participant, not thrown. */
    DkgHarness run() {
        Map<Integer, List<DkgMessage>> outgoing = new HashMap<>();
        for (DkgParticipant p : participants) outgoing.put(p.id(), p.start());
        for (int round = 1; round <= 7; round++) {
            List<Delivery> deliveries = new ArrayList<>();
            for (DkgParticipant p : participants) {
                for (DkgMessage m : outgoing.getOrDefault(p.id(), List.of())) {
                    deliveries.addAll(adversary.deliver(m, honestDeliveries(m)));
                }
            }
            for (DkgMessage m : injected.getOrDefault(round, List.of())) {
                deliveries.addAll(honestDeliveries(m));
            }
            for (Delivery d : deliveries) {
                DkgMessage decoded = DkgMessage.decode(config, d.bytes());
                if (decoded.kind() != DkgMessage.Kind.SHARE && d.recipient() == decoded.sender()) {
                    board.get(decoded.round()).add(d.bytes());
                }
                DkgParticipant target = participant(d.recipient());
                if (aborted.containsKey(target.id())) continue;
                try {
                    if (decoded.kind() == DkgMessage.Kind.SHARE) {
                        target.receivePrivate(d.sender(), d.bytes());
                    } else {
                        target.receiveBroadcast(d.sender(), d.bytes());
                    }
                } catch (IllegalArgumentException ignored) {
                    // a refused message is absent
                }
            }
            outgoing.clear();
            for (DkgParticipant p : participants) {
                if (aborted.containsKey(p.id())) continue;
                try {
                    outgoing.put(p.id(), p.closeRound());
                } catch (FaultAssumptionViolatedException e) {
                    aborted.put(p.id(), e);
                }
            }
        }
        return this;
    }

    List<Delivery> honestDeliveries(DkgMessage m) {
        List<Delivery> out = new ArrayList<>();
        if (m.kind() == DkgMessage.Kind.SHARE) {
            out.add(new Delivery(m.sender(), m.subject(), m.encode()));
        } else {
            for (int j = 1; j <= config.n(); j++) out.add(new Delivery(m.sender(), j, m.encode()));
        }
        return out;
    }

    /** The broadcast messages of rounds 1–6 as posted (from the sender's own copy). */
    List<byte[]> transcriptMessages() {
        List<byte[]> out = new ArrayList<>();
        for (int r = 1; r <= 6; r++) out.addAll(board.get(r));
        return out;
    }

    List<byte[]> confirmations() {
        return board.get(7);
    }

    /** Honest polynomials {@code a_ik}, {@code b_ik} from a deterministic source. */
    static List<ThresholdVss.Dealing> dealings(int t, int n, long seed) {
        Random rnd = new Random(seed);
        List<ThresholdVss.Dealing> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            BigInteger[] a = new BigInteger[t + 1];
            BigInteger[] b = new BigInteger[t + 1];
            for (int k = 0; k <= t; k++) {
                a[k] = new BigInteger(300, rnd).mod(JubjubCurve.SUBGROUP_ORDER);
                b[k] = new BigInteger(300, rnd).mod(JubjubCurve.SUBGROUP_ORDER);
            }
            out.add(ThresholdVss.dealWithCoefficients(a, b));
        }
        return out;
    }

    /** {@code Σ_{i∈qual} [a_i0]·G} from the true polynomials. */
    static JubjubPoint trueKey(List<ThresholdVss.Dealing> dealings, List<Integer> qual) {
        FastJubjubPoint acc = FastJubjubPoint.IDENTITY;
        for (int i : qual) acc = acc.add(FastJubjubPoint.of(dealings.get(i - 1).extraction().get(0)));
        return acc.toJubjubPoint();
    }
}
