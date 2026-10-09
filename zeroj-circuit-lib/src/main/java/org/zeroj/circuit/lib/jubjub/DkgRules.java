package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The public round rules of {@code elgamal-jubjub-threshold-v1} §5: deterministic functions of
 * the delivered broadcast sets only. A participant and anyone recomputing a transcript run
 * exactly this code, so they take identical decisions. Every decision that depends on private
 * input (complaining, adopting an answered pair, a participant's own checks) lives in
 * {@link DkgParticipant}.
 */
final class DkgRules {

    private DkgRules() {}

    /** R1–R3: the qualified set and the commitments of every dealer with a valid vector. */
    record Qualification(SortedSet<Integer> qual, SortedSet<Integer> disqualified,
                         Map<Integer, List<JubjubPoint>> commitments) {}

    /** R4–R5: marked dealers and the published extraction vectors of the rest. */
    record Marks(SortedSet<Integer> marked, Map<Integer, List<JubjubPoint>> published) {}

    /** R6 and the outputs. */
    record Outputs(Map<Integer, List<JubjubPoint>> extraction, JubjubPoint jointKey,
                   List<JubjubPoint> verificationKeys) {}

    static Qualification qualify(DkgConfig config, DkgRound r1, DkgRound r2, DkgRound r3) {
        int n = config.n();
        int t = config.t();
        SortedSet<Integer> disqualified = new TreeSet<>();
        Map<Integer, List<JubjubPoint>> commitments = new HashMap<>();
        for (int i = 1; i <= n; i++) {
            DkgMessage c = r1.single(DkgMessage.Kind.COMMITMENTS, i, 0);
            if (c == null) {
                disqualified.add(i); // R1: absent or in conflict
            } else {
                commitments.put(i, c.points());
            }
        }
        for (int i = 1; i <= n; i++) {
            if (disqualified.contains(i)) continue;
            List<Integer> complainers = new ArrayList<>();
            for (int j = 1; j <= n; j++) {
                if (j != i && r2.single(DkgMessage.Kind.COMPLAINT, j, i) != null) complainers.add(j);
            }
            if (complainers.size() > t) {
                disqualified.add(i);
                continue;
            }
            for (int j : complainers) {
                DkgMessage answer = r3.single(DkgMessage.Kind.ANSWER, i, j);
                if (answer == null
                        || !ThresholdVss.checkPedersenPublic(commitments.get(i), j, answer.s(), answer.sPrime())) {
                    disqualified.add(i);
                    break;
                }
            }
        }
        SortedSet<Integer> qual = new TreeSet<>();
        for (int i = 1; i <= n; i++) {
            if (!disqualified.contains(i)) qual.add(i);
        }
        if (qual.size() < n - t) {
            throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.TOO_FEW_QUALIFIED,
                    "QUAL has " + qual.size() + " members, at least n - t = " + (n - t) + " are honest");
        }
        return new Qualification(Collections.unmodifiableSortedSet(qual),
                Collections.unmodifiableSortedSet(disqualified), commitments);
    }

    static Marks mark(DkgConfig config, Qualification q, DkgRound r4, DkgRound r5) {
        SortedSet<Integer> marked = new TreeSet<>();
        Map<Integer, List<JubjubPoint>> published = new HashMap<>();
        for (int i : q.qual()) {
            DkgMessage e = r4.single(DkgMessage.Kind.EXTRACTION, i, 0);
            if (e == null) {
                marked.add(i); // R4: absent or in conflict
            } else {
                published.put(i, e.points());
            }
        }
        // Every complaint is evaluated on its own, conflicting variants included: a valid one is
        // evidence against the dealer whoever sent it (spec §5, R5).
        for (DkgMessage complaint : r5.all(DkgMessage.Kind.EXTRACTION_COMPLAINT)) {
            int i = complaint.subject();
            int j = complaint.sender();
            if (!published.containsKey(i) || marked.contains(i)) continue;
            if (ThresholdVss.checkPedersenPublic(q.commitments().get(i), j, complaint.s(), complaint.sPrime())
                    && !ThresholdVss.checkFeldmanPublic(published.get(i), j, complaint.s())) {
                marked.add(i); // R5: a valid complaint
            }
        }
        for (int i : marked) published.remove(i);
        return new Marks(Collections.unmodifiableSortedSet(marked), published);
    }

    static Outputs finish(DkgConfig config, Qualification q, Marks marks, DkgRound r6) {
        Map<Integer, List<JubjubPoint>> extraction = new TreeMap<>(marks.published());
        for (int i : marks.marked()) {
            SortedMap<Integer, BigInteger[]> valid = new TreeMap<>();
            for (int j = 1; j <= config.n(); j++) {
                if (j == i) continue;
                DkgMessage pair = r6.single(DkgMessage.Kind.RECONSTRUCTION, j, i);
                if (pair != null && ThresholdVss.checkPedersenPublic(q.commitments().get(i), j, pair.s(), pair.sPrime())) {
                    valid.put(j, new BigInteger[]{pair.s(), pair.sPrime()});
                }
            }
            extraction.put(i, ThresholdVss.reconstruct(q.commitments().get(i), config.t(), valid).extraction());
        }
        int t = config.t();
        List<JubjubPoint> summed = new ArrayList<>(t + 1);
        for (int k = 0; k <= t; k++) {
            FastJubjubPoint acc = FastJubjubPoint.IDENTITY;
            for (int i : q.qual()) acc = acc.add(FastJubjubPoint.of(extraction.get(i).get(k)));
            summed.add(acc.toJubjubPoint());
        }
        JubjubPoint y = summed.get(0);
        if (y.isIdentity()) {
            throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.IDENTITY_JOINT_KEY,
                    "the joint key is the identity");
        }
        List<JubjubPoint> verification = new ArrayList<>(config.n());
        for (int j = 1; j <= config.n(); j++) {
            verification.add(ThresholdMath.evaluateInExponent(summed, j));
        }
        return new Outputs(Collections.unmodifiableMap(extraction), y, List.copyOf(verification));
    }
}
