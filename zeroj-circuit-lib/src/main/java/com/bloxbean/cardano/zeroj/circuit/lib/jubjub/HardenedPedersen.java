package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import java.util.Objects;

/**
 * Internal fixed-limb pure-Java Pedersen-generation candidate from ADR-0039 M9.
 *
 * <p>This path contains no secret {@code BigInteger} operation and uses a fixed 252-iteration
 * point schedule for both legs. It remains a separate dedicated-host candidate until its own
 * timing, JVM, and external-review gates pass. Existing disclosed-opening verification remains
 * on {@link PedersenCommitment#verify}. The class is deliberately package-private so an
 * unreviewed candidate cannot be mistaken for a released hardened API.
 */
final class HardenedPedersen {

    @FunctionalInterface
    interface CommitObserver {
        void afterAdmission();
    }

    private static final CommitObserver NO_OBSERVER = () -> { };

    private HardenedPedersen() {
    }

    /** Generates {@code [value]G + [blinding]H} from an owned mutable opening. */
    static JubjubPoint commit(HardenedPedersenOpening opening) {
        return commit(opening, NO_OBSERVER);
    }

    static JubjubPoint commit(
            HardenedPedersenOpening opening, CommitObserver observer) {
        Objects.requireNonNull(opening, "opening");
        Objects.requireNonNull(observer, "observer");
        PedersenScratch scratch = new PedersenScratch();
        HardenedPedersenOpening.Lease lease = opening.admit();
        try {
            observer.afterAdmission();
            lease.copyInto(scratch);
            CtJubjubPointOps.generator(scratch.words, PedersenScratch.GENERATOR);
            CtJubjubPointOps.pedersenH(scratch.words, PedersenScratch.H);
            CtJubjubPointOps.scalarMul(
                    scratch.words, PedersenScratch.VALUE_POINT,
                    scratch.words, PedersenScratch.GENERATOR,
                    scratch.words, PedersenScratch.VALUE,
                    scratch.words, PedersenScratch.POINT_WORK);
            CtJubjubPointOps.scalarMul(
                    scratch.words, PedersenScratch.BLINDING_POINT,
                    scratch.words, PedersenScratch.H,
                    scratch.words, PedersenScratch.BLINDING,
                    scratch.words, PedersenScratch.POINT_WORK);
            CtJubjubPointOps.add(
                    scratch.words, PedersenScratch.SUM,
                    scratch.words, PedersenScratch.VALUE_POINT,
                    scratch.words, PedersenScratch.BLINDING_POINT,
                    scratch.words, PedersenScratch.POINT_WORK);
            CtJubjubPointOps.normalize(
                    scratch.words, PedersenScratch.NORMALIZED,
                    scratch.words, PedersenScratch.SUM,
                    scratch.words, PedersenScratch.POINT_WORK);
            if (CtJubjubPointOps.wellFormedMask(
                    scratch.words, PedersenScratch.NORMALIZED,
                    scratch.words, PedersenScratch.CHECK_WORK) != -1L) {
                throw new IllegalStateException(
                        "fixed-limb Pedersen generation produced an invalid public point");
            }
            return JubjubPublicAdapter.normalizedPoint(
                    scratch.words, PedersenScratch.NORMALIZED,
                    scratch.publicCoordinates, 0, 32,
                    scratch.words, PedersenScratch.CHECK_WORK);
        } finally {
            try {
                scratch.wipe();
            } finally {
                lease.close();
            }
        }
    }
}
