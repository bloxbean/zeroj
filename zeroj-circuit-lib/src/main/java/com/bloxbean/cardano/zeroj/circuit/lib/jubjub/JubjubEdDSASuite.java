package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T6;

import java.math.BigInteger;

/**
 * Pinned constants of the {@code ZeroJ-JubjubEdDSA-v1} suite.
 *
 * <p>The normative specification is
 * <a href="../../../../../../../../../docs/specs/jubjub-eddsa-v1.md">docs/specs/jubjub-eddsa-v1.md</a>.
 * This class exists so the off-circuit and in-circuit implementations read the same literals
 * from one place; the spec, not this file, is authoritative.
 *
 * <h2>Domain separation</h2>
 * The nonce and challenge are separate uses of Poseidon and must not be interchangeable. Each
 * seeds the sponge's <b>capacity</b> cell with a distinct tag rather than the customary zero.
 * This costs nothing — it replaces a constant that was already there — and it means a value
 * computed for one use can never be reinterpreted as the other.
 *
 * <p>Each tag is derived from its ASCII label as
 * {@code OS2IP(SHA-512(label)) mod p}, with the digest read big-endian. The derivation is
 * documented so it can be audited and is asserted by {@code JubjubEdDSASuiteTest}, but the
 * literals below are what the implementation uses — nothing is derived at runtime.
 *
 * <h2>Why {@code t=6} for the challenge</h2>
 * The challenge absorbs five field elements {@code (R.u, R.v, pk.u, pk.v, msg)}. With a
 * capacity of one, the rate is {@code t - 1}, so a single permutation needs {@code t >= 6}.
 * {@code t = 5} has rate 4 and cannot express it.
 *
 * <p>Measured, in-circuit: the five-element challenge under {@code t=6} with a tag costs
 * <b>2,772</b> constraints, against <b>3,312</b> for the previous untagged four-fold
 * {@code t=3} construction and <b>4,140</b> for a tagged five-fold one. The wide permutation
 * is both cheaper and domain-separated, so there was no reason to ship a folded interim and
 * invalidate signatures twice.
 */
public final class JubjubEdDSASuite {

    private JubjubEdDSASuite() {}

    /** Suite identifier. A change to any constant here requires a new identifier, not an edit. */
    public static final String SUITE_ID = "ZeroJ-JubjubEdDSA-v1";

    /** Label the challenge tag is derived from. */
    public static final String CHALLENGE_TAG_LABEL = SUITE_ID + "-challenge";

    /** Label the nonce tag is derived from. */
    public static final String NONCE_TAG_LABEL = SUITE_ID + "-nonce";

    /**
     * Capacity-cell tag for the challenge sponge.
     * {@code OS2IP(SHA-512("ZeroJ-JubjubEdDSA-v1-challenge")) mod p}.
     */
    public static final BigInteger CHALLENGE_TAG = new BigInteger(
            "00eddbdea8f7a5571d7ba19cab887f55f5225616ae1a827da58198fec59f999b", 16);

    /**
     * Capacity-cell tag for the nonce sponge.
     * {@code OS2IP(SHA-512("ZeroJ-JubjubEdDSA-v1-nonce")) mod p}.
     */
    public static final BigInteger NONCE_TAG = new BigInteger(
            "6737a0f0a6c1453e3776d8f7f0ab0181b254d79b0d450d72c46803ed651ae865", 16);

    /** Poseidon preset for the challenge: {@code t=6}, rate 5. */
    public static PoseidonParams challengeParams() {
        return PoseidonParamsBLS12_381T6.INSTANCE;
    }

    /** Poseidon preset for the nonce: {@code t=3}, rate 2. */
    public static PoseidonParams nonceParams() {
        return PoseidonParamsBLS12_381T3.INSTANCE;
    }
}
