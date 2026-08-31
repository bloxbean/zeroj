package com.bloxbean.cardano.zeroj.examples.dsl.auction.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * On-chain ZK auction verifier — validates sealed bids without revealing bid amounts.
 * <p>
 * The ZK circuit (sealed_bid.circom) proves:
 *   1. The bid matches the on-chain commitment: Poseidon(bidAmount, salt) == commitment
 *   2. The bid exceeds the reserve price: bidAmount >= reservePrice
 * <p>
 * Public inputs: [bidCommitment, reservePrice]
 * <p>
 * The bidCommitment is stored in the datum (set during bidding phase).
 * The reservePrice is a validator parameter (set by the auctioneer at deploy time).
 * <p>
 * This domain-specific verifier composes the reusable {@link Groth16BLS12381Lib}
 * on-chain library with a {@code reservePriceBytes} binding parameter.
 */
@SpendingValidator
public class ZkAuctionVerifier {

    @Param static byte[] reservePriceBytes;  // Reserve price as big-endian bytes
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        PlutusData inputs = Builtins.unListData(datum);
        BigInteger pub1 = Builtins.asInteger(Builtins.headList(Builtins.tailList(inputs)));  // reservePrice

        // Binding: reserve price must match the auctioneer's configured reserve
        BigInteger committedReserve = Builtins.byteStringToInteger(true, reservePriceBytes);
        boolean reserveMatches = pub1.equals(committedReserve);

        boolean proofValid = Groth16BLS12381Lib.verify(datum, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return reserveMatches && proofValid;
    }
}
