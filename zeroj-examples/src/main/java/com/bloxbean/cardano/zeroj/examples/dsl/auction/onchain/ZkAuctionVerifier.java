package com.bloxbean.cardano.zeroj.examples.dsl.auction.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.julc.stdlib.lib.BlsLib;

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
 * This is a domain-specific verifier that extends the core Groth16 pattern
 * (from {@code zeroj-onchain-julc}) with a {@code reservePriceBytes} binding
 * parameter, demonstrating how to customize the core verifier for a specific use case.
 */
@SpendingValidator
public class ZkAuctionVerifier {

    @Param static byte[] reservePriceBytes;  // Reserve price as big-endian bytes
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static byte[] vkIc0;
    @Param static byte[] vkIc1;
    @Param static byte[] vkIc2;

    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        PlutusData inputs = Builtins.unListData(datum);
        BigInteger pub0 = Builtins.asInteger(Builtins.headList(inputs));  // bidCommitment
        BigInteger pub1 = Builtins.asInteger(Builtins.headList(Builtins.tailList(inputs)));  // reservePrice

        // Binding: reserve price must match the auctioneer's configured reserve
        BigInteger committedReserve = Builtins.byteStringToInteger(true, reservePriceBytes);
        boolean reserveMatches = pub1.equals(committedReserve);

        // Groth16 verification
        byte[] a = BlsLib.g1Uncompress(proof.piA());
        byte[] b = BlsLib.g2Uncompress(proof.piB());
        byte[] c = BlsLib.g1Uncompress(proof.piC());
        byte[] alpha = BlsLib.g1Uncompress(vkAlpha);
        byte[] beta  = BlsLib.g2Uncompress(vkBeta);
        byte[] gamma = BlsLib.g2Uncompress(vkGamma);
        byte[] delta = BlsLib.g2Uncompress(vkDelta);
        byte[] ic0   = BlsLib.g1Uncompress(vkIc0);
        byte[] ic1   = BlsLib.g1Uncompress(vkIc1);
        byte[] ic2   = BlsLib.g1Uncompress(vkIc2);

        byte[] vkX = BlsLib.g1Add(ic0,
                BlsLib.g1Add(BlsLib.g1ScalarMul(pub0, ic1), BlsLib.g1ScalarMul(pub1, ic2)));

        byte[] negAlpha = BlsLib.g1Neg(alpha);
        byte[] lhs = BlsLib.mulMlResult(BlsLib.millerLoop(a, b), BlsLib.millerLoop(negAlpha, beta));
        byte[] rhs = BlsLib.mulMlResult(BlsLib.millerLoop(vkX, gamma), BlsLib.millerLoop(c, delta));

        return reserveMatches && BlsLib.finalVerify(lhs, rhs);
    }
}
