package org.zeroj.examples.pedersen.g1.onchain;

import org.julclang.core.types.JulcG1;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

import java.math.BigInteger;

/**
 * ADR-0060 M4 example validator (experimental, not published): an output locked by a
 * {@code pedersen-bls12-381-g1-v1} commitment, spent by disclosing its opening.
 *
 * <p>Datum {@code Holding(owner, commitment)}: the owner's 28-octet key hash and the 48-octet
 * compressed commitment {@code C = [m]·G + [r]·H}. Redeemer {@code Opening(value, blinding)}.
 *
 * <p>The spend is accepted iff
 * <ul>
 *   <li>the owner key hash is exactly 28 octets and the owner signs the transaction, and</li>
 *   <li>{@link PedersenG1Lib#verifyScalarOpeningBounded} accepts {@code (value, blinding)} for the
 *       strictly decoded commitment with an application amount bound of 64 bits. The library fails
 *       the script on a commitment that is not exactly 48 octets, not a canonical encoding or not in
 *       the subgroup, on {@code value} or {@code blinding} outside {@code [0, q)}, and on
 *       {@code value ≥ 2^64}, before any scalar multiplication; a well-formed opening that does not
 *       match returns {@code false}.</li>
 * </ul>
 *
 * <p><b>What this example does not provide</b> (spec §9, ADR-0060 D9):
 * <ul>
 *   <li><b>No replay protection beyond UTxO consumption.</b> The output can be spent once; the same
 *       opening is accepted for any other output that carries the same commitment and owner.</li>
 *   <li><b>No context or output binding.</b> The opening is not bound to the transaction, its
 *       outputs or where the locked value goes; only the owner's signature authorizes the spend.</li>
 *   <li><b>The opened value is public forever</b> once the spending transaction is on chain, and so
 *       is the blinding: the commitment stops hiding anything.</li>
 *   <li><b>Residues, not balances.</b> {@code value} is a residue mod {@code q}; the 64-bit bound is
 *       this example's application policy, not a property of the profile.</li>
 *   <li>Example only. No audit, no production claim.</li>
 * </ul>
 */
@SpendingValidator
public class G1ScalarOpeningValidator {

    record Holding(byte[] owner, byte[] commitment) {}

    record Opening(BigInteger value, BigInteger blinding) {}

    @Entrypoint
    public static boolean validate(Holding datum, Opening opening, ScriptContext ctx) {
        if (Builtins.lengthOfByteString(datum.owner()) != 28L || !signedBy(ctx, datum.owner())) {
            return false;
        }
        JulcG1 commitment = PedersenG1Lib.decodeCommitment(datum.commitment());
        return PedersenG1Lib.verifyScalarOpeningBounded(
                commitment, opening.value(), opening.blinding(), amountBits());
    }

    /** The application amount bound: values must be below {@code 2^64}. */
    private static BigInteger amountBits() {
        return BigInteger.valueOf(64L);
    }

    private static boolean signedBy(ScriptContext ctx, byte[] owner) {
        boolean found = false;
        for (var signer : ctx.txInfo().signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), owner);
        }
        return found;
    }
}
