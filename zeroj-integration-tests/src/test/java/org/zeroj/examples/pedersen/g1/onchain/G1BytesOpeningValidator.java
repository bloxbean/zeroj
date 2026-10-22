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
 * {@code pedersen-bls12-381-g1-bytes-v1} commitment, spent by disclosing the committed octets.
 *
 * <p>Datum {@code Holding(owner, commitment)}: the owner's 28-octet key hash and the 48-octet
 * compressed commitment {@code C = [HashBytesToScalarG1(payload)]·G + [r]·H}. Redeemer
 * {@code BytesOpening(payload, blinding)}.
 *
 * <p>The spend is accepted iff
 * <ul>
 *   <li>the owner key hash is exactly 28 octets and the owner signs the transaction, and</li>
 *   <li>{@link PedersenG1Lib#verifyBytesOpening} accepts {@code (payload, blinding)} for the
 *       strictly decoded commitment. The library recomputes the scalar from the payload on-chain
 *       (spec §5, {@code sha2_256}); it fails the script on a commitment that is not exactly 48
 *       octets, not canonical or not in the subgroup, and on {@code blinding} outside
 *       {@code [0, q)} before any hashing or multiplication. A well-formed opening that does not
 *       match returns {@code false}.</li>
 * </ul>
 *
 * <p><b>What this example does not provide</b> (spec §9, ADR-0060 D9):
 * <ul>
 *   <li><b>No replay protection beyond UTxO consumption.</b> The output can be spent once; the same
 *       opening is accepted for any other output that carries the same commitment and owner.</li>
 *   <li><b>No context or output binding.</b> The opening is not bound to the transaction, its
 *       outputs or where the locked value goes; only the owner's signature authorizes the spend.</li>
 *   <li><b>Every opened octet is public forever</b> once the spending transaction is on chain, as is
 *       the blinding.</li>
 *   <li><b>Payload size.</b> The payload travels in the redeemer, so it is bounded by the
 *       16,384-octet transaction (which also carries this script) and by the execution budget, whose
 *       hashing cost grows with the payload. ADR-0060 M4 measures the limit; this example claims
 *       none.</li>
 *   <li>Example only. No audit, no production claim.</li>
 * </ul>
 */
@SpendingValidator
public class G1BytesOpeningValidator {

    record Holding(byte[] owner, byte[] commitment) {}

    record BytesOpening(byte[] payload, BigInteger blinding) {}

    @Entrypoint
    public static boolean validate(Holding datum, BytesOpening opening, ScriptContext ctx) {
        if (Builtins.lengthOfByteString(datum.owner()) != 28L || !signedBy(ctx, datum.owner())) {
            return false;
        }
        JulcG1 commitment = PedersenG1Lib.decodeCommitment(datum.commitment());
        return PedersenG1Lib.verifyBytesOpening(commitment, opening.payload(), opening.blinding());
    }

    private static boolean signedBy(ScriptContext ctx, byte[] owner) {
        boolean found = false;
        for (var signer : ctx.txInfo().signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), owner);
        }
        return found;
    }
}
