package org.zeroj.examples.pedersen.g1.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

/**
 * Test harness only (ADR-0060 I10, node parity): exposes {@link PedersenG1Lib#decodeCommitment} to a
 * Cardano node. The redeemer carries an encoding of any length; the spend succeeds iff the library
 * decodes it and the decoded point re-encodes to exactly the same octets. The datum is ignored and
 * anyone can spend: this is not an example validator and provides no authorization of any kind.
 */
@SpendingValidator
public class G1DecodeNodeProbe {

    record Probe(byte[] encoded) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        return Builtins.equalsByteString(
                PedersenG1Lib.encodeCommitment(PedersenG1Lib.decodeCommitment(probe.encoded())), probe.encoded());
    }
}
