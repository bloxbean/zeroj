package org.zeroj.onchain.julc.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

/**
 * Test harness only: exposes {@link PedersenG1Lib#decodeCommitment} to the Julc VM. The redeemer
 * carries the encoding; the script succeeds iff decoding succeeds and re-encodes to the same octets.
 */
@SpendingValidator
public class PedersenG1DecodeProbe {

    record Probe(byte[] encoded) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        return Builtins.equalsByteString(
                PedersenG1Lib.encodeCommitment(PedersenG1Lib.decodeCommitment(probe.encoded())), probe.encoded());
    }
}
