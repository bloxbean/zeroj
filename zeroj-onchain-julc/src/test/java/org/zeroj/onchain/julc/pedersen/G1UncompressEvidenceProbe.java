package org.zeroj.onchain.julc.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;

/**
 * Test harness only (ADR-0060 D9 builtin evidence): succeeds iff {@code bls12_381_G1_uncompress}
 * accepts the octets, and reports whether they re-encode exactly ({@code roundTrip}). Records builtin
 * behaviour; no library relies on it.
 */
@SpendingValidator
public class G1UncompressEvidenceProbe {

    record Probe(byte[] encoded, boolean roundTrip) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        byte[] again = Builtins.bls12_381_G1_compress(Builtins.bls12_381_G1_uncompress(probe.encoded()));
        return Builtins.equalsByteString(again, probe.encoded()) == probe.roundTrip();
    }
}
