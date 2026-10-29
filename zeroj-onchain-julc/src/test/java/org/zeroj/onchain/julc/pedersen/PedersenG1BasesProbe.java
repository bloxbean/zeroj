package org.zeroj.onchain.julc.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

/**
 * Test harness only (ADR-0060 I1): {@code bls12_381_G1_hashToGroup("G", DST_B)} and
 * {@code ("H", DST_B)} equal the library's pinned bases. The redeemer carries {@code DST_B}.
 */
@SpendingValidator
public class PedersenG1BasesProbe {

    record Probe(byte[] dstB) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        byte[] g = Builtins.consByteString(71L, Builtins.emptyByteString());
        byte[] h = Builtins.consByteString(72L, Builtins.emptyByteString());
        return Builtins.equalsByteString(
                        Builtins.bls12_381_G1_compress(Builtins.bls12_381_G1_hashToGroup(g, probe.dstB())),
                        PedersenG1Lib.baseGEncoding())
                && Builtins.equalsByteString(
                        Builtins.bls12_381_G1_compress(Builtins.bls12_381_G1_hashToGroup(h, probe.dstB())),
                        PedersenG1Lib.baseHEncoding());
    }
}
