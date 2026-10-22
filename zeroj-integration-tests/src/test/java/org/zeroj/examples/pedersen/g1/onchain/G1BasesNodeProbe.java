package org.zeroj.examples.pedersen.g1.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

/**
 * Test harness only (ADR-0060 I1, on-node reproduction of the bases): succeeds iff
 * {@code bls12_381_G1_hashToGroup("G", dst)} and {@code ("H", dst)}, compressed, equal the library's
 * pinned {@link PedersenG1Lib#baseGEncoding()} and {@link PedersenG1Lib#baseHEncoding()}. The redeemer
 * carries {@code dst}; with {@code DST_B} (spec §2.1) the spend must succeed. The datum is ignored and
 * anyone can spend: this is not an example validator.
 */
@SpendingValidator
public class G1BasesNodeProbe {

    record Probe(byte[] dst) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        byte[] g = Builtins.consByteString(71L, Builtins.emptyByteString());
        byte[] h = Builtins.consByteString(72L, Builtins.emptyByteString());
        return Builtins.equalsByteString(
                        Builtins.bls12_381_G1_compress(Builtins.bls12_381_G1_hashToGroup(g, probe.dst())),
                        PedersenG1Lib.baseGEncoding())
                && Builtins.equalsByteString(
                        Builtins.bls12_381_G1_compress(Builtins.bls12_381_G1_hashToGroup(h, probe.dst())),
                        PedersenG1Lib.baseHEncoding());
    }
}
