package org.zeroj.onchain.julc.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

import java.math.BigInteger;

/**
 * Test harness only (builtin evidence): {@code compress(bls12_381_G1_scalarMul(scalar, G)) == expected}
 * for an arbitrary integer, including negative and {@code ≥ q} values the library never passes.
 */
@SpendingValidator
public class G1ScalarMulEvidenceProbe {

    record Probe(BigInteger scalar, byte[] expected) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        return Builtins.equalsByteString(
                Builtins.bls12_381_G1_compress(Builtins.bls12_381_G1_scalarMul(probe.scalar(), Builtins.bls12_381_G1_uncompress(PedersenG1Lib.baseGEncoding()))),
                probe.expected());
    }
}
