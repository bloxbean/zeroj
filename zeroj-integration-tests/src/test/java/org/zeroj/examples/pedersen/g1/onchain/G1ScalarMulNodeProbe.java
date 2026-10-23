package org.zeroj.examples.pedersen.g1.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

import java.math.BigInteger;

/**
 * Test harness only (ADR-0060 D9, builtin evidence on a node): succeeds iff
 * {@code compress(bls12_381_G1_scalarMul(scalar, G)) == expected} for an arbitrary integer, including
 * negative and {@code ≥ q} values the library never passes. Same logic as the Julc-VM-only
 * {@code G1ScalarMulEvidenceProbe} of {@code zeroj-onchain-julc}. The datum is ignored and anyone can
 * spend: this is not an example validator and provides no authorization of any kind.
 */
@SpendingValidator
public class G1ScalarMulNodeProbe {

    record Probe(BigInteger scalar, byte[] expected) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        return Builtins.equalsByteString(
                Builtins.bls12_381_G1_compress(Builtins.bls12_381_G1_scalarMul(probe.scalar(), Builtins.bls12_381_G1_uncompress(PedersenG1Lib.baseGEncoding()))),
                probe.expected());
    }
}
