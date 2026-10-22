package org.zeroj.examples.pedersen.g1.onchain;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;

import java.math.BigInteger;

/**
 * Test harness only (ADR-0060 D9, builtin evidence on a node): succeeds iff
 * {@code compress(bls12_381_G1_multiScalarMul(scalars, points)) == expected}, for lists of any
 * lengths, including empty and unequal ones. Same logic as the Julc-VM-only {@code G1MsmEvidenceProbe}
 * of {@code zeroj-onchain-julc}. The datum is ignored and anyone can spend: this is not an example
 * validator and provides no authorization of any kind.
 */
@SpendingValidator
public class G1MsmNodeProbe {

    record Probe(JulcList<BigInteger> scalars, JulcList<byte[]> points, byte[] expected) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        return Builtins.equalsByteString(
                Builtins.bls12_381_G1_compress(Builtins.bls12_381_G1_multiScalarMul(
                        Builtins.scalarsFromList(probe.scalars()), Builtins.g1PointsFromCompressed(probe.points()))),
                probe.expected());
    }
}
