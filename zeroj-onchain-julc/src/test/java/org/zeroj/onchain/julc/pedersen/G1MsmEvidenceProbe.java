package org.zeroj.onchain.julc.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;

import java.math.BigInteger;

/**
 * Test harness only (builtin evidence): {@code compress(bls12_381_G1_multiScalarMul(scalars, points))}
 * equals {@code expected}, for lists of any lengths, including empty and unequal ones.
 */
@SpendingValidator
public class G1MsmEvidenceProbe {

    record Probe(JulcList<BigInteger> scalars, JulcList<byte[]> points, byte[] expected) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        return Builtins.equalsByteString(
                Builtins.bls12_381_G1_compress(Builtins.bls12_381_G1_multiScalarMul(
                        Builtins.scalarsFromList(probe.scalars()), Builtins.g1PointsFromCompressed(probe.points()))),
                probe.expected());
    }
}
