package org.zeroj.onchain.julc.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcG1;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

import java.math.BigInteger;

/**
 * Test harness only: {@code operation} 0 is {@code a + b}, 1 is {@code a − b}, 2 is {@code −a}; the
 * result must encode to {@code expected}.
 */
@SpendingValidator
public class PedersenG1SumProbe {

    record Probe(byte[] a, byte[] b, BigInteger operation, byte[] expected) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        JulcG1 a = PedersenG1Lib.decodeCommitment(probe.a());
        JulcG1 b = PedersenG1Lib.decodeCommitment(probe.b());
        long op = probe.operation().longValue();
        JulcG1 result = op == 0L ? PedersenG1Lib.add(a, b)
                : op == 1L ? PedersenG1Lib.subtract(a, b) : PedersenG1Lib.negate(a);
        return Builtins.equalsByteString(PedersenG1Lib.encodeCommitment(result), probe.expected());
    }
}
