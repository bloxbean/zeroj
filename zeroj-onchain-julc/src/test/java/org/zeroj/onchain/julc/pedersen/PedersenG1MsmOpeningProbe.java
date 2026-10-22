package org.zeroj.onchain.julc.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

import java.math.BigInteger;

/**
 * Test harness only (ADR-0060 D9 measurement): the scalar-opening equation with one two-term
 * {@code bls12_381_G1_multiScalarMul} instead of two {@code scalarMul}, for the cost comparison. The
 * test passes only canonical scalars.
 */
@SpendingValidator
public class PedersenG1MsmOpeningProbe {

    record Probe(byte[] commitment, BigInteger value, BigInteger blinding) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        return Builtins.bls12_381_G1_equal(
                Builtins.bls12_381_G1_multiScalarMul(
                        Builtins.scalars(probe.value(), probe.blinding()),
                        Builtins.g1Points(Builtins.bls12_381_G1_uncompress(PedersenG1Lib.baseGEncoding()),
                                Builtins.bls12_381_G1_uncompress(PedersenG1Lib.baseHEncoding()))),
                PedersenG1Lib.decodeCommitment(probe.commitment()));
    }
}
