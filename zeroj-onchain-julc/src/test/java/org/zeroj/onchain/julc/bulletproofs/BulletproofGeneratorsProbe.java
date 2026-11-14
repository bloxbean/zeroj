package org.zeroj.onchain.julc.bulletproofs;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;

/**
 * Test harness only (ADR-0061 M4, I1): {@code compress(bls12_381_G1_hashToGroup(message_i, DST_BP))}
 * equals {@code expected_i} for every pair, so the Julc VM's RFC 9380 implementation reproduces the
 * pinned generator encodings (spec §2). The redeemer carries {@code DST_BP} and the messages.
 */
@SpendingValidator
public class BulletproofGeneratorsProbe {

    record Probe(byte[] dst, JulcList<byte[]> messages, JulcList<byte[]> expected) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        return allMatch(probe.dst(), probe.messages(), probe.expected());
    }

    static boolean allMatch(byte[] dst, JulcList<byte[]> messages, JulcList<byte[]> expected) {
        if (messages.isEmpty()) {
            return expected.isEmpty();
        }
        if (expected.isEmpty()) {
            return false;
        }
        return Builtins.equalsByteString(Builtins.bls12_381_G1_compress(Builtins.bls12_381_G1_hashToGroup(messages.head(), dst)),
                expected.head()) && allMatch(dst, messages.tail(), expected.tail());
    }
}
