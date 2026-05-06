package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class InCircuitEdDSAJubjubTest {

    private static final BigInteger SK = new BigInteger(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
            .mod(JubjubCurve.SUBGROUP_ORDER);
    private static final BigInteger MSG = new BigInteger(
            "0101010101010101010101010101010101010101010101010101010101010101", 16)
            .mod(JubjubCurve.BASE_FIELD_PRIME);

    @Test
    @DisplayName("In-circuit verify accepts a valid off-circuit signature")
    void verify_acceptsValidSignature() {
        EdDSAJubjub.Keypair kp = EdDSAJubjub.keypairFromSecret(SK);
        EdDSAJubjub.Signature sig = EdDSAJubjub.sign(SK, MSG);

        var circuit = buildVerifyCircuit();
        assertDoesNotThrow(() -> circuit.calculateWitness(witnessMap(kp, sig, MSG), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("In-circuit verify rejects tampered message")
    void verify_rejectsTamperedMessage() {
        EdDSAJubjub.Keypair kp = EdDSAJubjub.keypairFromSecret(SK);
        EdDSAJubjub.Signature sig = EdDSAJubjub.sign(SK, MSG);
        BigInteger tamperedMsg = MSG.add(BigInteger.ONE).mod(JubjubCurve.BASE_FIELD_PRIME);

        var circuit = buildVerifyCircuit();
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(witnessMap(kp, sig, tamperedMsg), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("In-circuit verify rejects malleated S = S + l")
    void verify_rejectsMalleatedS() {
        EdDSAJubjub.Keypair kp = EdDSAJubjub.keypairFromSecret(SK);
        EdDSAJubjub.Signature sig = EdDSAJubjub.sign(SK, MSG);
        // S + l is mathematically equivalent but out of range; the S < l
        // check inside the gadget must reject.
        EdDSAJubjub.Signature malleated = new EdDSAJubjub.Signature(
                sig.r(), sig.s().add(JubjubCurve.SUBGROUP_ORDER));

        var circuit = buildVerifyCircuit();
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(witnessMap(kp, malleated, MSG), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("In-circuit verify rejects wrong signer public key")
    void verify_rejectsWrongPk() {
        EdDSAJubjub.Keypair realKp = EdDSAJubjub.keypairFromSecret(SK);
        EdDSAJubjub.Signature sig = EdDSAJubjub.sign(SK, MSG);
        EdDSAJubjub.Keypair wrongKp = EdDSAJubjub.keypairFromSecret(
                SK.add(BigInteger.ONE).mod(JubjubCurve.SUBGROUP_ORDER));

        var circuit = buildVerifyCircuit();
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(witnessMap(wrongKp, sig, MSG), CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  Test helpers
    // ------------------------------------------------------------------

    private static CircuitBuilder buildVerifyCircuit() {
        return CircuitBuilder.create("eddsa_verify")
                .publicVar("pkU").publicVar("pkV")
                .publicVar("rU").publicVar("rV")
                .publicVar("msg").publicVar("s")
                .secretVar("kModL").secretVar("kQuotient")
                .define(api -> {
                    var pk = new InCircuitJubjub.Point(
                            api.var("pkU"), api.var("pkV"), api.constant(1),
                            api.mul(api.var("pkU"), api.var("pkV")));
                    var rPoint = new InCircuitJubjub.Point(
                            api.var("rU"), api.var("rV"), api.constant(1),
                            api.mul(api.var("rU"), api.var("rV")));
                    InCircuitEdDSAJubjub.verify(api, pk, api.var("msg"), rPoint,
                            api.var("s"), api.var("kModL"), api.var("kQuotient"));
                });
    }

    private static Map<String, List<BigInteger>> witnessMap(
            EdDSAJubjub.Keypair kp, EdDSAJubjub.Signature sig, BigInteger msg) {
        var kReduction = InCircuitEdDSAJubjub.witnessComputeKReduction(sig.r(), kp.pk(), msg);
        var m = new java.util.HashMap<String, List<BigInteger>>();
        m.put("pkU", List.of(kp.pk().affineU()));
        m.put("pkV", List.of(kp.pk().affineV()));
        m.put("rU", List.of(sig.r().affineU()));
        m.put("rV", List.of(sig.r().affineV()));
        m.put("msg", List.of(msg));
        m.put("s", List.of(sig.s()));
        m.put("kModL", List.of(kReduction.kModL()));
        m.put("kQuotient", List.of(kReduction.kQuotient()));
        return m;
    }
}
