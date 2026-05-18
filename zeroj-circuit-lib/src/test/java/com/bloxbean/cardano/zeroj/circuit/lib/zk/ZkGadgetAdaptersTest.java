package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBits;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.PoseidonN;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMiMC;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubPoint;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.PedersenCommitment;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBN254T3;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ZkGadgetAdaptersTest {
    private static final BigInteger EDDSA_SK = new BigInteger(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
            .mod(JubjubCurve.SUBGROUP_ORDER);
    private static final BigInteger EDDSA_MSG = new BigInteger(
            "0101010101010101010101010101010101010101010101010101010101010101", 16)
            .mod(JubjubCurve.BASE_FIELD_PRIME);

    @Test
    void mimcAdapterMatchesSignalAdapter() {
        var symbolic = CircuitBuilder.create("zk-mimc")
                .secretVar("left")
                .secretVar("right")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkMiMC.hash(zk, ZkField.secret(c, "left"), ZkField.secret(c, "right"));
                });

        var signal = CircuitBuilder.create("signal-mimc")
                .secretVar("left")
                .secretVar("right")
                .defineSignals(c -> SignalMiMC.hash(c, c.privateInput("left"), c.privateInput("right")));

        var inputs = Map.of(
                "left", List.of(BigInteger.valueOf(3)),
                "right", List.of(BigInteger.valueOf(11)));

        assertEquals(signal.constraintGraph().gates().size(), symbolic.constraintGraph().gates().size());
        assertArrayEquals(
                signal.calculateWitness(inputs, CurveId.BN254),
                symbolic.calculateWitness(inputs, CurveId.BN254));
    }

    @Test
    void poseidonAdapterMatchesSignalAdapter() {
        var symbolic = CircuitBuilder.create("zk-poseidon")
                .secretVar("left")
                .secretVar("right")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPoseidon.hash(zk, ZkField.secret(c, "left"), ZkField.secret(c, "right"));
                });

        var signal = CircuitBuilder.create("signal-poseidon")
                .secretVar("left")
                .secretVar("right")
                .defineSignals(c -> SignalPoseidon.hash(c, c.privateInput("left"), c.privateInput("right")));

        var inputs = Map.of(
                "left", List.of(BigInteger.valueOf(5)),
                "right", List.of(BigInteger.valueOf(9)));

        assertEquals(signal.constraintGraph().gates().size(), symbolic.constraintGraph().gates().size());
        assertArrayEquals(
                signal.calculateWitness(inputs, CurveId.BN254),
                symbolic.calculateWitness(inputs, CurveId.BN254));
    }

    @Test
    void poseidonNAdapterMatchesSignalAdapterForBn254() {
        var symbolic = CircuitBuilder.create("zk-poseidon-n")
                .secretVar("a")
                .secretVar("b")
                .secretVar("c")
                .secretVar("d")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPoseidonN.hash(
                            zk,
                            PoseidonParamsBN254T3.INSTANCE,
                            ZkField.secret(c, "a"),
                            ZkField.secret(c, "b"),
                            ZkField.secret(c, "c"),
                            ZkField.secret(c, "d"));
                });

        var signal = CircuitBuilder.create("signal-poseidon-n")
                .secretVar("a")
                .secretVar("b")
                .secretVar("c")
                .secretVar("d")
                .defineSignals(c -> PoseidonN.hash(
                        c,
                        PoseidonParamsBN254T3.INSTANCE,
                        c.privateInput("a"),
                        c.privateInput("b"),
                        c.privateInput("c"),
                        c.privateInput("d")));

        var inputs = Map.of(
                "a", List.of(BigInteger.valueOf(5)),
                "b", List.of(BigInteger.valueOf(9)),
                "c", List.of(BigInteger.valueOf(13)),
                "d", List.of(BigInteger.valueOf(17)));

        assertEquals(signal.constraintGraph().gates().size(), symbolic.constraintGraph().gates().size());
        assertArrayEquals(
                signal.calculateWitness(inputs, CurveId.BN254),
                symbolic.calculateWitness(inputs, CurveId.BN254));
    }

    @Test
    void poseidonNExplicitParamsSupportBls12381() {
        BigInteger a = BigInteger.valueOf(5);
        BigInteger b = BigInteger.valueOf(9);
        BigInteger cValue = BigInteger.valueOf(13);
        BigInteger expected = PoseidonHash.hashN(
                PoseidonParamsBLS12_381T3.INSTANCE,
                a,
                b,
                cValue);

        var circuit = CircuitBuilder.create("zk-poseidon-n-bls")
                .secretVar("a")
                .secretVar("b")
                .secretVar("c")
                .publicVar("out")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPoseidonN.hash(
                                    zk,
                                    PoseidonParamsBLS12_381T3.INSTANCE,
                                    ZkField.secret(c, "a"),
                                    ZkField.secret(c, "b"),
                                    ZkField.secret(c, "c"))
                            .assertEqual(ZkField.publicInput(c, "out"));
                });

        var valid = Map.of(
                "a", List.of(a),
                "b", List.of(b),
                "c", List.of(cValue),
                "out", List.of(expected));
        assertDoesNotThrow(() -> circuit.calculateWitness(valid, CurveId.BLS12_381));
        assertDoesNotThrow(() -> circuit.compileR1CS(CurveId.BLS12_381));
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BN254));

        var invalid = Map.of(
                "a", List.of(a),
                "b", List.of(b),
                "c", List.of(cValue),
                "out", List.of(BigInteger.ONE));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(invalid, CurveId.BLS12_381));
    }

    @Test
    void poseidonNRejectsEmptyInputsAndForeignBuilderSignals() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-poseidon-n-empty")
                .defineSignals(c -> ZkPoseidonN.hash(
                        new ZkContext(c),
                        PoseidonParamsBLS12_381T3.INSTANCE)));

        ZkField[] fieldFromOtherBuilder = new ZkField[1];
        CircuitBuilder.create("zk-poseidon-n-other")
                .secretVar("a")
                .defineSignals(c -> fieldFromOtherBuilder[0] = ZkField.secret(c, "a"));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-poseidon-n-local")
                .secretVar("b")
                .defineSignals(c -> ZkPoseidonN.hash(
                        new ZkContext(c),
                        PoseidonParamsBLS12_381T3.INSTANCE,
                        fieldFromOtherBuilder[0],
                        ZkField.secret(c, "b"))));
    }

    @Test
    void poseidonNRejectsNullArguments() {
        CircuitBuilder.create("zk-poseidon-n-null")
                .secretVar("a")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var input = ZkField.secret(c, "a");

                    assertThrows(NullPointerException.class, () -> ZkPoseidonN.hash(
                            null,
                            PoseidonParamsBLS12_381T3.INSTANCE,
                            input));
                    assertThrows(NullPointerException.class, () -> ZkPoseidonN.hash(
                            zk,
                            null,
                            input));
                    assertThrows(NullPointerException.class, () -> ZkPoseidonN.hash(
                            zk,
                            PoseidonParamsBLS12_381T3.INSTANCE,
                            (ZkField[]) null));
                    assertThrows(NullPointerException.class, () -> ZkPoseidonN.hash(
                            zk,
                            PoseidonParamsBLS12_381T3.INSTANCE,
                            input,
                            null));
                });
    }

    @Test
    void merkleComputeRootMatchesSignalAdapterRootBehavior() {
        var symbolic = CircuitBuilder.create("zk-merkle")
                .secretVar("leaf")
                .secretVar("sibling_0")
                .secretVar("sibling_1")
                .secretVar("pathBit_0")
                .secretVar("pathBit_1")
                .publicVar("root")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var leaf = ZkField.secret(c, "leaf");
                    var siblings = ZkArray.secretFields(c, "sibling", 2);
                    var pathBits = ZkArray.secretBools(c, "pathBit", 2);
                    ZkMerkle.computeRoot(zk, leaf, siblings, pathBits, ZkMiMC::hash)
                            .assertEqual(ZkField.publicInput(c, "root"));
                });

        var signal = CircuitBuilder.create("signal-merkle")
                .secretVar("leaf")
                .secretVar("sibling_0")
                .secretVar("sibling_1")
                .secretVar("pathBit_0")
                .secretVar("pathBit_1")
                .publicVar("root")
                .defineSignals(c -> {
                    Signal leaf = c.privateInput("leaf");
                    Signal[] siblings = {
                            c.privateInput("sibling_0"),
                            c.privateInput("sibling_1")
                    };
                    Signal[] pathBits = {
                            c.privateInput("pathBit_0"),
                            c.privateInput("pathBit_1")
                    };
                    c.assertEqual(
                            SignalMerkle.computeRoot(c, leaf, siblings, pathBits, SignalMiMC::hash),
                            c.publicInput("root"));
                });

        var inputs = Map.of(
                "leaf", List.of(BigInteger.valueOf(10)),
                "sibling_0", List.of(BigInteger.valueOf(20)),
                "sibling_1", List.of(BigInteger.valueOf(30)),
                "pathBit_0", List.of(BigInteger.ZERO),
                "pathBit_1", List.of(BigInteger.ONE),
                "root", List.of(expectedMiMCMerkleRoot(
                        BigInteger.valueOf(10),
                        BigInteger.valueOf(20),
                        BigInteger.valueOf(30),
                        BigInteger.ZERO,
                        BigInteger.ONE)));

        assertDoesNotThrow(() -> signal.calculateWitness(inputs, CurveId.BN254));
        assertDoesNotThrow(() -> symbolic.calculateWitness(inputs, CurveId.BN254));

        var invalid = Map.of(
                "leaf", List.of(BigInteger.valueOf(10)),
                "sibling_0", List.of(BigInteger.valueOf(20)),
                "sibling_1", List.of(BigInteger.valueOf(30)),
                "pathBit_0", List.of(BigInteger.ZERO),
                "pathBit_1", List.of(BigInteger.ONE),
                "root", List.of(BigInteger.ONE));
        assertThrows(ArithmeticException.class, () -> symbolic.calculateWitness(invalid, CurveId.BN254));
        assertThrows(ArithmeticException.class, () -> signal.calculateWitness(invalid, CurveId.BN254));
    }

    @Test
    void poseidonExplicitParamsSupportBls12381() {
        var circuit = CircuitBuilder.create("zk-poseidon-bls")
                .secretVar("left")
                .secretVar("right")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPoseidon.hash(
                            zk,
                            PoseidonParamsBLS12_381T3.INSTANCE,
                            ZkField.secret(c, "left"),
                            ZkField.secret(c, "right"));
                });

        assertDoesNotThrow(() -> circuit.compileR1CS(CurveId.BLS12_381));
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BN254));
    }

    @Test
    void merkleVerifySupportsCustomHashFunction() {
        var circuit = CircuitBuilder.create("zk-merkle-verify")
                .publicVar("root")
                .secretVar("leaf")
                .secretVar("sibling_0")
                .secretVar("sibling_1")
                .secretVar("pathBit_0")
                .secretVar("pathBit_1")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkMerkle.verifyProof(
                            zk,
                            ZkField.secret(c, "leaf"),
                            ZkField.publicInput(c, "root"),
                            ZkArray.secretFields(c, "sibling", 2),
                            ZkArray.secretBools(c, "pathBit", 2),
                            (context, left, right) -> left.add(right));
                });

        var valid = Map.of(
                "root", List.of(BigInteger.valueOf(23)),
                "leaf", List.of(BigInteger.valueOf(5)),
                "sibling_0", List.of(BigInteger.valueOf(7)),
                "sibling_1", List.of(BigInteger.valueOf(11)),
                "pathBit_0", List.of(BigInteger.ZERO),
                "pathBit_1", List.of(BigInteger.ONE));
        assertDoesNotThrow(() -> circuit.calculateWitness(valid, CurveId.BN254));

        var invalidRoot = Map.of(
                "root", List.of(BigInteger.valueOf(24)),
                "leaf", List.of(BigInteger.valueOf(5)),
                "sibling_0", List.of(BigInteger.valueOf(7)),
                "sibling_1", List.of(BigInteger.valueOf(11)),
                "pathBit_0", List.of(BigInteger.ZERO),
                "pathBit_1", List.of(BigInteger.ONE));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(invalidRoot, CurveId.BN254));
    }

    @Test
    void hashTypePoseidonAndIsMemberWorkTogether() {
        BigInteger expectedRoot = PoseidonHash.hash(
                PoseidonParamsBN254T3.INSTANCE,
                BigInteger.valueOf(5),
                BigInteger.valueOf(7));

        var circuit = CircuitBuilder.create("zk-merkle-poseidon-member")
                .publicVar("root")
                .publicVar("ok")
                .secretVar("leaf")
                .secretVar("sibling_0")
                .secretVar("pathBit_0")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkMerkle.isMember(
                            zk,
                            ZkField.secret(c, "leaf"),
                            ZkField.publicInput(c, "root"),
                            ZkArray.secretFields(c, "sibling", 1),
                            ZkArray.secretBools(c, "pathBit", 1),
                            ZkMerkle.HashType.POSEIDON)
                            .assertEqual(ZkBool.publicInput(c, "ok"));
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "root", List.of(expectedRoot),
                "ok", List.of(BigInteger.ONE),
                "leaf", List.of(BigInteger.valueOf(5)),
                "sibling_0", List.of(BigInteger.valueOf(7)),
                "pathBit_0", List.of(BigInteger.ZERO)), CurveId.BN254));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "root", List.of(expectedRoot),
                "ok", List.of(BigInteger.ZERO),
                "leaf", List.of(BigInteger.valueOf(5)),
                "sibling_0", List.of(BigInteger.valueOf(7)),
                "pathBit_0", List.of(BigInteger.ZERO)), CurveId.BN254));
    }

    @Test
    void mimcFieldGuardRejectsNonBn254Curve() {
        var circuit = CircuitBuilder.create("zk-mimc-field")
                .secretVar("left")
                .secretVar("right")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkMiMC.hash(zk, ZkField.secret(c, "left"), ZkField.secret(c, "right"));
                });

        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BLS12_381));
        assertThrows(IllegalStateException.class, () -> circuit.calculateWitness(Map.of(
                "left", List.of(BigInteger.ONE),
                "right", List.of(BigInteger.TWO)), CurveId.BLS12_381));
    }

    @Test
    void merkleRejectsMismatchedSiblingAndPathLengths() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-merkle-length")
                .secretVar("leaf")
                .secretVar("sibling_0")
                .secretVar("pathBit_0")
                .secretVar("pathBit_1")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkMerkle.computeRoot(
                            zk,
                            ZkField.secret(c, "leaf"),
                            ZkArray.secretFields(c, "sibling", 1),
                            ZkArray.secretBools(c, "pathBit", 2),
                            ZkMerkle.HashType.MIMC);
                }));
    }

    @Test
    void adaptersRejectSignalsFromDifferentBuilders() {
        ZkField[] fieldFromOtherBuilder = new ZkField[1];
        CircuitBuilder.create("zk-adapter-other")
                .secretVar("left")
                .defineSignals(c -> fieldFromOtherBuilder[0] = ZkField.secret(c, "left"));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-adapter-local")
                .secretVar("right")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkMiMC.hash(zk, fieldFromOtherBuilder[0], ZkField.secret(c, "right"));
                }));
    }

    @Test
    void merkleRejectsRootFromDifferentBuilderBeforeAddingPathConstraints() {
        ZkField[] rootFromOtherBuilder = new ZkField[1];
        CircuitBuilder.create("zk-merkle-other-root")
                .publicVar("root")
                .defineSignals(c -> rootFromOtherBuilder[0] = ZkField.publicInput(c, "root"));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-merkle-local-root")
                .secretVar("leaf")
                .secretVar("sibling_0")
                .secretVar("pathBit_0")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkMerkle.verify(
                            zk,
                            ZkField.secret(c, "leaf"),
                            rootFromOtherBuilder[0],
                            ZkArray.secretFields(c, "sibling", 1),
                            ZkArray.secretBools(c, "pathBit", 1),
                            ZkMiMC::hash);
                }));
    }

    @Test
    void merkleRejectsCustomHashReturningDifferentBuilderSignal() {
        ZkField[] fieldFromOtherBuilder = new ZkField[1];
        CircuitBuilder.create("zk-merkle-other-hash")
                .secretVar("hash")
                .defineSignals(c -> fieldFromOtherBuilder[0] = ZkField.secret(c, "hash"));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-merkle-local-hash")
                .secretVar("leaf")
                .secretVar("sibling_0")
                .secretVar("pathBit_0")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkMerkle.computeRoot(
                            zk,
                            ZkField.secret(c, "leaf"),
                            ZkArray.secretFields(c, "sibling", 1),
                            ZkArray.secretBools(c, "pathBit", 1),
                            (context, left, right) -> fieldFromOtherBuilder[0]);
                }));
    }

    @Test
    void jubjubPointAdapterAddsConstants() {
        JubjubPoint p = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(13));
        JubjubPoint q = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(27));
        JubjubPoint expected = p.add(q);

        var circuit = CircuitBuilder.create("zk-jubjub-add")
                .publicVar("outU")
                .publicVar("outV")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkJubjubPoint.constant(zk, p)
                            .add(zk, ZkJubjubPoint.constant(zk, q))
                            .assertAffineEquals(
                                    zk,
                                    ZkField.publicInput(c, "outU"),
                                    ZkField.publicInput(c, "outV"));
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "outU", List.of(expected.affineU()),
                "outV", List.of(expected.affineV())), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "outU", List.of(BigInteger.ONE),
                "outV", List.of(expected.affineV())), CurveId.BLS12_381));
    }

    @Test
    void jubjubPointAdapterHasNoPublicExtendedCoordinateConstructorAndGuardsField() {
        assertEquals(0, ZkJubjubPoint.class.getConstructors().length);

        var circuit = CircuitBuilder.create("zk-jubjub-affine-field")
                .publicVar("u")
                .publicVar("v")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkJubjubPoint.fromTrustedAffine(
                                    zk,
                                    ZkField.publicInput(c, "u"),
                                    ZkField.publicInput(c, "v"))
                            .assertAffineEquals(
                                    zk,
                                    ZkField.publicInput(c, "u"),
                                    ZkField.publicInput(c, "v"));
                });

        assertDoesNotThrow(() -> circuit.compileR1CS(CurveId.BLS12_381));
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BN254));
    }

    @Test
    void pedersenAdapterMatchesOffCircuitCommitment() {
        BigInteger value = BigInteger.valueOf(42);
        BigInteger blinding = BigInteger.valueOf(12345);
        JubjubPoint expected = PedersenCommitment.commit(value, blinding);

        var circuit = CircuitBuilder.create("zk-pedersen")
                .publicVar("outU")
                .publicVar("outV")
                .secretVar("value")
                .secretVar("blinding")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPedersen.commit(
                            zk,
                            ZkUInt.secret(c, "value", 16),
                            ZkUInt.secret(c, "blinding", 16),
                            16)
                            .assertAffineEquals(
                                    zk,
                                    ZkField.publicInput(c, "outU"),
                                    ZkField.publicInput(c, "outV"));
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "outU", List.of(expected.affineU()),
                "outV", List.of(expected.affineV()),
                "value", List.of(value),
                "blinding", List.of(blinding)), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "outU", List.of(expected.affineU().add(BigInteger.ONE)),
                "outV", List.of(expected.affineV()),
                "value", List.of(value),
                "blinding", List.of(blinding)), CurveId.BLS12_381));
    }

    @Test
    void pedersenAdapterSupportsLsbFirstBitInputs() {
        BigInteger value = BigInteger.valueOf(5);
        BigInteger blinding = BigInteger.valueOf(3);
        JubjubPoint expected = PedersenCommitment.commit(value, blinding);

        var circuit = CircuitBuilder.create("zk-pedersen-bits")
                .publicVar("outU")
                .publicVar("outV")
                .secretVar("valueBit_0")
                .secretVar("valueBit_1")
                .secretVar("valueBit_2")
                .secretVar("valueBit_3")
                .secretVar("blindingBit_0")
                .secretVar("blindingBit_1")
                .secretVar("blindingBit_2")
                .secretVar("blindingBit_3")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPedersen.commitBits(
                            zk,
                            ZkBits.secret(c, "valueBit", 4),
                            ZkBits.secret(c, "blindingBit", 4))
                            .assertAffineEquals(
                                    zk,
                                    ZkField.publicInput(c, "outU"),
                                    ZkField.publicInput(c, "outV"));
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "outU", List.of(expected.affineU()),
                "outV", List.of(expected.affineV()),
                "valueBit_0", List.of(BigInteger.ONE),
                "valueBit_1", List.of(BigInteger.ZERO),
                "valueBit_2", List.of(BigInteger.ONE),
                "valueBit_3", List.of(BigInteger.ZERO),
                "blindingBit_0", List.of(BigInteger.ONE),
                "blindingBit_1", List.of(BigInteger.ONE),
                "blindingBit_2", List.of(BigInteger.ZERO),
                "blindingBit_3", List.of(BigInteger.ZERO)), CurveId.BLS12_381));
    }

    @Test
    void pedersenAdapterRejectsInvalidScalarWidthAndWrongCurve() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-pedersen-width")
                .secretVar("value")
                .secretVar("blinding")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPedersen.commit(
                            zk,
                            ZkUInt.secret(c, "value", 253),
                            ZkUInt.secret(c, "blinding", 8));
                }));

        var circuit = CircuitBuilder.create("zk-pedersen-field")
                .secretVar("value")
                .secretVar("blinding")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPedersen.commit(
                            zk,
                            ZkUInt.secret(c, "value", 8),
                            ZkUInt.secret(c, "blinding", 8));
                });
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BN254));
    }

    @Test
    void pedersenAdapterRejectsNonCanonicalScalarWitness() {
        var circuit = CircuitBuilder.create("zk-pedersen-canonical")
                .publicVar("outU")
                .publicVar("outV")
                .secretVar("value")
                .secretVar("blinding")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPedersen.commit(
                            zk,
                            ZkUInt.secret(c, "value", 252),
                            ZkUInt.secret(c, "blinding", 252),
                            252)
                            .assertAffineEquals(
                                    zk,
                                    ZkField.publicInput(c, "outU"),
                                    ZkField.publicInput(c, "outV"));
                });

        var zeroCommitment = PedersenCommitment.commit(BigInteger.ZERO, BigInteger.ZERO);
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "outU", List.of(zeroCommitment.affineU()),
                "outV", List.of(zeroCommitment.affineV()),
                "value", List.of(JubjubCurve.SUBGROUP_ORDER),
                "blinding", List.of(BigInteger.ZERO)), CurveId.BLS12_381));
    }

    @Test
    void eddsaJubjubAdapterAcceptsValidSignatureAndRejectsTamperedMessage() {
        EdDSAJubjub.Keypair keypair = EdDSAJubjub.keypairFromSecret(EDDSA_SK);
        EdDSAJubjub.Signature signature = EdDSAJubjub.sign(EDDSA_SK, EDDSA_MSG);
        var circuit = buildEddsaVerifyCircuit();

        assertDoesNotThrow(() -> circuit.calculateWitness(
                eddsaWitness(keypair, signature, EDDSA_MSG), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                eddsaWitness(keypair, signature, EDDSA_MSG.add(BigInteger.ONE)), CurveId.BLS12_381));
    }

    @Test
    void eddsaJubjubAdapterRejectsIdentityPublicKey() {
        BigInteger s = BigInteger.valueOf(5);
        EdDSAJubjub.Keypair identityKey = new EdDSAJubjub.Keypair(BigInteger.ONE, JubjubPoint.IDENTITY);
        EdDSAJubjub.Signature forged = new EdDSAJubjub.Signature(
                JubjubPoint.SUBGROUP_GENERATOR.scalarMul(s), s);

        assertThrows(ArithmeticException.class, () -> buildEddsaVerifyCircuit()
                .calculateWitness(eddsaWitness(identityKey, forged, EDDSA_MSG), CurveId.BLS12_381));
    }

    @Test
    void eddsaJubjubAdapterRejectsOversizedScalarMetadata() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("zk-eddsa-width")
                .publicVar("pkU").publicVar("pkV")
                .publicVar("rU").publicVar("rV")
                .publicVar("msg").publicVar("s")
                .secretVar("kModL").secretVar("kQuotient")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkEdDSAJubjub.verify(
                            zk,
                            ZkJubjubPoint.fromTrustedAffine(
                                    zk,
                                    ZkField.publicInput(c, "pkU"),
                                    ZkField.publicInput(c, "pkV")),
                            ZkField.publicInput(c, "msg"),
                            ZkJubjubPoint.fromTrustedAffine(
                                    zk,
                                    ZkField.publicInput(c, "rU"),
                                    ZkField.publicInput(c, "rV")),
                            ZkUInt.publicInput(c, "s", 253),
                            ZkUInt.secret(c, "kModL", 252),
                            ZkUInt.secret(c, "kQuotient", 4));
                }));
    }

    private BigInteger expectedMiMCMerkleRoot(
            BigInteger leaf,
            BigInteger sibling0,
            BigInteger sibling1,
            BigInteger pathBit0,
            BigInteger pathBit1) {
        BigInteger current = leaf;
        current = hashOrderedByPathBit(current, sibling0, pathBit0);
        current = hashOrderedByPathBit(current, sibling1, pathBit1);
        return current;
    }

    private BigInteger hashOrderedByPathBit(BigInteger current, BigInteger sibling, BigInteger pathBit) {
        if (BigInteger.ZERO.equals(pathBit)) {
            return signalMiMCOffCircuit(current, sibling);
        }
        return signalMiMCOffCircuit(sibling, current);
    }

    private BigInteger signalMiMCOffCircuit(BigInteger left, BigInteger right) {
        var circuit = CircuitBuilder.create("zk-mimc-oracle")
                .publicVar("hash")
                .secretVar("left")
                .secretVar("right")
                .defineSignals(c -> c.assertEqual(
                        SignalMiMC.hash(c, c.privateInput("left"), c.privateInput("right")),
                        c.publicInput("hash")));

        var noAssert = CircuitBuilder.create("zk-mimc-oracle-value")
                .secretVar("left")
                .secretVar("right")
                .defineSignals(c -> SignalMiMC.hash(c, c.privateInput("left"), c.privateInput("right")));

        var witness = noAssert.calculateWitness(Map.of(
                "left", List.of(left),
                "right", List.of(right)), CurveId.BN254);
        BigInteger hash = witness[witness.length - 1];
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "hash", List.of(hash),
                "left", List.of(left),
                "right", List.of(right)), CurveId.BN254));
        return hash;
    }

    private CircuitBuilder buildEddsaVerifyCircuit() {
        return CircuitBuilder.create("zk-eddsa-jubjub")
                .publicVar("pkU").publicVar("pkV")
                .publicVar("rU").publicVar("rV")
                .publicVar("msg").publicVar("s")
                .secretVar("kModL").secretVar("kQuotient")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var publicKey = ZkJubjubPoint.fromTrustedAffine(
                            zk,
                            ZkField.publicInput(c, "pkU"),
                            ZkField.publicInput(c, "pkV"));
                    var rPoint = ZkJubjubPoint.fromTrustedAffine(
                            zk,
                            ZkField.publicInput(c, "rU"),
                            ZkField.publicInput(c, "rV"));
                    ZkEdDSAJubjub.verify(
                            zk,
                            publicKey,
                            ZkField.publicInput(c, "msg"),
                            rPoint,
                            ZkUInt.publicInput(c, "s", 252),
                            ZkUInt.secret(c, "kModL", 252),
                            ZkUInt.secret(c, "kQuotient", 4));
                });
    }

    private Map<String, List<BigInteger>> eddsaWitness(
            EdDSAJubjub.Keypair keypair,
            EdDSAJubjub.Signature signature,
            BigInteger message) {
        var kReduction = ZkEdDSAJubjub.witnessComputeKReduction(signature.r(), keypair.pk(), message);
        return Map.of(
                "pkU", List.of(keypair.pk().affineU()),
                "pkV", List.of(keypair.pk().affineV()),
                "rU", List.of(signature.r().affineU()),
                "rV", List.of(signature.r().affineV()),
                "msg", List.of(message),
                "s", List.of(signature.s()),
                "kModL", List.of(kReduction.kModL()),
                "kQuotient", List.of(kReduction.kQuotient()));
    }

}
