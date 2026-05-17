package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMiMC;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;
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

}
