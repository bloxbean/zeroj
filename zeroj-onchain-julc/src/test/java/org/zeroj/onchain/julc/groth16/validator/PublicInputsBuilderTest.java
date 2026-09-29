package org.zeroj.onchain.julc.groth16.validator;

import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.TxOutRef;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.TestDataBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Each {@code Groth16BLS12381Lib.publicInputsN} builds exactly N inputs, in order, when compiled
 * on-chain. Guards the ADR-0050 rename of the old overload set, which Julc pre16 compiled to the
 * 6-input body for every call.
 */
class PublicInputsBuilderTest extends ContractTest {

    private static Program program;

    @BeforeAll
    static void compile() {
        initCrypto();
        program = new PublicInputsBuilderTest()
                .compileValidator(PublicInputsBuilderProbe.class, Path.of("src/test/java")).program();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3, 4, 5, 6})
    void buildsTheInputsInOrder(int arity) {
        assertSuccess(evaluate(program, context(arity, expected(arity))));
    }

    @ParameterizedTest
    @ValueSource(ints = {2, 3, 4, 5, 6})
    void rejectsReorderedInputs(int arity) {
        List<PlutusData> reversed = new ArrayList<>(expected(arity));
        Collections.reverse(reversed);
        assertFailure(evaluate(program, context(arity, reversed)));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3, 4, 5})
    void rejectsAnInputListOfAnotherLength(int arity) {
        assertFailure(evaluate(program, context(arity, expected(arity + 1))));
    }

    private static List<PlutusData> expected(int arity) {
        List<PlutusData> inputs = new ArrayList<>();
        for (int i = 0; i < arity; i++) {
            inputs.add(PlutusData.integer(BigInteger.valueOf(10 + i)));
        }
        return inputs;
    }

    private PlutusData context(int arity, List<PlutusData> expectedInputs) {
        TxOutRef ref = TestDataBuilder.randomTxOutRef_typed();
        return spendingContext(ref, PlutusData.list(expectedInputs.toArray(PlutusData[]::new)))
                .redeemer(PlutusData.integer(BigInteger.valueOf(arity)))
                .buildPlutusData();
    }
}
