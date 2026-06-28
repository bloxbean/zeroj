package com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator;

import com.bloxbean.cardano.julc.core.Program;
import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.core.cbor.PlutusDataCborEncoder;
import com.bloxbean.cardano.julc.core.flat.UplcFlatEncoder;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKSetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano.MultiInputProofCompressed;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano.VkCompressed;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PlonkBLS12381MultiInputVerifierTest extends ContractTest {

    @Test
    void validatesBoundedPublicInputCounts() throws Exception {
        for (int count : List.of(1, 2, 4, 8)) {
            var fixture = fixture(count);
            var result = evaluate(fixture.program(), context(fixture, fixture.proof(), datum(fixture.publicInputs())));

            System.out.println("[test] PlonK BLS12-381 MPI verifier budget inputs=" + count
                    + ": " + result.budgetConsumed());
            assertSuccess(result);
            assertBudgetUnder(result, 5_800_000_000L, 1_700_000L);
        }
    }

    @Test
    void rejectsWrongPublicInputValue() throws Exception {
        var fixture = fixture(4);
        BigInteger[] publicInputs = fixture.publicInputs().clone();
        publicInputs[1] = publicInputs[1].add(BigInteger.ONE);

        var result = evaluate(fixture.program(), context(fixture, fixture.proof(), datum(publicInputs)));

        assertFailure(result);
    }

    @Test
    void rejectsSwappedPublicInputOrder() throws Exception {
        var fixture = fixture(4);
        BigInteger[] publicInputs = fixture.publicInputs().clone();
        BigInteger tmp = publicInputs[1];
        publicInputs[1] = publicInputs[2];
        publicInputs[2] = tmp;

        var result = evaluate(fixture.program(), context(fixture, fixture.proof(), datum(publicInputs)));

        assertFailure(result);
    }

    @Test
    void rejectsMissingPublicInput() throws Exception {
        var fixture = fixture(4);

        var result = evaluate(fixture.program(), context(fixture, fixture.proof(),
                PlutusData.list(PlutusData.integer(fixture.publicInputs()[0]),
                        PlutusData.integer(fixture.publicInputs()[1]),
                        PlutusData.integer(fixture.publicInputs()[2]))));

        assertFailure(result);
    }

    @Test
    void rejectsExtraPublicInput() throws Exception {
        var fixture = fixture(4);
        var result = evaluate(fixture.program(), context(fixture, fixture.proof(),
                PlutusData.list(PlutusData.integer(fixture.publicInputs()[0]),
                        PlutusData.integer(fixture.publicInputs()[1]),
                        PlutusData.integer(fixture.publicInputs()[2]),
                        PlutusData.integer(fixture.publicInputs()[3]),
                        PlutusData.integer(BigInteger.ONE))));

        assertFailure(result);
    }

    @Test
    void rejectsOverFieldPublicInput() throws Exception {
        var fixture = fixture(4);
        BigInteger[] publicInputs = fixture.publicInputs().clone();
        publicInputs[2] = fixture.vk().fr();

        var result = evaluate(fixture.program(), context(fixture, fixture.proof(), datum(publicInputs)));

        assertFailure(result);
    }

    @Test
    void rejectsMalformedInverseWitness() throws Exception {
        var fixture = fixture(4);
        BigInteger[] inverses = fixture.proof().publicInputInverses();
        inverses[1] = inverses[1].add(BigInteger.ONE).mod(fixture.vk().fr());
        var tampered = proofWithInverses(fixture.proof(), inverses);

        var result = evaluate(fixture.program(), context(fixture, tampered, datum(fixture.publicInputs())));

        assertFailure(result);
    }

    @Test
    void rejectsTamperedProofCommitment() throws Exception {
        var fixture = fixture(4);
        var tampered = new MultiInputProofCompressed(
                fixture.vk().g1Gen(),
                fixture.proof().cmB(),
                fixture.proof().cmC(),
                fixture.proof().cmZ(),
                fixture.proof().cmT1(),
                fixture.proof().cmT2(),
                fixture.proof().cmT3(),
                fixture.proof().wXi(),
                fixture.proof().wXiw(),
                fixture.proof().evalA(),
                fixture.proof().evalB(),
                fixture.proof().evalC(),
                fixture.proof().evalS1(),
                fixture.proof().evalS2(),
                fixture.proof().evalZw(),
                fixture.proof().publicInputInverses());

        var result = evaluate(fixture.program(), context(fixture, tampered, datum(fixture.publicInputs())));

        assertFailure(result);
    }

    @Test
    void appliedScriptDatumAndRedeemerStayWithinInlineSizeGate() throws Exception {
        var fixture = fixture(8);
        byte[] scriptFlat = UplcFlatEncoder.encodeProgram(fixture.program());
        byte[] datumCbor = PlutusDataCborEncoder.encode(datum(fixture.publicInputs()));
        byte[] redeemerCbor = PlutusDataCborEncoder.encode(redeemer(fixture.proof()));

        System.out.println("[test] PlonK BLS12-381 MPI applied script flat bytes: " + scriptFlat.length);
        System.out.println("[test] PlonK BLS12-381 MPI datum CBOR bytes: " + datumCbor.length);
        System.out.println("[test] PlonK BLS12-381 MPI redeemer CBOR bytes: " + redeemerCbor.length);

        assertTrue(scriptFlat.length <= 16_384,
                () -> "Applied PlonK MPI verifier script is " + scriptFlat.length
                        + " bytes; use CIP-33 reference-script packaging before deployment");
        assertTrue(datumCbor.length <= 16_384,
                () -> "PlonK MPI datum is " + datumCbor.length + " bytes and exceeds the inline data size limit");
        assertTrue(redeemerCbor.length <= 16_384,
                () -> "PlonK MPI proof redeemer is " + redeemerCbor.length
                        + " bytes and exceeds the inline data size limit");
    }

    private Fixture fixture(int publicInputCount) throws Exception {
        return fixture(publicInputCount, false, null);
    }

    @Test
    void paramVerifierValidatesScriptParameterPublicInputs() throws Exception {
        var fixture = paramFixture(4);
        var irrelevantDatum = PlutusData.list(PlutusData.integer(BigInteger.valueOf(999)));

        var result = evaluate(fixture.program(), context(fixture, fixture.proof(), irrelevantDatum));

        assertSuccess(result);
    }

    @Test
    void paramVerifierRejectsWrongScriptParameterPublicInputValue() throws Exception {
        var correct = fixture(4);
        BigInteger[] wrongScriptInputs = correct.publicInputs().clone();
        wrongScriptInputs[0] = wrongScriptInputs[0].add(BigInteger.ONE);
        var fixture = paramFixture(4, wrongScriptInputs);

        var result = evaluate(fixture.program(), context(fixture, fixture.proof(), PlutusData.list()));

        assertFailure(result);
    }

    @Test
    void paramVerifierRejectsEmptyScriptParameterPublicInputs() throws Exception {
        var fixture = paramFixture(1, new BigInteger[0]);

        var result = evaluate(fixture.program(), context(fixture, fixture.proof(), PlutusData.list()));

        assertFailure(result);
    }

    @Test
    void paramVerifierRejectsOverFieldScriptParameterPublicInput() throws Exception {
        var correct = fixture(4);
        BigInteger[] overFieldInputs = correct.publicInputs().clone();
        overFieldInputs[2] = correct.vk().fr();
        var fixture = paramFixture(4, overFieldInputs);

        var result = evaluate(fixture.program(), context(fixture, fixture.proof(), PlutusData.list()));

        assertFailure(result);
    }

    @Test
    void paramVerifierRejectsMoreThanEightScriptParameterPublicInputs() throws Exception {
        BigInteger[] tooMany = new BigInteger[9];
        for (int i = 0; i < tooMany.length; i++) {
            tooMany[i] = BigInteger.valueOf(i + 1L);
        }
        var fixture = paramFixture(8, tooMany);

        var result = evaluate(fixture.program(), context(fixture, fixture.proof(), PlutusData.list()));

        assertFailure(result);
    }

    @Test
    void paramVerifierAppliedScriptAndRedeemerStayWithinInlineSizeGate() throws Exception {
        var fixture = paramFixture(8);
        byte[] scriptFlat = UplcFlatEncoder.encodeProgram(fixture.program());
        byte[] redeemerCbor = PlutusDataCborEncoder.encode(redeemer(fixture.proof()));

        System.out.println("[test] PlonK BLS12-381 MPI param verifier applied script flat bytes: "
                + scriptFlat.length);
        System.out.println("[test] PlonK BLS12-381 MPI param verifier redeemer CBOR bytes: "
                + redeemerCbor.length);

        assertTrue(scriptFlat.length <= 16_384,
                () -> "Applied PlonK MPI param verifier script is " + scriptFlat.length
                        + " bytes; use CIP-33 reference-script packaging before deployment");
        assertTrue(redeemerCbor.length <= 16_384,
                () -> "PlonK MPI param verifier proof redeemer is " + redeemerCbor.length
                        + " bytes and exceeds the inline data size limit");
    }

    private Fixture paramFixture(int publicInputCount) throws Exception {
        return fixture(publicInputCount, true, null);
    }

    private Fixture paramFixture(int publicInputCount, BigInteger[] scriptPublicInputs) throws Exception {
        return fixture(publicInputCount, true, scriptPublicInputs);
    }

    private Fixture fixture(int publicInputCount, boolean scriptParameterInputs,
                            BigInteger[] scriptPublicInputsOverride) throws Exception {
        var circuit = circuit(publicInputCount);
        var plonk = circuit.compilePlonK(CurveId.BLS12_381);
        var witness = circuit.calculateWitness(witnessInputs(publicInputCount), CurveId.BLS12_381);

        var srs = PowersOfTauBLS381.generate(8);
        int numGates = plonk.numGates();
        BigInteger[][] gates = new BigInteger[numGates][5];
        for (int i = 0; i < numGates; i++) {
            var row = plonk.gateRows().get(i);
            gates[i] = new BigInteger[]{row.qL(), row.qR(), row.qO(), row.qM(), row.qC()};
        }

        var pk = PlonKSetupBLS381.setup(numGates, plonk.numPublicInputs(), gates,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), srs);

        var extWitness = plonk.extendWitness(witness);
        int n = pk.domainSize();
        MontFr381[] wireA = new MontFr381[n];
        MontFr381[] wireB = new MontFr381[n];
        MontFr381[] wireC = new MontFr381[n];
        for (int i = 0; i < n; i++) {
            if (i < numGates) {
                var row = plonk.gateRows().get(i);
                wireA[i] = MontFr381.fromBigInteger(extWitness[row.wireA()]);
                wireB[i] = MontFr381.fromBigInteger(extWitness[row.wireB()]);
                wireC[i] = MontFr381.fromBigInteger(extWitness[row.wireC()]);
            } else {
                wireA[i] = wireB[i] = wireC[i] = MontFr381.ZERO;
            }
        }

        BigInteger[] publicInputs = new BigInteger[plonk.numPublicInputs()];
        for (int i = 0; i < publicInputs.length; i++) {
            publicInputs[i] = witness[i + 1];
        }

        var rng = SecureRandom.getInstance("SHA1PRNG");
        rng.setSeed(new byte[]{0x4d, 0x50, 0x49, (byte) publicInputCount});
        var proof = PlonKProverBLS381.proveCardanoMpi(pk, wireA, wireB, wireC, publicInputs, rng);

        var compressedVk = PlonKProverToCardano.compressVk(pk);
        var compressedProof = PlonKProverToCardano.compressMpiProof(proof, pk, publicInputs);

        Program program;
        if (scriptParameterInputs) {
            var compiled = compileValidator(PlonkBLS12381MultiInputParamVerifier.class);
            BigInteger[] scriptPublicInputs = scriptPublicInputsOverride == null ? publicInputs : scriptPublicInputsOverride;
            program = applyParamInputParams(compiled.program(), compressedVk, scriptPublicInputs);
        } else {
            var compiled = compileValidator(PlonkBLS12381MultiInputVerifier.class);
            program = applyDatumInputParams(compiled.program(), compressedVk, publicInputCount);
        }

        return new Fixture(program, compressedVk, compressedProof, publicInputs);
    }

    private static Program applyDatumInputParams(Program program, VkCompressed compressedVk, int publicInputCount) {
        return program.applyParams(
                PlutusData.bytes(compressedVk.qm()),
                PlutusData.bytes(compressedVk.ql()),
                PlutusData.bytes(compressedVk.qr()),
                PlutusData.bytes(compressedVk.qo()),
                PlutusData.bytes(compressedVk.qc()),
                PlutusData.bytes(compressedVk.s1()),
                PlutusData.bytes(compressedVk.s2()),
                PlutusData.bytes(compressedVk.s3()),
                PlutusData.bytes(compressedVk.x2()),
                PlutusData.integer(compressedVk.domainSize()),
                PlutusData.integer(compressedVk.domainPower()),
                PlutusData.integer(compressedVk.omega()),
                PlutusData.integer(compressedVk.k1()),
                PlutusData.integer(compressedVk.k2()),
                PlutusData.integer(compressedVk.k1OverK2()),
                PlutusData.integer(compressedVk.fr()),
                PlutusData.integer(compressedVk.nInv()),
                PlutusData.bytes(compressedVk.g1Gen()),
                PlutusData.bytes(compressedVk.g2Gen()),
                PlutusData.bytes(PlonKProverToCardano.CARDANO_MPI_PROOF_FORMAT.getBytes(StandardCharsets.US_ASCII)),
                PlutusData.integer(publicInputCount));
    }

    private static Program applyParamInputParams(Program program, VkCompressed compressedVk, BigInteger[] publicInputs) {
        return program.applyParams(
                PlutusData.bytes(compressedVk.qm()),
                PlutusData.bytes(compressedVk.ql()),
                PlutusData.bytes(compressedVk.qr()),
                PlutusData.bytes(compressedVk.qo()),
                PlutusData.bytes(compressedVk.qc()),
                PlutusData.bytes(compressedVk.s1()),
                PlutusData.bytes(compressedVk.s2()),
                PlutusData.bytes(compressedVk.s3()),
                PlutusData.bytes(compressedVk.x2()),
                PlutusData.integer(compressedVk.domainSize()),
                PlutusData.integer(compressedVk.domainPower()),
                PlutusData.integer(compressedVk.omega()),
                PlutusData.integer(compressedVk.k1()),
                PlutusData.integer(compressedVk.k2()),
                PlutusData.integer(compressedVk.k1OverK2()),
                PlutusData.integer(compressedVk.fr()),
                PlutusData.integer(compressedVk.nInv()),
                PlutusData.bytes(compressedVk.g1Gen()),
                PlutusData.bytes(compressedVk.g2Gen()),
                PlutusData.bytes(PlonKProverToCardano.CARDANO_MPI_PROOF_FORMAT.getBytes(StandardCharsets.US_ASCII)),
                datum(publicInputs));
    }

    private static CircuitBuilder circuit(int publicInputCount) {
        var builder = CircuitBuilder.create("plonk-mpi-" + publicInputCount);
        for (int i = 0; i < publicInputCount; i++) {
            builder.publicVar("p" + i);
        }
        builder.secretVar("x");
        return builder.define(api -> {
            if (publicInputCount == 1) {
                api.assertEqual(api.var("x"), api.var("p0"));
            } else {
                var expr = api.mul(api.var("p0"), api.var("x"));
                for (int i = 1; i < publicInputCount - 1; i++) {
                    expr = api.add(expr, api.var("p" + i));
                }
                api.assertEqual(expr, api.var("p" + (publicInputCount - 1)));
            }
        });
    }

    private static Map<String, List<BigInteger>> witnessInputs(int publicInputCount) {
        Map<String, List<BigInteger>> inputs = new HashMap<>();
        BigInteger x = BigInteger.valueOf(7);
        inputs.put("x", List.of(x));
        if (publicInputCount == 1) {
            inputs.put("p0", List.of(x));
            return inputs;
        }

        BigInteger acc = BigInteger.valueOf(3).multiply(x);
        inputs.put("p0", List.of(BigInteger.valueOf(3)));
        for (int i = 1; i < publicInputCount - 1; i++) {
            BigInteger value = BigInteger.valueOf(i + 3L);
            inputs.put("p" + i, List.of(value));
            acc = acc.add(value);
        }
        inputs.put("p" + (publicInputCount - 1), List.of(acc));
        return inputs;
    }

    private PlutusData context(Fixture fixture, MultiInputProofCompressed proof, PlutusData datum) {
        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        return spendingContext(txOutRef, datum)
                .redeemer(redeemer(proof))
                .buildPlutusData();
    }

    private static PlutusData datum(BigInteger[] publicInputs) {
        PlutusData[] values = new PlutusData[publicInputs.length];
        for (int i = 0; i < publicInputs.length; i++) {
            values[i] = PlutusData.integer(publicInputs[i]);
        }
        return PlutusData.list(values);
    }

    private static PlutusData redeemer(MultiInputProofCompressed proof) {
        return PlutusData.constr(0,
                PlutusData.bytes(proof.cmA()),
                PlutusData.bytes(proof.cmB()),
                PlutusData.bytes(proof.cmC()),
                PlutusData.bytes(proof.cmZ()),
                PlutusData.bytes(proof.cmT1()),
                PlutusData.bytes(proof.cmT2()),
                PlutusData.bytes(proof.cmT3()),
                PlutusData.bytes(proof.wXi()),
                PlutusData.bytes(proof.wXiw()),
                PlutusData.integer(proof.evalA()),
                PlutusData.integer(proof.evalB()),
                PlutusData.integer(proof.evalC()),
                PlutusData.integer(proof.evalS1()),
                PlutusData.integer(proof.evalS2()),
                PlutusData.integer(proof.evalZw()),
                inverseDatum(proof.publicInputInverses()));
    }

    private static PlutusData inverseDatum(BigInteger[] inverses) {
        PlutusData[] values = new PlutusData[inverses.length];
        for (int i = 0; i < inverses.length; i++) {
            values[i] = PlutusData.integer(inverses[i]);
        }
        return PlutusData.list(values);
    }

    private static MultiInputProofCompressed proofWithInverses(MultiInputProofCompressed proof, BigInteger[] inverses) {
        return new MultiInputProofCompressed(
                proof.cmA(), proof.cmB(), proof.cmC(), proof.cmZ(),
                proof.cmT1(), proof.cmT2(), proof.cmT3(),
                proof.wXi(), proof.wXiw(),
                proof.evalA(), proof.evalB(), proof.evalC(),
                proof.evalS1(), proof.evalS2(), proof.evalZw(),
                inverses);
    }

    private record Fixture(
            Program program,
            VkCompressed vk,
            MultiInputProofCompressed proof,
            BigInteger[] publicInputs) {}
}
