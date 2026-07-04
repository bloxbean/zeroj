package com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator;

import com.bloxbean.cardano.julc.core.Program;
import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.core.cbor.PlutusDataCborEncoder;
import com.bloxbean.cardano.julc.core.flat.UplcFlatEncoder;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKSetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano.ProofCompressed;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano.VkCompressed;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PlonkBLS12381VerifierTest extends ContractTest {

    @Test
    void validatesJavaGeneratedCardanoProfileProof() throws Exception {
        var fixture = fixture();
        var result = evaluate(fixture.program(), context(fixture, fixture.proof(), PlutusData.list(PlutusData.integer(33))));

        System.out.println("[test] PlonK BLS12-381 production verifier budget: " + result.budgetConsumed());
        assertSuccess(result);
        assertBudgetUnder(result, 5_500_000_000L, 1_500_000L);
    }

    @Test
    void rejectsWrongPublicInput() throws Exception {
        var fixture = fixture();
        var wrongDatum = PlutusData.list(PlutusData.integer(34));

        var result = evaluate(fixture.program(), context(fixture, fixture.proof(), wrongDatum));

        assertFailure(result);
    }

    @Test
    void rejectsExtraPublicInput() throws Exception {
        var fixture = fixture();
        var extraDatum = PlutusData.list(PlutusData.integer(33), PlutusData.integer(1));

        var result = evaluate(fixture.program(), context(fixture, fixture.proof(), extraDatum));

        assertFailure(result);
    }

    @Test
    void rejectsTamperedProofCommitment() throws Exception {
        var fixture = fixture();
        var tampered = new ProofCompressed(
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
                fixture.proof().xiMinusOneInv(),
                fixture.proof().xiMinusOmegaInv());

        var result = evaluate(fixture.program(), context(fixture, tampered, PlutusData.list(PlutusData.integer(33))));

        assertFailure(result);
    }

    @Test
    void rejectsOverFieldEvaluationScalar() throws Exception {
        var fixture = fixture();
        var tampered = new ProofCompressed(
                fixture.proof().cmA(),
                fixture.proof().cmB(),
                fixture.proof().cmC(),
                fixture.proof().cmZ(),
                fixture.proof().cmT1(),
                fixture.proof().cmT2(),
                fixture.proof().cmT3(),
                fixture.proof().wXi(),
                fixture.proof().wXiw(),
                fixture.vk().fr(),
                fixture.proof().evalB(),
                fixture.proof().evalC(),
                fixture.proof().evalS1(),
                fixture.proof().evalS2(),
                fixture.proof().evalZw(),
                fixture.proof().xiMinusOneInv(),
                fixture.proof().xiMinusOmegaInv());

        var result = evaluate(fixture.program(), context(fixture, tampered, PlutusData.list(PlutusData.integer(33))));

        assertFailure(result);
    }

    @Test
    void rejectsWrongProtocolFrParameter() throws Exception {
        var fixture = fixture();
        var tamperedVk = vkWithProtocolParams(fixture.vk(),
                fixture.vk().fr().subtract(BigInteger.ONE),
                fixture.vk().g1Gen(),
                fixture.vk().g2Gen());
        var tamperedProgram = program(tamperedVk);

        var result = evaluate(tamperedProgram,
                context(fixture, fixture.proof(), PlutusData.list(PlutusData.integer(33))));

        assertFailure(result);
    }

    @Test
    void rejectsWrongProtocolG1GeneratorParameter() throws Exception {
        var fixture = fixture();
        byte[] wrongG1 = fixture.vk().g1Gen().clone();
        wrongG1[wrongG1.length - 1] ^= 1;
        var tamperedVk = vkWithProtocolParams(fixture.vk(),
                fixture.vk().fr(),
                wrongG1,
                fixture.vk().g2Gen());
        var tamperedProgram = program(tamperedVk);

        var result = evaluate(tamperedProgram,
                context(fixture, fixture.proof(), PlutusData.list(PlutusData.integer(33))));

        assertFailure(result);
    }

    @Test
    void rejectsWrongProtocolG2GeneratorParameter() throws Exception {
        var fixture = fixture();
        byte[] wrongG2 = fixture.vk().g2Gen().clone();
        wrongG2[wrongG2.length - 1] ^= 1;
        var tamperedVk = vkWithProtocolParams(fixture.vk(),
                fixture.vk().fr(),
                fixture.vk().g1Gen(),
                wrongG2);
        var tamperedProgram = program(tamperedVk);

        var result = evaluate(tamperedProgram,
                context(fixture, fixture.proof(), PlutusData.list(PlutusData.integer(33))));

        assertFailure(result);
    }

    @Test
    void appliedScriptAndRedeemerStayWithinInlineSizeGate() throws Exception {
        var fixture = fixture();
        byte[] scriptFlat = UplcFlatEncoder.encodeProgram(fixture.program());
        byte[] redeemerCbor = PlutusDataCborEncoder.encode(redeemer(fixture.proof()));

        System.out.println("[test] PlonK BLS12-381 applied script flat bytes: " + scriptFlat.length);
        System.out.println("[test] PlonK BLS12-381 redeemer CBOR bytes: " + redeemerCbor.length);

        assertTrue(scriptFlat.length <= 16_384,
                () -> "Applied PlonK verifier script is " + scriptFlat.length
                        + " bytes; use CIP-33 reference-script packaging before deployment");
        assertTrue(redeemerCbor.length <= 16_384,
                () -> "PlonK proof redeemer is " + redeemerCbor.length
                        + " bytes and exceeds the inline data size limit");
    }

    private Fixture fixture() throws Exception {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("c")));

        var plonk = circuit.compilePlonK(CurveId.BLS12_381);
        var witness = circuit.calculateWitness(Map.of(
                "c", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BLS12_381);

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
        rng.setSeed(new byte[]{0x50, 0x4c, 0x4f, 0x4e, 0x4b});
        var proof = PlonKProverBLS381.proveCardano(pk, wireA, wireB, wireC, publicInputs, rng);

        var compressedVk = PlonKProverToCardano.compressVk(pk);
        var compressedProof = PlonKProverToCardano.compressProof(proof, pk, publicInputs);

        var program = program(compressedVk);

        return new Fixture(program, compressedVk, compressedProof);
    }

    private Program program(VkCompressed compressedVk) {
        var compiled = compileValidator(PlonkBLS12381Verifier.class);
        return compiled.program().applyParams(
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
                PlutusData.bytes(compressedVk.g2Gen()));
    }

    private static VkCompressed vkWithProtocolParams(VkCompressed vk, BigInteger fr, byte[] g1Gen, byte[] g2Gen) {
        return new VkCompressed(
                vk.qm(), vk.ql(), vk.qr(), vk.qo(), vk.qc(),
                vk.s1(), vk.s2(), vk.s3(), vk.x2(),
                vk.domainSize(), vk.domainPower(), vk.omega(),
                vk.k1(), vk.k2(), vk.k1OverK2(),
                fr, vk.nInv(), g1Gen, g2Gen);
    }

    private PlutusData context(Fixture fixture, ProofCompressed proof, PlutusData datum) {
        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        return spendingContext(txOutRef, datum)
                .redeemer(redeemer(proof))
                .buildPlutusData();
    }

    private static PlutusData redeemer(ProofCompressed proof) {
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
                PlutusData.integer(proof.xiMinusOneInv()),
                PlutusData.integer(proof.xiMinusOmegaInv()));
    }

    private record Fixture(Program program, VkCompressed vk, ProofCompressed proof) {}
}
