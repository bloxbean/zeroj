package org.zeroj.onchain.julc.bulletproofs;

import org.julclang.compiler.CompileResult;
import org.julclang.core.PlutusData;
import org.julclang.core.flat.UplcFlatEncoder;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.TestDataBuilder;
import org.julclang.vm.EvalOptions;
import org.julclang.vm.EvalResult;
import org.julclang.vm.ExBudget;
import org.julclang.vm.JulcVm;
import org.julclang.vm.PlutusLanguage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zeroj.bls12381.bulletproofs.BulletproofTestSupport;
import org.zeroj.bls12381.bulletproofs.G1RangeProver;
import org.zeroj.bls12381.bulletproofs.TestNonceProver;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 M4 (D8): the Cardano cost study of the {@code bulletproof-range-bls12-381-g1-v1} verifier
 * algebra under the Plutus V3 PV11 cost model in the Julc VM. <b>Not a verifier</b>: the probe takes
 * the transcript challenges as inputs ({@link BulletproofAlgebraCostProbe}). Budgets are records,
 * not checks (ADR-0061 I11), printed for {@code docs/benchmarks/bulletproof-range-g1-*.md}.
 */
class BulletproofAlgebraCostTest extends ContractTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] CTX = "https://example.com/zeroj/cost-study/v1".getBytes(StandardCharsets.US_ASCII);
    private static final BigInteger Q = new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final byte[] DST_BP =
            "ZeroJ-bulletproof-bls12-381-g1-gens-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_".getBytes(StandardCharsets.US_ASCII);
    private static final long MAX_TX_CPU = 10_000_000_000L;
    private static final long MAX_TX_MEM = 16_500_000L;
    private static final JulcVm PV11 = JulcVm.create();
    private final Map<Class<?>, CompileResult> compiled = new HashMap<>();

    @BeforeAll
    static void costModel() throws IOException {
        long[] costs;
        try (InputStream in = JulcVm.class.getResourceAsStream("/cost-model/plutus-v3-pv11-costs-v1.params")) {
            assertNotNull(in, "PV11 cost-model parameters");
            costs = new String(in.readAllBytes(), StandardCharsets.UTF_8).lines()
                    .filter(line -> !line.isBlank() && !line.startsWith("#"))
                    .mapToLong(Long::parseLong).toArray();
        }
        assertEquals(350, costs.length);
        PV11.setCostModelParams(costs, PlutusLanguage.PLUTUS_V3, 11, 0);
    }

    @ParameterizedTest(name = "n = {0}")
    @ValueSource(ints = {16, 32, 64})
    @DisplayName("Measurement: the verifier algebra (challenges supplied) for an honest proof; a tampered proof fails")
    void algebraCost(int bits) throws Exception {
        BigInteger v = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.valueOf(7));
        BigInteger gamma = BigInteger.valueOf(0x5EED);
        byte[] commitment = G1Pedersen.pureJava().commitScalar(v, gamma).toPointBytes();
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) (0x40 + bits));
        byte[] proof = TestNonceProver.prove(G1RangeProver.pureJava(), G1PedersenOpening.of(v, gamma), bits, CTX, seed).toBytes();

        EvalResult ok = run(BulletproofAlgebraCostProbe.class, redeemer(commitment, proof, bits));
        assertTrue(ok.isSuccess(), "honest proof, n = " + bits + ": " + ok);
        byte[] bad = proof.clone();
        int aOffset = bad.length - 64;
        BigInteger a = new BigInteger(1, bad, aOffset, 32).add(BigInteger.ONE).mod(Q);
        System.arraycopy(be32(a), 0, bad, aOffset, 32);
        EvalResult rejected = run(BulletproofAlgebraCostProbe.class, redeemer(commitment, bad, bits));
        assertTrue(!rejected.isSuccess(), "tampered a must fail, n = " + bits);

        int scriptBytes = UplcFlatEncoder.encodeProgram(compiled(BulletproofAlgebraCostProbe.class).program()).length;
        System.out.println("[measure] bulletproof algebra n=" + bits + " (challenges supplied, NOT a verifier): "
                + describe(ok.budgetConsumed()) + ", script " + scriptBytes + " octets (flat); the redeemer carries "
                + (2 * bits + 1) + " generator encodings (" + 48 * (2 * bits + 1) + " octets) and the "
                + proof.length + "-octet proof");
    }

    @Test
    @DisplayName("I1: the Julc VM's hashToGroup reproduces all 129 pinned generators (in batches of 16)")
    void generatorsOnChain() {
        List<String> all = new ArrayList<>(BulletproofTestSupport.generatorsHex(64));
        assertEquals(129, all.size());
        long cpu = 0;
        long mem = 0;
        for (int from = 0; from < all.size(); from += 16) {
            int to = Math.min(all.size(), from + 16);
            List<PlutusData> messages = new ArrayList<>();
            List<PlutusData> expected = new ArrayList<>();
            for (int i = from; i < to; i++) {
                messages.add(PlutusData.bytes(message(i)));
                expected.add(PlutusData.bytes(HEX.parseHex(all.get(i))));
            }
            EvalResult r = run(BulletproofGeneratorsProbe.class, PlutusData.bytes(DST_BP), PlutusData.list(messages.toArray(new PlutusData[0])),
                    PlutusData.list(expected.toArray(new PlutusData[0])));
            assertTrue(r.isSuccess(), "batch from " + from + ": " + r);
            cpu += r.budgetConsumed().cpuSteps();
            mem += r.budgetConsumed().memoryUnits();
        }
        // A wrong tag must not reproduce them.
        byte[] wrong = DST_BP.clone();
        wrong[0] ^= 1;
        EvalResult r = run(BulletproofGeneratorsProbe.class, PlutusData.bytes(wrong),
                PlutusData.list(PlutusData.bytes(message(0))), PlutusData.list(PlutusData.bytes(HEX.parseHex(all.get(0)))));
        assertTrue(!r.isSuccess());
        System.out.println("[measure] hashToGroup of all 129 generators (9 evaluations): cpu " + cpu + ", mem " + mem);
    }

    /** "G" ‖ I2OSP(i, 4) for i < 64, "H" ‖ I2OSP(i − 64, 4), then "U" (spec §2.1). */
    private static byte[] message(int index) {
        if (index == 128) {
            return new byte[] {'U'};
        }
        int i = index % 64;
        return new byte[] {(byte) (index < 64 ? 'G' : 'H'), (byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i};
    }

    private static PlutusData[] redeemer(byte[] commitment, byte[] proof, int bits) throws Exception {
        int k = Integer.numberOfTrailingZeros(bits);
        BulletproofTestSupport.Challenges ch = BulletproofTestSupport.challenges(commitment, proof, bits, CTX);
        List<PlutusData> xj = new ArrayList<>();
        List<PlutusData> xjInv = new ArrayList<>();
        for (BigInteger x : ch.xj()) {
            xj.add(PlutusData.integer(x));
            xjInv.add(PlutusData.integer(x.modInverse(Q)));
        }
        List<PlutusData> ls = new ArrayList<>();
        List<PlutusData> rs = new ArrayList<>();
        for (int j = 0; j < k; j++) {
            ls.add(PlutusData.bytes(Arrays.copyOfRange(proof, 288 + 96 * j, 336 + 96 * j)));
            rs.add(PlutusData.bytes(Arrays.copyOfRange(proof, 336 + 96 * j, 384 + 96 * j)));
        }
        List<PlutusData> gens = new ArrayList<>();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        for (String g : BulletproofTestSupport.generatorsHex(bits)) {
            gens.add(PlutusData.bytes(HEX.parseHex(g)));
            sha.update(HEX.parseHex(g));
        }
        int end = proof.length;
        return new PlutusData[] {
                PlutusData.integer(bits), PlutusData.integer(ch.y()), PlutusData.integer(ch.y().modInverse(Q)),
                PlutusData.integer(ch.z()), PlutusData.integer(ch.x()), PlutusData.integer(ch.xu()),
                PlutusData.list(xj.toArray(new PlutusData[0])), PlutusData.list(xjInv.toArray(new PlutusData[0])),
                PlutusData.integer(scalar(proof, 192)), PlutusData.integer(scalar(proof, 224)), PlutusData.integer(scalar(proof, 256)),
                PlutusData.integer(scalar(proof, end - 64)), PlutusData.integer(scalar(proof, end - 32)),
                PlutusData.bytes(commitment), PlutusData.bytes(Arrays.copyOfRange(proof, 0, 48)),
                PlutusData.bytes(Arrays.copyOfRange(proof, 48, 96)), PlutusData.bytes(Arrays.copyOfRange(proof, 96, 144)),
                PlutusData.bytes(Arrays.copyOfRange(proof, 144, 192)), PlutusData.list(ls.toArray(new PlutusData[0])), PlutusData.list(rs.toArray(new PlutusData[0])),
                PlutusData.list(gens.toArray(new PlutusData[0])), PlutusData.bytes(sha.digest())};
    }

    private static BigInteger scalar(byte[] proof, int offset) {
        return new BigInteger(1, proof, offset, 32);
    }

    private static byte[] be32(BigInteger x) {
        byte[] raw = x.toByteArray();
        byte[] out = new byte[32];
        int skip = raw.length > 32 ? raw.length - 32 : 0;
        System.arraycopy(raw, skip, out, 32 - (raw.length - skip), raw.length - skip);
        return out;
    }

    private EvalResult run(Class<?> probe, PlutusData... fields) {
        CompileResult result = compiled(probe);
        return PV11.evaluateWithArgs(result.program(), result.target().ledgerTarget(), List.of(context(fields)), null,
                EvalOptions.DEFAULT);
    }

    private CompileResult compiled(Class<?> probe) {
        return compiled.computeIfAbsent(probe, p -> compileValidator(p, Path.of("src/test/java")));
    }

    private PlutusData context(PlutusData... fields) {
        return spendingContext(TestDataBuilder.randomTxOutRef_typed(), PlutusData.integer(0))
                .redeemer(PlutusData.constr(0, fields)).buildPlutusData();
    }

    private static String describe(ExBudget b) {
        return String.format("cpu %,d (%.2f%% of max tx), mem %,d (%.2f%% of max tx)", b.cpuSteps(),
                100.0 * b.cpuSteps() / MAX_TX_CPU, b.memoryUnits(), 100.0 * b.memoryUnits() / MAX_TX_MEM);
    }
}
