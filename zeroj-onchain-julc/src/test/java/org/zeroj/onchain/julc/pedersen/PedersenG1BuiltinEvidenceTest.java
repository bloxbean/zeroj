package org.zeroj.onchain.julc.pedersen;

import org.julclang.compiler.CompileResult;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
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
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenBytesCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * ADR-0060 M4 builtin evidence and measurements ({@code pedersen-bls12-381-g1-v1} §9; registry spec
 * §15). The outcomes recorded here are builtin behaviour on inputs the CIPs leave unspecified; the
 * library never relies on them (its guards run first, {@link PedersenG1LibVmTest}). A change in any
 * pinned outcome means the Julc VM changed and must be re-checked on a node.
 *
 * <p>Budgets are measured under the Plutus V3 PV11 cost model shipped with the Julc VM and printed for
 * the measurements document; they are records, not checks (ADR-0060 I11).
 */
class PedersenG1BuiltinEvidenceTest extends ContractTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final BigInteger Q = G1Point.R;
    private static final String G_HEX =
            "80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e";
    private static final String H_HEX =
            "92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65";
    private static final G1Point G = Bls12381Codecs.g1FromCompressed(HEX.parseHex(G_HEX));
    private static final G1Point H = Bls12381Codecs.g1FromCompressed(HEX.parseHex(H_HEX));
    private static final G1Pedersen PEDERSEN = G1Pedersen.pureJava();
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Maximum transaction execution units and size of the DevKit and mainnet PV11 parameters. */
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

    @Test
    @DisplayName("Evidence: what bls12_381_G1_uncompress accepts")
    void uncompressEvidence() {
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put("identity c0‖0^47", "c0" + "00".repeat(47));
        cases.put("infinity with sort flag e0‖0^47", "e0" + "00".repeat(47));
        cases.put("infinity with coordinate bit", "c0" + "00".repeat(46) + "01");
        cases.put("uncompressed-flag infinity 40‖0^47", "40" + "00".repeat(47));
        cases.put("x = 0 (order 3)", "80" + "00".repeat(47));
        cases.put("x = 0, sort flag (order 3)", "a0" + "00".repeat(47));
        cases.put("x = 1 (not on curve)", "80" + "00".repeat(46) + "01");
        cases.put("x = 4 (on curve, not in G1)", "80" + "00".repeat(46) + "04");
        cases.put("G + (0,2) mixed order",
                "b6ee2defa35097e6bbaea5ab251479b37157dedfcbc4b319181bf28298f048a66eb93dc0230190c18ae135644c2d3df4");
        cases.put("x = P_381", "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
        cases.put("G with compression flag clear", "00" + G_HEX.substring(2));
        cases.put("G with sort flag flipped (−G)", flipSort(G_HEX));
        cases.put("47 octets", "80" + "00".repeat(46));
        cases.put("49 octets (G ‖ 00)", G_HEX + "00");
        cases.put("G", G_HEX);
        for (var e : cases.entrySet()) {
            byte[] encoded = HEX.parseHex(e.getValue());
            boolean exact = isSuccess(run(G1UncompressEvidenceProbe.class, PlutusData.bytes(encoded), bool(true)));
            boolean differs = isSuccess(run(G1UncompressEvidenceProbe.class, PlutusData.bytes(encoded), bool(false)));
            String outcome = exact ? "accepted, re-encodes exactly" : differs ? "accepted, re-encodes differently" : "rejected";
            System.out.println("[evidence] uncompress " + e.getKey() + ": " + outcome);
            boolean accepted = e.getKey().startsWith("identity") || e.getKey().startsWith("G with sort flag")
                    || e.getKey().equals("G");
            // Every accepted encoding re-encodes exactly; everything else, including every spec §10.4
            // negative, is rejected. The library does not rely on this (it checks length and round trip).
            assertEquals(accepted ? "accepted, re-encodes exactly" : "rejected", outcome, e.getKey());
        }
    }

    @Test
    @DisplayName("Evidence: bls12_381_G1_scalarMul on integers outside [0, q)")
    void scalarMulEvidence() {
        BigInteger[] scalars = {BigInteger.ONE.negate(), Q, Q.add(BigInteger.ONE), Q.negate().subtract(BigInteger.ONE),
                BigInteger.ONE.shiftLeft(256), BigInteger.ONE.shiftLeft(4096), BigInteger.ONE.shiftLeft(4096).negate()};
        for (BigInteger s : scalars) {
            byte[] reduced = Bls12381Codecs.g1ToCompressed(G.scalarMul(s.mod(Q)));
            EvalResult r = run(G1ScalarMulEvidenceProbe.class, PlutusData.integer(s), PlutusData.bytes(reduced));
            System.out.println("[evidence] scalarMul(" + label(s) + ", G): "
                    + (r.isSuccess() ? "equals [s mod q]G" : "fails or differs") + ", budget " + r.budgetConsumed());
            // Observed: integers up to 2^256 in magnitude are reduced mod q; 2^4096 fails the script.
            // The library never passes such a scalar (check 1 and the delta rule run first).
            assertEquals(s.abs().bitLength() <= 257, r.isSuccess(), label(s));
        }
    }

    @Test
    @DisplayName("Evidence: bls12_381_G1_multiScalarMul on empty and unequal lists")
    void msmEvidence() {
        byte[] identity = HEX.parseHex("c0" + "00".repeat(47));
        BigInteger two = BigInteger.TWO;
        BigInteger three = BigInteger.valueOf(3);
        Map<String, Object[]> cases = new LinkedHashMap<>();
        cases.put("empty, empty → identity", new Object[] {List.of(), List.<byte[]>of(), identity});
        cases.put("[2], [] → identity", new Object[] {List.of(two), List.<byte[]>of(), identity});
        cases.put("[], [G] → identity", new Object[] {List.of(), List.of(HEX.parseHex(G_HEX)), identity});
        cases.put("[2, 3], [G] → [2]G (truncated)", new Object[] {List.of(two, three), List.of(HEX.parseHex(G_HEX)),
                Bls12381Codecs.g1ToCompressed(G.scalarMul(two))});
        cases.put("[2], [G, H] → [2]G (truncated)", new Object[] {List.of(two), List.of(HEX.parseHex(G_HEX), HEX.parseHex(H_HEX)),
                Bls12381Codecs.g1ToCompressed(G.scalarMul(two))});
        cases.put("[2, 3], [G, H] → [2]G + [3]H", new Object[] {List.of(two, three), List.of(HEX.parseHex(G_HEX), HEX.parseHex(H_HEX)),
                Bls12381Codecs.g1ToCompressed(G.scalarMul(two).add(H.scalarMul(three)))});
        for (var e : cases.entrySet()) {
            @SuppressWarnings("unchecked") List<BigInteger> s = (List<BigInteger>) e.getValue()[0];
            @SuppressWarnings("unchecked") List<byte[]> p = (List<byte[]>) e.getValue()[1];
            EvalResult r = run(G1MsmEvidenceProbe.class,
                    PlutusData.list(s.stream().map(PlutusData::integer).toArray(PlutusData[]::new)),
                    PlutusData.list(p.stream().map(PlutusData::bytes).toArray(PlutusData[]::new)),
                    PlutusData.bytes((byte[]) e.getValue()[2]));
            System.out.println("[evidence] MSM " + e.getKey() + ": " + (r.isSuccess() ? "yes" : "no (fails or differs)"));
            // Observed: empty lists give the identity and unequal lists are truncated to the shorter.
            // The library uses no MSM (two scalarMul are cheaper, msmVersusScalarMul).
            assertEquals(true, r.isSuccess(), e.getKey());
        }
    }

    @Test
    @DisplayName("Measurement: two scalarMul against one two-term MSM for a scalar opening (PV11)")
    void msmVersusScalarMul() {
        BigInteger m = G1Pedersen.randomBlinding(RANDOM);
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenCommitment c = PEDERSEN.commitScalar(m, r);
        EvalResult two = run(PedersenG1OpeningProbe.class, PlutusData.bytes(c.toPointBytes()),
                PlutusData.integer(m), PlutusData.integer(r), bool(false), PlutusData.integer(BigInteger.ZERO));
        EvalResult msm = run(PedersenG1MsmOpeningProbe.class, PlutusData.bytes(c.toPointBytes()),
                PlutusData.integer(m), PlutusData.integer(r));
        System.out.println("[measure] scalar opening, two scalarMul: " + describe(two.budgetConsumed()));
        System.out.println("[measure] scalar opening, one MSM:       " + describe(msm.budgetConsumed()));
        assertEquals(true, two.isSuccess());
        assertEquals(true, msm.isSuccess());
        // Positive controls for the marked counts: each variant runs exactly what it says.
        PlutusData ctxTwo = context(PlutusData.bytes(c.toPointBytes()), PlutusData.integer(m), PlutusData.integer(r),
                bool(false), PlutusData.integer(BigInteger.ZERO));
        assertEquals(new MarkedBuiltinCounts.Counts(3, 2, 0),
                MarkedBuiltinCounts.count(compiled(PedersenG1OpeningProbe.class), ctxTwo, true));
        PlutusData ctxMsm = context(PlutusData.bytes(c.toPointBytes()), PlutusData.integer(m), PlutusData.integer(r));
        assertEquals(new MarkedBuiltinCounts.Counts(3, 0, 1),
                MarkedBuiltinCounts.count(compiled(PedersenG1MsmOpeningProbe.class), ctxMsm, true));
        // A record, not a gate (I11): the library's choice of two scalarMul rests on this comparison.
        System.out.println("[measure] MSM minus two scalarMul: "
                + (msm.budgetConsumed().cpuSteps() - two.budgetConsumed().cpuSteps()) + " cpu");
    }

    @Test
    @DisplayName("Measurement: byte-opening cost by payload size (PV11)")
    void payloadSizes() {
        for (int n : new int[] {0, 32, 256, 1024, 4096, 8192, 12288, 15360, 16384, 32768}) {
            byte[] payload = new byte[n];
            RANDOM.nextBytes(payload);
            BigInteger blinding = G1Pedersen.randomBlinding(RANDOM);
            G1PedersenBytesCommitment c = PEDERSEN.commitBytes(payload, blinding);
            EvalResult ok = run(PedersenG1BytesProbe.class, PlutusData.bytes(c.toPointBytes()),
                    PlutusData.bytes(payload), PlutusData.integer(blinding));
            assertEquals(true, ok.isSuccess(), "n = " + n);
            System.out.println("[measure] bytes opening n=" + n + ": " + describe(ok.budgetConsumed()));
        }
    }

    @Test
    @DisplayName("Measurement: strict decode alone, and a two-term sum (PV11)")
    void decodeAndSum() {
        G1PedersenCommitment a = PEDERSEN.commitScalar(G1Pedersen.randomBlinding(RANDOM), G1Pedersen.randomBlinding(RANDOM));
        G1PedersenCommitment b = PEDERSEN.commitScalar(G1Pedersen.randomBlinding(RANDOM), G1Pedersen.randomBlinding(RANDOM));
        EvalResult decode = run(PedersenG1DecodeProbe.class, PlutusData.bytes(a.toPointBytes()));
        EvalResult sum = run(PedersenG1SumProbe.class, PlutusData.bytes(a.toPointBytes()), PlutusData.bytes(b.toPointBytes()),
                PlutusData.integer(BigInteger.ZERO), PlutusData.bytes(a.add(b).toPointBytes()));
        assertEquals(true, decode.isSuccess());
        assertEquals(true, sum.isSuccess());
        System.out.println("[measure] strict decode + re-encode: " + describe(decode.budgetConsumed()));
        System.out.println("[measure] two decodes + add + compress/compare: " + describe(sum.budgetConsumed()));
    }

    // ------------------------------------------------------------------ helpers

    private EvalResult run(Class<?> probe, PlutusData... fields) {
        CompileResult result = compiled(probe);
        Program program = result.program();
        return PV11.evaluateWithArgs(program, result.target().ledgerTarget(), List.of(context(fields)), null,
                EvalOptions.DEFAULT);
    }

    private CompileResult compiled(Class<?> probe) {
        return compiled.computeIfAbsent(probe, p -> compileValidator(p, Path.of("src/test/java")));
    }

    private PlutusData context(PlutusData... fields) {
        return spendingContext(TestDataBuilder.randomTxOutRef_typed(), PlutusData.integer(0))
                .redeemer(PlutusData.constr(0, fields)).buildPlutusData();
    }

    private static boolean isSuccess(EvalResult r) {
        return r instanceof EvalResult.Success;
    }

    private static PlutusData bool(boolean b) {
        return PlutusData.constr(b ? 1 : 0);
    }

    private static String describe(ExBudget b) {
        return String.format("cpu %,d (%.2f%% of max tx), mem %,d (%.2f%% of max tx)", b.cpuSteps(),
                100.0 * b.cpuSteps() / MAX_TX_CPU, b.memoryUnits(), 100.0 * b.memoryUnits() / MAX_TX_MEM);
    }

    private static String label(BigInteger s) {
        if (s.equals(Q)) return "q";
        if (s.equals(Q.add(BigInteger.ONE))) return "q + 1";
        if (s.equals(Q.negate().subtract(BigInteger.ONE))) return "−q − 1";
        if (s.abs().bitCount() == 1 && s.abs().bitLength() > 64) {
            return (s.signum() < 0 ? "−" : "") + "2^" + (s.abs().bitLength() - 1);
        }
        return s.toString();
    }

    private static String flipSort(String hex) {
        byte[] b = HEX.parseHex(hex);
        b[0] ^= 0x20;
        return HEX.formatHex(b);
    }
}
