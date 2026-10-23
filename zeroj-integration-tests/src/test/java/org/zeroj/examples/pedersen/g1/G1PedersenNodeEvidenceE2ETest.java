package org.zeroj.examples.pedersen.g1;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.ScriptSupplier;
import com.bloxbean.cardano.client.api.TransactionEvaluator;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.EvaluationResult;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.api.DefaultProtocolParamsSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultScriptSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.exception.CborDeserializationException;
import com.bloxbean.cardano.client.exception.CborSerializationException;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ExUnits;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.plutus.spec.Redeemer;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.client.transaction.spec.Transaction;
import com.bloxbean.cardano.client.transaction.spec.TransactionInput;
import org.julclang.clientlib.JulcScriptLoader;
import org.julclang.clientlib.eval.JulcTransactionEvaluator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenBytesCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;
import org.zeroj.examples.dsl.common.YaciHelper;
import org.zeroj.examples.pedersen.g1.onchain.G1BasesNodeProbe;
import org.zeroj.examples.pedersen.g1.onchain.G1BytesOpeningValidator;
import org.zeroj.examples.pedersen.g1.onchain.G1DecodeNodeProbe;
import org.zeroj.examples.pedersen.g1.onchain.G1MsmNodeProbe;
import org.zeroj.examples.pedersen.g1.onchain.G1ScalarMulNodeProbe;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ADR-0060 M4 node evidence on Yaci DevKit for the {@code pedersen-bls12-381-g1} on-chain library.
 * Each group records what a real Cardano node does and compares it with the Julc VM.
 *
 * <ol>
 *   <li><b>Strict decoding, node parity (I10).</b> {@link G1DecodeNodeProbe} accepts iff
 *       {@code PedersenG1Lib.decodeCommitment} succeeds and re-encodes exactly. For every encoding
 *       (the identity, {@code G}, {@code −G}, and every spec §10.4 negative), a spend carrying it is
 *       submitted to the node with a fixed budget, so the node evaluates the script even when it
 *       fails. On the same transaction, the Julc VM verdict is recorded ({@link JulcTransactionEvaluator}).
 *       The expected verdict is the spec §10.4 outcome (from the independent Python reference); the
 *       off-chain Java strict decoder is a third column. All four must agree, and for each rejection
 *       the node and the VM must name the same failure point (the library's length guard, or
 *       {@code bls12_381_G1_uncompress} itself). That failure point is recorded builtin behaviour;
 *       the library does not rely on it (its round-trip check stands behind {@code uncompress}).</li>
 *   <li><b>Bases on the node (I1).</b> {@link G1BasesNodeProbe} recomputes {@code G} and {@code H}
 *       with {@code bls12_381_G1_hashToGroup} under {@code DST_B} and compares them with the pinned
 *       constants. Accepted with {@code DST_B}; a one-bit-different DST is rejected by the node.</li>
 *   <li><b>scalarMul and MSM edge cases, node parity (D9).</b> {@link G1ScalarMulNodeProbe} compares
 *       {@code compress(bls12_381_G1_scalarMul(s, G))} with {@code compress([s mod q]G)} computed
 *       off-chain, for {@code s} in {−1, q, q + 1, −q − 1, 2^256, 2^4096, −2^4096};
 *       {@link G1MsmNodeProbe} compares {@code compress(bls12_381_G1_multiScalarMul(scalars, points))}
 *       with the identity or the truncated sum, for empty and unequal lists. Each case is a fixed-budget
 *       spend on the node, with the Julc VM verdict on the same transaction; script failure is told apart
 *       from a budget overrun and from any other (transaction-validation) rejection, and the node must
 *       agree with the VM case by case. The library relies on none of these outcomes.</li>
 *   <li><b>Payload limit of a byte opening.</b> With {@link G1BytesOpeningValidator}, the largest
 *       payload {@code n} an honest opening transaction can carry is found by binary search, each step
 *       a real lock and spend on the node: once with the script inline in the spending transaction and
 *       once as a reference script. Every probe has the same minimal transaction shape (the locked
 *       input, one pinned collateral input, one output, one key witness) and the same fixed blinding
 *       ({@link #PAYLOAD_BLINDING}), so size grows only with {@code n}, strictly (asserted over every
 *       probed point); a different shape (more inputs, outputs or signers) lowers the limit. Recorded:
 *       wire and ledger size, fee and ex-units at {@code n}, and the node's reason at {@code n + 1}. These are
 *       measurements (ADR-0060 I11), not checks.</li>
 * </ol>
 *
 * <p>A rejected transaction is not applied, so negatives reuse one locked output. Honest byte openings
 * are costed locally with Julc (DevKit's {@code /evaluate} cannot initialise blst in the aarch64
 * container, ADR-0056); the node validates every submitted transaction. Tagged {@code e2e}; skips
 * when DevKit is not reachable. Run with
 * {@code ./gradlew :zeroj-integration-tests:e2eTest --tests '*G1PedersenNodeEvidenceE2ETest*'}.
 */
@Tag("e2e")
class G1PedersenNodeEvidenceE2ETest {

    private static final HexFormat HEX = HexFormat.of();
    private static final G1Pedersen PEDERSEN = G1Pedersen.pureJava();

    private static final String G_HEX =
            "80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e";
    private static final String H_HEX =
            "92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65";
    private static final BigInteger Q = G1Point.R;
    /**
     * The one blinding of every payload-limit probe: {@code q − 1}, a fixed public test value (never a
     * secret). It is 32 octets, the longest Plutus integer encoding any canonical blinding in
     * {@code [0, q)} can have, so the measured limit is the conservative one, and it is the same for every
     * probe, so the transaction size depends on {@code n} alone.
     */
    private static final BigInteger PAYLOAD_BLINDING = Q.subtract(BigInteger.ONE);
    /** {@code DST_B} of spec §2.1 (68 ASCII octets). */
    private static final String DST_B_HEX = "5a65726f4a2d706564657273656e2d626c7331322d3338312d67312d62617369732d"
            + "76312d424c53313233383147315f584d443a5348412d3235365f535357555f524f5f";

    /** Fixed budget for node-parity spends: within DevKit's per-transaction maximum (16.5M mem, 10G steps). */
    private static final ExUnits FIXED_BUDGET = new ExUnits(BigInteger.valueOf(10_000_000),
            BigInteger.valueOf(5_000_000_000L));

    private static final int SEARCH_LOW = 8_000;
    private static final int SEARCH_HIGH = 16_384;

    private static boolean available;
    private static BackendService backend;
    private static Account owner;

    @BeforeAll
    static void setup() {
        available = YaciHelper.isYaciReachable();
        if (!available) return;
        backend = YaciHelper.createBackendService();
        owner = new Account(Networks.testnet());
        YaciHelper.topUp(owner.baseAddress(), 1000);
    }

    // ==================================================================
    //  1. Strict decoding: node versus Julc VM versus spec §10.4 (I10)
    // ==================================================================

    enum Verdict { ACCEPTED, SCRIPT_FAILURE, BUDGET, OTHER }

    record DecodeCase(String label, String hex, Verdict expected) {
        boolean encodedLength48() {
            return hex.length() == 96;
        }
    }

    @Test
    @DisplayName("Node parity: decodeCommitment accepts the identity, G and −G and rejects every spec §10.4 negative, as the Julc VM does")
    void decodeParity() throws Exception {
        assumeTrue(available, "Yaci DevKit not running");
        PlutusScript script = JulcScriptLoader.load(G1DecodeNodeProbe.class);
        String scriptAddress = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();

        List<DecodeCase> accepted = List.of(
                new DecodeCase("identity c0‖0^47", "c0" + "00".repeat(47), Verdict.ACCEPTED),
                new DecodeCase("G (spec §2.2)", G_HEX, Verdict.ACCEPTED),
                new DecodeCase("−G (G with the sort flag flipped)", flipSort(G_HEX), Verdict.ACCEPTED));
        List<DecodeCase> rejected = List.of(
                new DecodeCase("e0‖0^47 (infinity with sort flag)", "e0" + "00".repeat(47), Verdict.SCRIPT_FAILURE),
                new DecodeCase("c0‖0^46‖01 (infinity with a coordinate bit)", "c0" + "00".repeat(46) + "01",
                        Verdict.SCRIPT_FAILURE),
                new DecodeCase("80‖0^47 (x = 0, order 3)", "80" + "00".repeat(47), Verdict.SCRIPT_FAILURE),
                new DecodeCase("a0‖0^47 (x = 0, sort flag, order 3)", "a0" + "00".repeat(47), Verdict.SCRIPT_FAILURE),
                new DecodeCase("G with the compression flag clear", "00" + G_HEX.substring(2), Verdict.SCRIPT_FAILURE),
                new DecodeCase("x = 1 (not on the curve)", "80" + "00".repeat(46) + "01", Verdict.SCRIPT_FAILURE),
                new DecodeCase("x = 4 (on the curve, not in G1)", "80" + "00".repeat(46) + "04", Verdict.SCRIPT_FAILURE),
                new DecodeCase("G + (0, 2) (mixed order)",
                        "b6ee2defa35097e6bbaea5ab251479b37157dedfcbc4b319181bf28298f048a66eb93dc0230190c18ae135644c2d3df4",
                        Verdict.SCRIPT_FAILURE),
                new DecodeCase("x = P_381 with the compression flag",
                        "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
                        Verdict.SCRIPT_FAILURE),
                new DecodeCase("47 octets (80‖0^46)", "80" + "00".repeat(46), Verdict.SCRIPT_FAILURE),
                new DecodeCase("49 octets (G‖00)", G_HEX + "00", Verdict.SCRIPT_FAILURE));

        // One output per accepted case. The first also carries every negative: it must survive them all.
        List<Utxo> locked = lockMany(owner, scriptAddress, emptyDatum(), accepted.size());
        Utxo negativesUtxo = locked.get(0);

        List<String> table = new ArrayList<>();
        for (DecodeCase c : rejected) {
            table.add(runDecodeCase(script, negativesUtxo, c));
        }
        for (int i = 0; i < accepted.size(); i++) {
            table.add(runDecodeCase(script, locked.get(i), accepted.get(i)));
        }
        System.out.println("[DevKit] decodeCommitment parity (spec §10.4 / Java strict decoder / Julc VM / node):");
        table.forEach(row -> System.out.println("[DevKit]   " + row));
        System.out.println("[DevKit]   the output that carried all " + rejected.size()
                + " negatives was then spent by the identity case: " + outRef(negativesUtxo));
    }

    private String runDecodeCase(PlutusScript script, Utxo locked, DecodeCase c) throws Exception {
        byte[] encoded = HEX.parseHex(c.hex());
        boolean javaAccepts;
        try {
            byte[] again = G1PedersenCommitment.decode(encoded).toPointBytes();
            javaAccepts = HEX.formatHex(again).equals(c.hex());
        } catch (RuntimeException e) {
            javaAccepts = false;
        }
        AtomicReference<Result<List<EvaluationResult>>> vm = new AtomicReference<>();
        Outcome node = spend(script, null, locked, owner, null, probe(encoded), vmThenFixedBudget(localEvaluator(null), vm));
        Verdict vmVerdict = vmVerdict(vm.get());
        Verdict nodeVerdict = nodeVerdict(node);
        if (nodeVerdict == Verdict.ACCEPTED) {
            YaciHelper.waitForConfirmation(backend, node.result().getValue());
        }
        String vmCause = vmCause(vm.get());
        String nodeCause = nodeCause(node);
        String row = String.format("%-46s %3d octets  expected %-14s java %-8s vm %-14s node %-14s%s", c.label(),
                encoded.length, c.expected(), javaAccepts ? "accepts" : "rejects", vmVerdict, nodeVerdict,
                nodeVerdict == Verdict.ACCEPTED ? "  tx " + node.result().getValue()
                        : "  failed at: node " + nodeCause + ", vm " + vmCause + " (" + vmDetail(vm.get()) + ")");

        assertNotNull(node.tx(), c.label() + ": the transaction was never built: " + node.result().getResponse());
        assertEquals(c.expected() == Verdict.ACCEPTED, javaAccepts, c.label() + ": Java strict decoder versus spec §10.4");
        assertEquals(c.expected(), vmVerdict, c.label() + ": Julc VM versus spec §10.4: " + vm.get().getResponse());
        assertEquals(c.expected(), nodeVerdict, c.label() + ": node versus spec §10.4: " + node.result().getResponse());
        assertEquals(vmVerdict, nodeVerdict, c.label() + ": node versus Julc VM");
        if (vmVerdict == Verdict.ACCEPTED) {
            assertWithinFixedBudget(vm.get(), c.label());
        } else {
            // Both fail at the same point: the library's length guard ('error') before uncompress, or
            // bls12_381_G1_uncompress itself (curve, subgroup and flag checks of the CIP-0381 element contract).
            assertEquals(c.encodedLength48() ? "bls12_381_G1_uncompress" : "error", nodeCause,
                    c.label() + ": node failure point: " + nodeReason(node));
            assertEquals(nodeCause, vmCause, c.label() + ": node versus Julc VM failure point");
        }
        return row;
    }

    // ==================================================================
    //  2. Bases reproduced on the node with hashToGroup (I1)
    // ==================================================================

    @Test
    @DisplayName("Node: hashToGroup(\"G\"/\"H\", DST_B) equals the pinned bases; a one-bit-different DST is rejected")
    void basesOnNode() throws Exception {
        assumeTrue(available, "Yaci DevKit not running");
        PlutusScript script = JulcScriptLoader.load(G1BasesNodeProbe.class);
        String scriptAddress = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        Utxo locked = lockMany(owner, scriptAddress, emptyDatum(), 1).get(0);

        byte[] dstB = HEX.parseHex(DST_B_HEX);
        assertEquals(68, dstB.length, "DST_B is 68 octets");
        byte[] oneBitOff = dstB.clone();
        oneBitOff[oneBitOff.length - 1] ^= 1;

        AtomicReference<Result<List<EvaluationResult>>> vmWrong = new AtomicReference<>();
        Outcome wrong = spend(script, null, locked, owner, null, probe(oneBitOff), vmThenFixedBudget(localEvaluator(null), vmWrong));
        assertNotNull(wrong.tx(), "one-bit-different DST: never built: " + wrong.result().getResponse());
        Verdict wrongVm = vmVerdict(vmWrong.get());
        Verdict wrongNode = nodeVerdict(wrong);
        System.out.println("[DevKit] bases, DST with the last bit flipped: vm " + wrongVm + ", node " + wrongNode
                + "  " + nodeReason(wrong));
        assertEquals(Verdict.SCRIPT_FAILURE, wrongVm, "Julc VM, one-bit-different DST");
        assertEquals(Verdict.SCRIPT_FAILURE, wrongNode, "node, one-bit-different DST: " + wrong.result().getResponse());

        AtomicReference<Result<List<EvaluationResult>>> vmRight = new AtomicReference<>();
        Outcome right = spend(script, null, locked, owner, null, probe(dstB), vmThenFixedBudget(localEvaluator(null), vmRight));
        assertNotNull(right.tx(), "DST_B: never built: " + right.result().getResponse());
        Verdict rightVm = vmVerdict(vmRight.get());
        Verdict rightNode = nodeVerdict(right);
        assertEquals(Verdict.ACCEPTED, rightVm, "Julc VM, DST_B: " + vmRight.get().getResponse());
        assertEquals(Verdict.ACCEPTED, rightNode, "node, DST_B: " + right.result().getResponse());
        assertWithinFixedBudget(vmRight.get(), "DST_B");
        YaciHelper.waitForConfirmation(backend, right.result().getValue());
        ExUnits used = vmRight.get().getValue().get(0).getExUnits();
        System.out.println("[DevKit] bases, DST_B: vm " + rightVm + " (mem=" + used.getMem() + " steps="
                + used.getSteps() + "), node " + rightNode + "  tx " + right.result().getValue()
                + " (the locked output survived the rejected spend)");
    }

    // ==================================================================
    //  3. scalarMul and multiScalarMul edge cases: node versus Julc VM (D9)
    // ==================================================================

    /** One builtin-evidence case: the redeemer, and what the Julc VM is expected to say about it. */
    record BuiltinCase(String builtin, String label, PlutusData redeemer, Verdict vmExpected) {}

    @Test
    @DisplayName("Node parity: bls12_381_G1_scalarMul outside [0, q) and multiScalarMul on empty and unequal lists, as the Julc VM")
    void scalarMulAndMsmParity() throws Exception {
        assumeTrue(available, "Yaci DevKit not running");
        G1Point g = Bls12381Codecs.g1FromCompressed(HEX.parseHex(G_HEX));
        G1Point h = Bls12381Codecs.g1FromCompressed(HEX.parseHex(H_HEX));

        List<BuiltinCase> scalarMulCases = new ArrayList<>();
        for (BigInteger s : new BigInteger[] {BigInteger.ONE.negate(), Q, Q.add(BigInteger.ONE),
                Q.negate().subtract(BigInteger.ONE), BigInteger.ONE.shiftLeft(256), BigInteger.ONE.shiftLeft(4096),
                BigInteger.ONE.shiftLeft(4096).negate()}) {
            byte[] reduced = Bls12381Codecs.g1ToCompressed(g.scalarMul(s.mod(Q)));
            // Julc VM (PedersenG1BuiltinEvidenceTest): reduced mod q up to |s| = 2^256; 2^4096 fails the script.
            Verdict vmExpected = s.abs().bitLength() <= 257 ? Verdict.ACCEPTED : Verdict.SCRIPT_FAILURE;
            scalarMulCases.add(new BuiltinCase("scalarMul", "s = " + label(s) + " (" + s.abs().bitLength() + " bits)",
                    constr(BigIntPlutusData.of(s), new BytesPlutusData(reduced)), vmExpected));
        }

        byte[] identity = HEX.parseHex("c0" + "00".repeat(47));
        byte[] gBytes = HEX.parseHex(G_HEX);
        byte[] hBytes = HEX.parseHex(H_HEX);
        BigInteger two = BigInteger.TWO;
        BigInteger three = BigInteger.valueOf(3);
        byte[] twoG = Bls12381Codecs.g1ToCompressed(g.scalarMul(two));
        List<BuiltinCase> msmCases = List.of(
                msmCase("[], [] → identity", List.of(), List.of(), identity),
                msmCase("[2], [] → identity", List.of(two), List.of(), identity),
                msmCase("[], [G] → identity", List.of(), List.of(gBytes), identity),
                msmCase("[2, 3], [G] → [2]G (truncated)", List.of(two, three), List.of(gBytes), twoG),
                msmCase("[2], [G, H] → [2]G (truncated)", List.of(two), List.of(gBytes, hBytes), twoG),
                msmCase("[2, 3], [G, H] → [2]G + [3]H", List.of(two, three), List.of(gBytes, hBytes),
                        Bls12381Codecs.g1ToCompressed(g.scalarMul(two).add(h.scalarMul(three)))));

        List<BuiltinRow> rows = new ArrayList<>();
        rows.addAll(runBuiltinCases(JulcScriptLoader.load(G1ScalarMulNodeProbe.class), scalarMulCases));
        rows.addAll(runBuiltinCases(JulcScriptLoader.load(G1MsmNodeProbe.class), msmCases));

        System.out.println("[DevKit] scalarMul / multiScalarMul edge cases (Julc VM versus node, same transaction, fixed budget):");
        System.out.println(String.format("[DevKit]   %-9s | %-36s | %-14s | %-14s | %-14s | %s", "builtin", "case",
                "vm expected", "vm", "node", "failure point / tx"));
        for (BuiltinRow r : rows) {
            System.out.println("[DevKit]   " + r.line());
        }

        // Asserted only after the whole table is printed, so a disagreement shows every case.
        for (BuiltinRow r : rows) {
            String what = r.c().builtin() + " " + r.c().label();
            assertNotNull(r.node().tx(), what + ": the transaction was never built: " + r.node().result().getResponse());
            assertEquals(r.c().vmExpected(), r.vm(), what + ": Julc VM: " + r.vmResult().getResponse());
            assertEquals(r.vm(), r.nodeVerdict(), what + ": node versus Julc VM: " + r.node().result().getResponse());
            if (r.vm() == Verdict.ACCEPTED) {
                assertWithinFixedBudget(r.vmResult(), what);
            } else {
                // A script failure on both, at the same point, never a budget overrun or a ledger rejection.
                assertEquals(nodeCause(r.node()), vmCause(r.vmResult()), what + ": node versus Julc VM failure point");
            }
        }
    }

    record BuiltinRow(BuiltinCase c, Result<List<EvaluationResult>> vmResult, Verdict vm, Outcome node,
                      Verdict nodeVerdict, String line) {}

    private static BuiltinCase msmCase(String label, List<BigInteger> scalars, List<byte[]> points, byte[] expected) {
        // Julc VM (PedersenG1BuiltinEvidenceTest): empty lists give the identity, unequal lists are truncated.
        return new BuiltinCase("MSM", label, constr(
                ListPlutusData.of(scalars.stream().map(BigIntPlutusData::of).toArray(PlutusData[]::new)),
                ListPlutusData.of(points.stream().map(BytesPlutusData::new).toArray(PlutusData[]::new)),
                new BytesPlutusData(expected)), Verdict.ACCEPTED);
    }

    /** One locked output per case (a rejected spend leaves it in place), each spent with a fixed budget. */
    private List<BuiltinRow> runBuiltinCases(PlutusScript script, List<BuiltinCase> cases) throws Exception {
        String scriptAddress = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        List<Utxo> locked = lockMany(owner, scriptAddress, emptyDatum(), cases.size());
        List<BuiltinRow> rows = new ArrayList<>();
        for (int i = 0; i < cases.size(); i++) {
            BuiltinCase c = cases.get(i);
            AtomicReference<Result<List<EvaluationResult>>> vm = new AtomicReference<>();
            Outcome node = spend(script, null, locked.get(i), owner, null, c.redeemer(),
                    vmThenFixedBudget(localEvaluator(null), vm));
            Verdict vmVerdict = vmVerdict(vm.get());
            Verdict nodeVerdict = nodeVerdict(node);
            if (nodeVerdict == Verdict.ACCEPTED) {
                YaciHelper.waitForConfirmation(backend, node.result().getValue());
            }
            String detail;
            if (nodeVerdict == Verdict.ACCEPTED) {
                ExUnits used = vmVerdict == Verdict.ACCEPTED ? vm.get().getValue().get(0).getExUnits() : null;
                detail = "tx " + node.result().getValue()
                        + (used == null ? "" : " (vm mem=" + used.getMem() + " steps=" + used.getSteps() + ")");
            } else {
                detail = "node " + nodeCause(node) + " [" + nodeReason(node) + "], vm " + vmCause(vm.get())
                        + " (" + vmDetail(vm.get()) + ")";
            }
            String line = String.format("%-9s | %-36s | %-14s | %-14s | %-14s | %s", c.builtin(), c.label(),
                    c.vmExpected(), vmVerdict, nodeVerdict, detail);
            rows.add(new BuiltinRow(c, vm.get(), vmVerdict, node, nodeVerdict, line));
        }
        return rows;
    }

    // ==================================================================
    //  4. Payload limit of a byte opening (inline script and reference script)
    // ==================================================================

    record Probe(int n, Outcome outcome) {}

    @Test
    @DisplayName("Node: the largest byte-opening payload, script inline and as a reference script")
    void payloadLimit() throws Exception {
        assumeTrue(available, "Yaci DevKit not running");
        PlutusScript script = JulcScriptLoader.load(G1BytesOpeningValidator.class);
        String scriptAddress = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        int scriptSize = script.serializeScriptBody().length;

        // Deploy the validator once as a reference script, at an address the owner never spends from.
        String refHolder = new Account(Networks.testnet()).baseAddress();
        Result<String> deployed = new QuickTxBuilder(backend)
                .compose(new Tx().payToAddress(refHolder, Amount.ada(30), script).from(owner.baseAddress()))
                .withSigner(SignerProviders.signerFrom(owner)).complete();
        assertTrue(deployed.isSuccessful(), "reference script deployment failed: " + deployed.getResponse());
        YaciHelper.waitForConfirmation(backend, deployed.getValue());
        Utxo refUtxo = YaciHelper.findUtxo(backend, refHolder, deployed.getValue());
        assertEquals(HEX.formatHex(script.getScriptHash()), refUtxo.getReferenceScriptHash(),
                "the deployed output carries the validator as its reference script");
        System.out.println("[DevKit] reference script deployed at " + outRef(refUtxo) + " (script "
                + scriptSize + " octets)");

        Map<String, Probe[]> limits = new LinkedHashMap<>();
        // The opener owns the datum, signs, pays the fee out of the unlocked 5 ADA and receives the rest.
        // Its one top-up UTxO is pinned as the collateral of every spend (CCL then never selects it as a
        // regular input), and locks are funded by the owner. So every probe has the same minimal shape:
        // the locked input only, that one collateral input, one output, one key witness; size grows only
        // with n. The shape is printed and asserted equal at the boundary.
        Account opener = new Account(Networks.testnet());
        YaciHelper.topUp(opener.baseAddress(), 50);
        TransactionInput collateral = onlyUtxo(opener.baseAddress());
        limits.put("inline", search(script, scriptAddress, null, opener, collateral));
        limits.put("reference", search(script, scriptAddress, refUtxo, opener, collateral));

        System.out.println("[DevKit] byte-opening payload limit (G1BytesOpeningValidator, script "
                + scriptSize + " octets, max_tx_size 16384, fixed blinding r = q - 1, "
                + BigIntPlutusData.of(PAYLOAD_BLINDING).serializeToBytes().length + "-octet Plutus integer):");
        System.out.println("[DevKit]   tx size = wire octets / ledger octets (the node's measure, without the isValid flag)");
        System.out.println(String.format("[DevKit]   %-9s | %-7s | %-15s | %-13s | %-10s | %-13s | %s",
                "script", "max n", "tx size", "fee lovelace", "mem", "steps", "n + 1 rejected by the node"));
        for (var e : limits.entrySet()) {
            Probe ok = e.getValue()[0];
            Probe over = e.getValue()[1];
            Transaction tx = ok.outcome().tx();
            Redeemer r = tx.getWitnessSet().getRedeemers().get(0);
            int wire = tx.serialize().length;
            System.out.println(String.format("[DevKit]   %-9s | %,7d | %,6d / %,6d | %,13d | %,10d | %,13d | wire size %,d: %s  %s",
                    e.getKey(), ok.n(), wire, wire - 1, tx.getBody().getFee(), r.getExUnits().getMem(),
                    r.getExUnits().getSteps(), over.outcome().tx().serialize().length, nodeReason(over.outcome()),
                    shape(tx)));
        }
    }

    /**
     * Binary search for the largest accepted payload. Each probe locks a fresh output under the
     * commitment to {@code pattern(n)} and submits the honest opening. Returns {max accepted, max + 1}.
     */
    private Probe[] search(PlutusScript script, String scriptAddress, Utxo refUtxo, Account opener,
                           TransactionInput collateral) throws Exception {
        String mode = refUtxo == null ? "inline" : "reference";
        Map<Integer, Outcome> seen = new TreeMap<>();
        int lo = SEARCH_LOW;
        int hi = SEARCH_HIGH;
        Outcome atLo = openBytes(script, scriptAddress, refUtxo, opener, collateral, lo);
        seen.put(lo, atLo);
        assertTrue(atLo.result().isSuccessful(), mode + ": n = " + lo + " must be accepted: " + atLo.result().getResponse());
        Outcome atHi = openBytes(script, scriptAddress, refUtxo, opener, collateral, hi);
        seen.put(hi, atHi);
        assertFalse(atHi.result().isSuccessful(), mode + ": n = " + hi + " must be rejected");
        while (hi - lo > 1) {
            int mid = (lo + hi) >>> 1;
            Outcome o = openBytes(script, scriptAddress, refUtxo, opener, collateral, mid);
            seen.put(mid, o);
            if (o.result().isSuccessful()) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        Outcome ok = seen.get(lo);
        Outcome over = seen.get(hi);
        assertEquals(lo + 1, hi);
        assertTrue(ok.result().isSuccessful(), mode + ": n = " + lo + " accepted");
        assertNotNull(over.tx(), mode + ": n = " + hi + " was never built: " + over.result().getResponse());
        assertFalse(over.result().isSuccessful(), mode + ": n = " + hi + " rejected");
        assertEquals(shape(ok.tx()), shape(over.tx()),
                mode + ": n and n + 1 must have the same transaction shape, so the boundary is the payload's");
        // With the blinding and every other size-bearing input fixed, the serialized size must grow
        // strictly with n over every probed point, or the binary search is not searching a monotone predicate.
        StringBuilder sizes = new StringBuilder();
        int lastN = -1;
        int lastSize = -1;
        for (var e : seen.entrySet()) {
            Transaction tx = e.getValue().tx();
            assertNotNull(tx, mode + ": n = " + e.getKey() + " was never built: " + e.getValue().result().getResponse());
            int size = tx.serialize().length;
            sizes.append(sizes.isEmpty() ? "" : ", ").append(e.getKey()).append(" -> ").append(size);
            assertTrue(size > lastSize, mode + ": transaction size must grow strictly with n, but n = " + e.getKey()
                    + " gives " + size + " octets after n = " + lastN + " gave " + lastSize);
            lastN = e.getKey();
            lastSize = size;
        }
        System.out.println("[DevKit] payload " + mode + " probed n -> tx size (strictly increasing): " + sizes);
        String reason = String.valueOf(over.result().getResponse());
        assertTrue(reason.contains("MaxTxSizeUTxO"),
                mode + ": n = " + hi + " must be rejected by the node for the transaction size: " + abbreviate(reason));
        // The node's size is one octet less than the wire encoding CCL builds: the ledger measures the
        // transaction without its isValid flag (observed here, asserted so that a change is noticed).
        Matcher m = Pattern.compile("supplied: (\\d+), expected: (\\d+)").matcher(reason);
        assertTrue(m.find(), mode + ": the node's MaxTxSizeUTxO names the supplied and maximum sizes: " + abbreviate(reason));
        int supplied = Integer.parseInt(m.group(1));
        int maximum = Integer.parseInt(m.group(2));
        assertEquals(over.tx().serialize().length - 1, supplied, mode + ": node size of n + 1 versus its wire size");
        assertTrue(supplied > maximum, mode + ": n + 1 is over the maximum");
        assertTrue(ok.tx().serialize().length - 1 <= maximum, mode + ": n is within the maximum (ledger size)");
        return new Probe[] {new Probe(lo, ok), new Probe(hi, over)};
    }

    private Outcome openBytes(PlutusScript script, String scriptAddress, Utxo refUtxo, Account opener,
                              TransactionInput collateral, int n)
            throws Exception {
        byte[] payload = G1PedersenOnChainTest.pattern(n);
        BigInteger blinding = PAYLOAD_BLINDING;
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(payload, blinding);
        assertTrue(PEDERSEN.verifyBytes(c, payload, blinding), "off-chain oracle, n = " + n);
        byte[] openerPkh = opener.hdKeyPair().getPublicKey().getKeyHash();
        Utxo locked = lockMany(owner, scriptAddress, holding(openerPkh, c.toPointBytes()), 1).get(0);
        Outcome o = spend(script, refUtxo, locked, opener, collateral, bytesOpening(payload, blinding),
                localEvaluator(script));
        String mode = refUtxo == null ? "inline" : "reference";
        if (o.result().isSuccessful()) {
            YaciHelper.waitForConfirmation(backend, o.result().getValue());
            Redeemer r = o.tx().getWitnessSet().getRedeemers().get(0);
            System.out.println("[DevKit] payload " + mode + " n=" + n + ": ACCEPTED size=" + o.tx().serialize().length
                    + " fee=" + o.tx().getBody().getFee() + " mem=" + r.getExUnits().getMem()
                    + " steps=" + r.getExUnits().getSteps() + " " + shape(o.tx()));
        } else {
            System.out.println("[DevKit] payload " + mode + " n=" + n + ": rejected"
                    + (o.tx() == null ? " before submission" : " size=" + o.tx().serialize().length + " " + shape(o.tx()))
                    + ": " + nodeReason(o));
        }
        return o;
    }

    // ------------------------------------------------------------------
    //  Harness
    // ------------------------------------------------------------------

    /** A submission result and the transaction as it was built and signed (null if building failed). */
    record Outcome(Result<String> result, Transaction tx) {}

    /** The single UTxO at {@code address} (after a top-up), as a transaction input. */
    private static TransactionInput onlyUtxo(String address) throws Exception {
        for (int attempt = 0; attempt < 15; attempt++) {
            var utxos = backend.getUtxoService().getUtxos(address, 10, 1);
            if (utxos.isSuccessful() && utxos.getValue() != null && utxos.getValue().size() == 1) {
                Utxo u = utxos.getValue().get(0);
                return new TransactionInput(u.getTxHash(), u.getOutputIndex());
            }
            Thread.sleep(2000);
        }
        throw new IllegalStateException("expected exactly one UTxO at " + address);
    }

    /** Locks {@code count} separate 5 ADA outputs with {@code datum} in one transaction funded by {@code funder}. */
    private static List<Utxo> lockMany(Account funder, String scriptAddress, PlutusData datum, int count)
            throws Exception {
        Tx lock = new Tx();
        for (int i = 0; i < count; i++) {
            lock = lock.payToContract(scriptAddress, Amount.ada(5), datum);
        }
        lock = lock.from(funder.baseAddress());
        Result<String> locked = new QuickTxBuilder(backend).compose(lock)
                .mergeOutputs(false)
                .withSigner(SignerProviders.signerFrom(funder)).complete();
        assertTrue(locked.isSuccessful(), "lock failed: " + locked.getResponse());
        YaciHelper.waitForConfirmation(backend, locked.getValue());
        // Read the lock's outputs by reference, not by listing the script address: every run leaves the
        // locked outputs of rejected (oversize) probes there for good, so a first page of the address's
        // UTxOs eventually misses a fresh one. The lock has count script outputs and one change output.
        for (int attempt = 0; attempt < 15; attempt++) {
            List<Utxo> utxos = new ArrayList<>();
            for (int i = 0; i <= count; i++) {
                Result<Utxo> out = backend.getUtxoService().getTxOutput(locked.getValue(), i);
                if (out.isSuccessful() && out.getValue() != null && scriptAddress.equals(out.getValue().getAddress())) {
                    utxos.add(out.getValue());
                }
            }
            if (utxos.size() == count) return utxos;
            Thread.sleep(2000);
        }
        throw new IllegalStateException("expected " + count + " locked outputs of " + locked.getValue() + " at " + scriptAddress);
    }

    /**
     * Spends {@code locked} with {@code redeemer}. {@code account} signs (and is a required signer),
     * pays the fee and the collateral, and receives the 5 ADA. The validator is attached inline, or read
     * from {@code refUtxo} when it is not null. {@code collateral}, when not null, pins the collateral input.
     */
    private static Outcome spend(PlutusScript script, Utxo refUtxo, Utxo locked, Account account,
                                 TransactionInput collateral, PlutusData redeemer, TransactionEvaluator evaluator) {
        var tx = new ScriptTx().collectFrom(locked, redeemer).payToAddress(account.baseAddress(), Amount.ada(5));
        if (refUtxo == null) {
            tx = tx.attachSpendingValidator(script);
        } else {
            tx = tx.readFrom(refUtxo);
        }
        AtomicReference<Transaction> built = new AtomicReference<>();
        try {
            var context = new QuickTxBuilder(backend).compose(tx)
                    .withTxEvaluator(evaluator)
                    .withTxInspector(built::set)
                    .withSigner(SignerProviders.signerFrom(account))
                    .withRequiredSigners(account.hdKeyPair().getPublicKey().getKeyHash())
                    .feePayer(account.baseAddress())
                    .collateralPayer(account.baseAddress());
            if (refUtxo != null) {
                context = context.withReferenceScripts(script);
            }
            if (collateral != null) {
                context = context.withCollateralInputs(collateral);
            }
            return new Outcome(context.complete(), built.get());
        } catch (RuntimeException e) {
            YaciHelper.assumeNoBlsCostingFailure(e);
            return new Outcome(Result.error(e.getMessage()), built.get());
        }
    }

    /**
     * Julc-costed evaluation. {@code referenceScript}, when not null, is resolved locally by hash so
     * that a transaction that reads it from a reference input can be evaluated without the indexer.
     */
    private static TransactionEvaluator localEvaluator(PlutusScript referenceScript) {
        ScriptSupplier indexer = new DefaultScriptSupplier(backend.getScriptService());
        ScriptSupplier scripts = indexer;
        if (referenceScript != null) {
            String hash;
            try {
                hash = HEX.formatHex(referenceScript.getScriptHash());
            } catch (CborSerializationException e) {
                throw new IllegalStateException(e);
            }
            scripts = h -> h.equals(hash) ? Optional.of(referenceScript) : indexer.getScript(h);
        }
        return new JulcTransactionEvaluator(
                new DefaultUtxoSupplier(backend.getUtxoService()),
                new DefaultProtocolParamsSupplier(backend.getEpochService()),
                scripts);
    }

    /**
     * Records the Julc VM's verdict on the exact transaction being built, then assigns
     * {@link #FIXED_BUDGET} to every redeemer so that the transaction reaches the node whatever the
     * VM says. The last evaluation is the one of the transaction that is submitted (only the fee and
     * ex-units differ between drafts, and the probes do not read either).
     */
    private static TransactionEvaluator vmThenFixedBudget(TransactionEvaluator vm,
                                                          AtomicReference<Result<List<EvaluationResult>>> verdict) {
        return (cbor, inputUtxos) -> {
            try {
                verdict.set(vm.evaluateTx(cbor, inputUtxos));
            } catch (Exception e) {
                verdict.set(Result.error("Julc evaluation threw: " + e));
            }
            Transaction tx;
            try {
                tx = Transaction.deserialize(cbor);
            } catch (CborDeserializationException e) {
                return Result.error(e.getMessage());
            }
            List<EvaluationResult> results = new ArrayList<>();
            for (Redeemer r : tx.getWitnessSet().getRedeemers()) {
                results.add(new EvaluationResult(r.getTag(), r.getIndex().intValue(), FIXED_BUDGET));
            }
            return Result.success("fixed budget").withValue(results);
        };
    }

    private static Verdict vmVerdict(Result<List<EvaluationResult>> r) {
        assertNotNull(r, "the Julc VM never evaluated the transaction");
        if (r.isSuccessful()) return Verdict.ACCEPTED;
        String msg = String.valueOf(r.getResponse());
        if (msg.contains("Budget exhausted")) return Verdict.BUDGET;
        if (msg.contains("Script evaluation failed")) return Verdict.SCRIPT_FAILURE;
        return Verdict.OTHER;
    }

    /** The node's verdict: accepted, a failing script (phase 2), a budget overrun, or anything else. */
    private static Verdict nodeVerdict(Outcome o) {
        if (o.result().isSuccessful()) return Verdict.ACCEPTED;
        if (o.tx() == null) return Verdict.OTHER;
        String response = String.valueOf(o.result().getResponse());
        if (response.contains("overspending") || response.contains("ExBudgetExceeded")) return Verdict.BUDGET;
        if (response.contains("PlutusFailure") || response.contains("ValidationTagMismatch")
                || response.contains("FailedUnexpectedly")) return Verdict.SCRIPT_FAILURE;
        return Verdict.OTHER;
    }

    private static void assertWithinFixedBudget(Result<List<EvaluationResult>> vm, String label) {
        for (EvaluationResult e : vm.getValue()) {
            assertTrue(e.getExUnits().getMem().compareTo(FIXED_BUDGET.getMem()) < 0
                            && e.getExUnits().getSteps().compareTo(FIXED_BUDGET.getSteps()) < 0,
                    label + ": the fixed budget must exceed the honest cost, so a rejection is never a budget failure");
        }
    }

    /** What the node names as the cause of a phase-2 failure ("Caused by: …"): a builtin, or {@code error}. */
    private static String nodeCause(Outcome o) {
        Matcher m = Pattern.compile("Caused by: ([A-Za-z0-9_]+)").matcher(String.valueOf(o.result().getResponse()));
        return m.find() ? m.group(1) : "?";
    }

    /** The same for the Julc VM, in the node's vocabulary. */
    private static String vmCause(Result<List<EvaluationResult>> r) {
        String msg = String.valueOf(r.getResponse());
        if (msg.contains("FAIL: Error term encountered")) return "error";
        Matcher m = Pattern.compile("FAIL: Bls12_381_([A-Za-z0-9_]+)").matcher(msg);
        if (m.find()) return "bls12_381_" + m.group(1);
        return "?";
    }

    /** The Julc VM's own failure text (blst's reason for an uncompress failure). */
    private static String vmDetail(Result<List<EvaluationResult>> r) {
        String msg = String.valueOf(r.getResponse()).replaceAll("\\s+", " ");
        int at = msg.indexOf("FAIL: ");
        if (at < 0) return abbreviate(msg, 80);
        msg = msg.substring(at + 6);
        int end = msg.indexOf(" EqualsInteger");
        return end > 0 ? msg.substring(0, end) : abbreviate(msg, 80);
    }

    /** The node's stated reason, shortened to the part that names it. */
    private static String nodeReason(Outcome o) {
        if (o.result().isSuccessful()) return "accepted";
        String response = String.valueOf(o.result().getResponse());
        for (String key : new String[] {"MaxTxSizeUTxO", "The machine terminated", "ExBudgetExceeded",
                "FeeTooSmallUTxO", "PlutusFailure", "ValidationTagMismatch"}) {
            int at = response.indexOf(key);
            if (at >= 0) {
                String from = response.substring(at).replaceAll("\\s+", " ");
                int close = from.indexOf('}');
                return key.equals("MaxTxSizeUTxO") && close > 0 ? from.substring(0, close + 1) : abbreviate(from, 160);
            }
        }
        return abbreviate(response.replaceAll("\\s+", " "), 160);
    }

    /** Inputs, reference inputs, collateral inputs, outputs and key witnesses of a transaction. */
    private static String shape(Transaction tx) {
        var body = tx.getBody();
        return "[in=" + size(body.getInputs()) + " ref=" + size(body.getReferenceInputs())
                + " coll=" + size(body.getCollateral()) + " out=" + size(body.getOutputs())
                + " vkeys=" + size(tx.getWitnessSet().getVkeyWitnesses()) + "]";
    }

    private static int size(List<?> list) {
        return list == null ? 0 : list.size();
    }

    private static PlutusData constr(PlutusData... fields) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(fields)).build();
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

    private static PlutusData emptyDatum() {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of()).build();
    }

    private static PlutusData probe(byte[] octets) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(new BytesPlutusData(octets))).build();
    }

    private static PlutusData holding(byte[] ownerKeyHash, byte[] commitment) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(ownerKeyHash), new BytesPlutusData(commitment))).build();
    }

    private static PlutusData bytesOpening(byte[] payload, BigInteger blinding) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(payload), BigIntPlutusData.of(blinding))).build();
    }

    private static String flipSort(String hex) {
        byte[] b = HEX.parseHex(hex);
        b[0] ^= 0x20;
        return HEX.formatHex(b);
    }

    private static String outRef(Utxo u) {
        return u.getTxHash() + "#" + u.getOutputIndex();
    }

    private static String abbreviate(String s) {
        return abbreviate(s, 400);
    }

    private static String abbreviate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
