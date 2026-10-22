package org.zeroj.onchain.julc.pedersen;

import org.julclang.compiler.CompileResult;
import org.julclang.core.PlutusData;
import org.julclang.vm.EvalOptions;
import org.julclang.vm.EvalResult;
import org.julclang.vm.JulcVm;
import org.julclang.vm.PlutusLanguage;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Exact counts of the BLS12-381 G1 builtins one whole evaluation ran (the ADR-0056 marked cost
 * model). The PV11 cost model is loaded with the CPU costs of {@code bls12_381_G1_uncompress},
 * {@code bls12_381_G1_scalarMul} and {@code bls12_381_G1_multiScalarMul} replaced by 10^10, 10^12
 * and 10^14. Everything else an evaluation of these probes costs stays below 10^10 and each count
 * below 100, so the digit pairs of the consumed CPU are the counts. Unlike the Julc VM's builtin
 * trace, which keeps only the last 20 builtins, this sees the whole evaluation.
 *
 * <p>{@code PedersenG1Lib} decompresses its pinned bases only inside the operations that use them,
 * so a decode-only evaluation runs exactly one {@code uncompress}.
 */
final class MarkedBuiltinCounts {

    /** Indices in the canonical PV11 Plutus V3 parameter list, and the values found there. */
    private static final int UNCOMPRESS_CPU = 211;
    private static final int SCALAR_MUL_CPU = 208;
    private static final int MSM_CPU = 313;
    private static final long UNCOMPRESS_MARK = 10_000_000_000L;
    private static final long SCALAR_MUL_MARK = UNCOMPRESS_MARK * 100;
    private static final long MSM_MARK = SCALAR_MUL_MARK * 100;

    private static final JulcVm VM = vm();

    record Counts(long uncompress, long scalarMul, long msm) {}

    private MarkedBuiltinCounts() {
    }

    /** Evaluates {@code compiled} on {@code context} under the marked model; the outcome must equal {@code expectSuccess}. */
    static Counts count(CompileResult compiled, PlutusData context, boolean expectSuccess) {
        EvalResult result = VM.evaluateWithArgs(compiled.program(), compiled.target().ledgerTarget(),
                List.of(context), null, EvalOptions.DEFAULT);
        if (result.isSuccess() != expectSuccess) {
            throw new AssertionError("marked run outcome " + result.isSuccess() + " differs from the expected " + expectSuccess);
        }
        long cpu = result.budgetConsumed().cpuSteps();
        Counts counts = new Counts(cpu / UNCOMPRESS_MARK % 100, cpu / SCALAR_MUL_MARK % 100, cpu / MSM_MARK % 100);
        // Exactness: the marked total must be the counts times the marks plus unmarked work below one
        // uncompress mark, and no count may reach 100 (that would carry into the next digit pair).
        long marked = counts.uncompress() * UNCOMPRESS_MARK + counts.scalarMul() * SCALAR_MUL_MARK
                + counts.msm() * MSM_MARK;
        long unmarked = cpu - marked;
        if (unmarked < 0 || unmarked >= UNCOMPRESS_MARK / 2 || cpu >= 100 * MSM_MARK) {
            throw new AssertionError("marked counts are not exact: cpu " + cpu);
        }
        return counts;
    }

    private static JulcVm vm() {
        long[] costs;
        try (InputStream in = JulcVm.class.getResourceAsStream("/cost-model/plutus-v3-pv11-costs-v1.params")) {
            if (in == null) {
                throw new IllegalStateException("PV11 cost-model parameters missing");
            }
            costs = new String(in.readAllBytes(), StandardCharsets.UTF_8).lines()
                    .filter(line -> !line.isBlank() && !line.startsWith("#"))
                    .mapToLong(Long::parseLong).toArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        if (costs.length != 350 || costs[UNCOMPRESS_CPU] != 52_948_122L || costs[SCALAR_MUL_CPU] != 76_433_006L
                || costs[MSM_CPU] != 321_837_444L) {
            throw new IllegalStateException("unexpected PV11 parameter layout");
        }
        costs[UNCOMPRESS_CPU] = UNCOMPRESS_MARK;
        costs[SCALAR_MUL_CPU] = SCALAR_MUL_MARK;
        costs[MSM_CPU] = MSM_MARK;
        JulcVm vm = JulcVm.create();
        vm.setCostModelParams(costs, PlutusLanguage.PLUTUS_V3, 11, 0);
        return vm;
    }
}
