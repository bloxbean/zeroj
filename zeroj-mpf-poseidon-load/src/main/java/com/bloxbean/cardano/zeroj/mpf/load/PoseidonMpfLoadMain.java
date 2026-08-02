package com.bloxbean.cardano.zeroj.mpf.load;

/** Command-line entry point for ADR-0041's resumable load and proof benchmark. */
public final class PoseidonMpfLoadMain {
    private PoseidonMpfLoadMain() {}

    public static void main(String[] args) throws Exception {
        final LoadOptions options;
        try {
            options = LoadOptions.parse(args);
        } catch (LoadOptions.HelpRequested ignored) {
            printHelp();
            return;
        }

        System.out.printf("Poseidon MPF profile=%s CCL=%s stage=%s entries=%,d workDir=%s%n",
                com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfHash.PROFILE_ID,
                BuildInfo.cclVersion(), options.stage(), options.entries(), options.workDir());

        if (options.stage().includes(LoadOptions.Stage.LOAD)) {
            new PoseidonMpfLoadRunner(options).run();
        }

        if (options.stage().includes(LoadOptions.Stage.DEPTH_SCAN)) {
            new PoseidonMpfDepthScanRunner(options).run();
        }

        PoseidonMpfProofRunner.ProofRun proofs = null;
        if (options.stage().includes(LoadOptions.Stage.PROOFS)
                || options.stage().includes(LoadOptions.Stage.CIRCUIT)) {
            proofs = new PoseidonMpfProofRunner(options).run();
        }

        if (options.stage().includes(LoadOptions.Stage.CIRCUIT)) {
            new PoseidonMpfCircuitBenchmark(options).run(proofs);
        }

        System.out.println("Benchmark stages completed. Report: " + options.workDir().resolve("report.json"));
    }

    private static void printHelp() {
        System.out.println("""
                ZeroJ Poseidon MPF load/proof benchmark

                  --stage=all|load|proofs|circuit|depth-scan
                                                       default: all (depth-scan is opt-in)
                  --work-dir=PATH                      default: build/poseidon-mpf-5m
                  --entries=N                          default: 5000000
                  --batch=N                            default: 1000
                  --seed=N                             default: 25
                  --samples=N                          default: 32
                  --max-steps=N                        default: 8
                  --max-fork-prefix-chunks=N           default: 2
                  --pair-cache=N                       default: 262144 entries (0 disables)
                  --rocksdb-profile=high-throughput|balanced|low-memory|default
                                                       default: high-throughput
                  --progress-every=N                   default: 100000 (0 disables)
                  --wal=true|false                     default: true
                  --depth-scan-version=N               default: latest root; depth-scan only
                  --setup=none|in-memory|store|load    default: none
                  --keys-dir=PATH                      default: WORK_DIR/groth16-keys
                  --allow-insecure-setup=true|false    required for in-memory/store setup

                Local setup is single-party and benchmark-only. It is not production key material.
                """);
    }
}
