package com.bloxbean.cardano.zeroj.jmt.load;

public final class PoseidonJmtLoadMain {
    private PoseidonJmtLoadMain() {}

    public static void main(String[] arguments) throws Exception {
        try {
            JmtLoadOptions options = JmtLoadOptions.parse(arguments);
            if (options.stage().includes(JmtLoadOptions.Stage.LOAD)) {
                new PoseidonJmtLoadRunner(options).run();
            }
            PoseidonJmtProofRunner.ProofRun proofs = null;
            if (options.stage().includes(JmtLoadOptions.Stage.PROOFS)
                    || options.stage().includes(JmtLoadOptions.Stage.CIRCUIT)) {
                proofs = new PoseidonJmtProofRunner(options).run();
            }
            if (options.stage().includes(JmtLoadOptions.Stage.DEPTH_SCAN)) {
                new PoseidonJmtDepthScanRunner(options).run();
            }
            if (options.stage().includes(JmtLoadOptions.Stage.CIRCUIT)) {
                new PoseidonJmtCircuitBenchmark(options).run(proofs);
            }
            if (options.stage().includes(JmtLoadOptions.Stage.OPERATIONS)) {
                new PoseidonJmtOperationBenchmark(options).run();
            }
        } catch (JmtLoadOptions.HelpRequested ignored) {
            usage();
        }
    }

    private static void usage() {
        System.out.println("""
                ZeroJ Poseidon JMT durable load/benchmark
                  --stage=load|proofs|circuit|depth-scan|operations|all
                  --work-dir=.benchmark-data/poseidon-jmt-5m
                  --entries=5000000 --batch=5000 --seed=42
                  --samples=32 --max-levels=64
                  --circuit-trials=1 --operation-entries=1000
                  --pair-cache=262144 (0 disables the bounded binary-pair cache)
                  --rocksdb-profile=high-throughput|balanced|low-memory|default
                  --progress-every=100000
                  --setup=none|in-memory|store|load --keys-dir=PATH
                  --allow-insecure-setup=false
                """);
    }
}
