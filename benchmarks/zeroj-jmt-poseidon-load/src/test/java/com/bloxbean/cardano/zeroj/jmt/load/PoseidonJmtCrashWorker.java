package com.bloxbean.cardano.zeroj.jmt.load;

import com.bloxbean.cardano.vds.jmt.rocksdb.RocksDbJmtStore;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtTree;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;

/** Child JVM used to exercise abrupt termination after a synced Poseidon JMT commit. */
public final class PoseidonJmtCrashWorker {
    private PoseidonJmtCrashWorker() {}

    public static void main(String[] arguments) {
        Path database = Path.of(arguments[0]);
        long stopVersion = Long.parseLong(arguments[1]);
        JmtLoadOptions options = JmtLoadOptions.parse(new String[]{
                "--work-dir=" + database.resolveSibling("worker-options"), "--entries=1"});
        try (RocksDbJmtStore store = RocksDbJmtStore.open(
                database.toString(), options.storeOptions())) {
            PoseidonJmtTree tree = new PoseidonJmtTree(store);
            long start = store.latestRoot().orElseThrow().version() + 1;
            for (long version = start; version <= stopVersion; version++) {
                tree.put(version, Map.of(
                        bytes("crash-key-" + version), bytes("crash-value-" + version)));
            }
            Runtime.getRuntime().halt(0);
        }
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
