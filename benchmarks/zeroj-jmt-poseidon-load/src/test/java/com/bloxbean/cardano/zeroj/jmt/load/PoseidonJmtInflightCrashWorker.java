package com.bloxbean.cardano.zeroj.jmt.load;

import com.bloxbean.cardano.vds.jmt.rocksdb.RocksDbJmtStore;
import com.bloxbean.cardano.vds.jmt.store.JmtStore;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtTree;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/** Child JVM whose parent kills it after a JMT commit enters the durable store boundary. */
public final class PoseidonJmtInflightCrashWorker {
    private PoseidonJmtInflightCrashWorker() {}

    public static void main(String[] arguments) throws Exception {
        Path database = Path.of(arguments[0]);
        Path commitMarker = Path.of(arguments[1]);
        int entries = Integer.parseInt(arguments[2]);
        JmtLoadOptions options = JmtLoadOptions.parse(new String[]{
                "--work-dir=" + database.resolveSibling("inflight-worker-options"), "--entries=1"});
        try (RocksDbJmtStore store = RocksDbJmtStore.open(
                database.toString(), options.storeOptions())) {
            JmtStore intercepted = (JmtStore) Proxy.newProxyInstance(
                    JmtStore.class.getClassLoader(), new Class<?>[]{JmtStore.class},
                    (proxy, method, args) -> {
                        Object result = invoke(store, method, args);
                        if (!method.getName().equals("beginCommit")) return result;
                        JmtStore.CommitBatch batch = (JmtStore.CommitBatch) result;
                        return Proxy.newProxyInstance(
                                JmtStore.CommitBatch.class.getClassLoader(),
                                new Class<?>[]{JmtStore.CommitBatch.class},
                                (batchProxy, batchMethod, batchArgs) -> {
                                    if (batchMethod.getName().equals("commit")) {
                                        Files.writeString(commitMarker, "commit-entered",
                                                StandardCharsets.US_ASCII);
                                        System.out.println("COMMIT_ENTERED");
                                        System.out.flush();
                                    }
                                    return invoke(batch, batchMethod, batchArgs);
                                });
                    });
            PoseidonJmtTree tree = new PoseidonJmtTree(intercepted);
            Map<byte[], byte[]> updates = new LinkedHashMap<>();
            for (int index = 0; index < entries; index++) {
                updates.put(bytes("inflight-key-" + index), bytes("inflight-value-" + index));
            }
            tree.put(2, updates);
        }
    }

    private static Object invoke(Object target, java.lang.reflect.Method method, Object[] arguments)
            throws Throwable {
        try {
            return method.invoke(target, arguments);
        } catch (InvocationTargetException error) {
            throw error.getCause();
        }
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
