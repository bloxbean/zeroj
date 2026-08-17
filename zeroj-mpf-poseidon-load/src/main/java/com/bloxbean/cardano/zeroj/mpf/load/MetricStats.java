package com.bloxbean.cardano.zeroj.mpf.load;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class MetricStats {
    private MetricStats() {}

    static Map<String, Double> nanos(List<Long> values) {
        var sorted = new ArrayList<>(values);
        sorted.sort(Long::compareTo);
        Map<String, Double> out = new LinkedHashMap<>();
        out.put("minMs", millis(sorted.getFirst()));
        out.put("medianMs", millis(quantile(sorted, 0.50)));
        out.put("p95Ms", millis(quantile(sorted, 0.95)));
        out.put("p99Ms", millis(quantile(sorted, 0.99)));
        out.put("maxMs", millis(sorted.getLast()));
        return Map.copyOf(out);
    }

    static Map<String, Double> integers(List<Integer> values) {
        var sorted = new ArrayList<>(values);
        sorted.sort(Integer::compareTo);
        Map<String, Double> out = new LinkedHashMap<>();
        out.put("min", sorted.getFirst().doubleValue());
        out.put("median", (double) quantileInts(sorted, 0.50));
        out.put("p95", (double) quantileInts(sorted, 0.95));
        out.put("p99", (double) quantileInts(sorted, 0.99));
        out.put("max", sorted.getLast().doubleValue());
        return Map.copyOf(out);
    }

    private static long quantile(List<Long> sorted, double percentile) {
        return sorted.get(index(sorted.size(), percentile));
    }

    private static int quantileInts(List<Integer> sorted, double percentile) {
        return sorted.get(index(sorted.size(), percentile));
    }

    private static int index(int size, double percentile) {
        return Math.min(size - 1, Math.max(0, (int) Math.ceil(percentile * size) - 1));
    }

    private static double millis(long nanos) {
        return nanos / 1_000_000.0;
    }
}
