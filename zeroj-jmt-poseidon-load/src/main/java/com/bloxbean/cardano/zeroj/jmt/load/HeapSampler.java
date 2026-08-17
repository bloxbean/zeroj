package com.bloxbean.cardano.zeroj.jmt.load;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

final class HeapSampler implements AutoCloseable {
    private static final long RSS_SAMPLE_INTERVAL_MILLIS = 1_000L;

    private final AtomicLong peakBytes = new AtomicLong();
    private final AtomicLong peakRssBytes = new AtomicLong();
    private final AtomicLong peakRssMinusUsedHeapBytes = new AtomicLong();
    private final AtomicLong rssSamples = new AtomicLong();
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final String rssSource = detectRssSource();
    private final Thread thread;

    HeapSampler() {
        sample(true);
        thread = Thread.ofPlatform().daemon().name("poseidon-jmt-heap-sampler").start(() -> {
            long lastRssSample = System.nanoTime();
            while (running.get()) {
                long now = System.nanoTime();
                boolean sampleRss = now - lastRssSample
                        >= Duration.ofMillis(RSS_SAMPLE_INTERVAL_MILLIS).toNanos();
                sample(sampleRss);
                if (sampleRss) lastRssSample = now;
                try {
                    Thread.sleep(200L);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        });
    }

    long peakBytes() {
        sample(false);
        return peakBytes.get();
    }

    long peakRssBytes() {
        sample(true);
        return peakRssBytes.get();
    }

    long peakRssMinusUsedHeapBytes() {
        sample(true);
        return peakRssMinusUsedHeapBytes.get();
    }

    long rssSamples() {
        return rssSamples.get();
    }

    String rssSource() {
        return rssSource;
    }

    private void sample(boolean includeRss) {
        Runtime runtime = Runtime.getRuntime();
        long heap = runtime.totalMemory() - runtime.freeMemory();
        peakBytes.accumulateAndGet(heap, Math::max);
        if (!includeRss) return;
        long rss = readRssBytes();
        if (rss <= 0) return;
        rssSamples.incrementAndGet();
        peakRssBytes.accumulateAndGet(rss, Math::max);
        peakRssMinusUsedHeapBytes.accumulateAndGet(Math.max(0L, rss - heap), Math::max);
    }

    private long readRssBytes() {
        if ("procfs-vmrss".equals(rssSource)) {
            try {
                for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
                    if (line.startsWith("VmRSS:")) {
                        String value = line.substring("VmRSS:".length()).trim().split("\\s+")[0];
                        return Math.multiplyExact(Long.parseLong(value), 1024L);
                    }
                }
            } catch (IOException | RuntimeException ignored) {
                return 0L;
            }
            return 0L;
        }
        if ("ps-rss".equals(rssSource)) {
            try {
                Process process = new ProcessBuilder(
                        "/bin/ps", "-o", "rss=", "-p",
                        Long.toString(ProcessHandle.current().pid())).start();
                if (!process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)
                        || process.exitValue() != 0) {
                    process.destroyForcibly();
                    return 0L;
                }
                String value = new String(process.getInputStream().readAllBytes(),
                        java.nio.charset.StandardCharsets.US_ASCII).trim();
                return value.isEmpty() ? 0L : Math.multiplyExact(Long.parseLong(value), 1024L);
            } catch (IOException | InterruptedException | RuntimeException ignored) {
                if (ignored instanceof InterruptedException) Thread.currentThread().interrupt();
                return 0L;
            }
        }
        return 0L;
    }

    private static String detectRssSource() {
        if (Files.isRegularFile(Path.of("/proc/self/status"))) return "procfs-vmrss";
        if (Files.isExecutable(Path.of("/bin/ps"))) return "ps-rss";
        return "unsupported";
    }

    @Override
    public void close() {
        running.set(false);
        thread.interrupt();
        sample(true);
    }
}
