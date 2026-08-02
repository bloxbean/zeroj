package com.bloxbean.cardano.zeroj.mpf.load;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

final class HeapSampler implements AutoCloseable {
    private final AtomicLong peakBytes = new AtomicLong();
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final Thread thread;

    HeapSampler() {
        sample();
        thread = Thread.ofPlatform().daemon().name("poseidon-mpf-heap-sampler").start(() -> {
            while (running.get()) {
                sample();
                try {
                    Thread.sleep(200L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        });
    }

    long peakBytes() {
        sample();
        return peakBytes.get();
    }

    private void sample() {
        Runtime runtime = Runtime.getRuntime();
        long used = runtime.totalMemory() - runtime.freeMemory();
        peakBytes.accumulateAndGet(used, Math::max);
    }

    @Override
    public void close() {
        running.set(false);
        thread.interrupt();
        sample();
    }
}
