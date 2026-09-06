package com.bloxbean.cardano.zeroj.examples.dsl.common;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SnarkjsProcessTest {
    @Test
    void processKeepingOutputOpenCannotBypassTimeout() throws Exception {
        String[] command = command("hang");
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            IOException error = assertThrows(IOException.class,
                    () -> SnarkjsProver.execute(null, 1, command));
            assertTrue(error.getMessage().contains("timed out"));
        });
    }

    @Test
    void outputLargerThanPipeBufferDoesNotDeadlockAndPreservesFailure() throws Exception {
        var result = SnarkjsProver.execute(null, 10, command("output"));
        assertEquals(7, result.exitCode());
        assertTrue(result.output().startsWith("x".repeat(200_000)));
        assertTrue(result.output().contains("diagnostic"));
    }

    private static String[] command(String mode) throws Exception {
        String java = ProcessHandle.current().info().command().orElseThrow();
        String classes = Path.of(Probe.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        return new String[]{java, "-cp", classes, Probe.class.getName(), mode};
    }

    public static class Probe {
        public static void main(String[] args) throws InterruptedException {
            if (args[0].equals("hang")) {
                Thread.sleep(30_000);
            } else {
                System.out.print("x".repeat(200_000));
                System.err.println("diagnostic");
                System.exit(7);
            }
        }
    }
}
