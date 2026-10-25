package org.zeroj.api.commitment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * ADR-0061 D7a / I13: the shared registry set seeded by {@link CommitmentProfile}, and the built-in
 * proof-protocol descriptor ({@code commitment-profiles-v1} §2.2, §2.3, §5).
 */
class ReservedIdentifiersTest {

    private static final String PROTOCOL_ID = "bulletproof-range-bls12-381-g1-v1";
    private static final String GENERATORS_ID = "bulletproof-bls12-381-g1-gens-v1";
    private static final List<String> BASIS_SETS = List.of("pedersen-jubjub-basis-v1",
            "pedersen-jubjub-vector-basis-v1", "pedersen-bls12-381-g1-basis-v1", GENERATORS_ID);
    private static final Pattern GRAMMAR = Pattern.compile("[a-z0-9]+(-[a-z0-9]+)*-v[1-9][0-9]*");

    @Test
    @DisplayName("The proof-protocol descriptor carries its identifier, consumed profile and generator set")
    void descriptor() {
        ProofProtocol p = ProofProtocols.BULLETPROOF_RANGE_BLS12_381_G1_V1;
        assertNotNull(p);
        assertEquals(PROTOCOL_ID, p.id().value());
        assertSame(CommitmentProfiles.PEDERSEN_BLS12_381_G1_V1, p.consumes());
        assertEquals(GENERATORS_ID, p.generatorSetId().value());
        assertSame(ProofProtocol.BULLETPROOF_RANGE_BLS12_381_G1_V1, p);
        assertTrue(p.toString().contains(PROTOCOL_ID));
    }

    @Test
    @DisplayName("define rejects the protocol, the generator set, every basis set and every reserved document name")
    void defineRejectsReserved() {
        List<String> ids = new ArrayList<>(BASIS_SETS);
        ids.add(PROTOCOL_ID);
        ids.addAll(reservedDocumentNames(registryText()));
        for (String id : ids) {
            for (CommitmentKind kind : CommitmentKind.values()) {
                for (CommitmentGroup group : CommitmentGroup.values()) {
                    CommitmentFormatException e = assertThrows(CommitmentFormatException.class,
                            () -> CommitmentProfile.define(CommitmentProfileId.of(id), kind, group, 48), id);
                    assertEquals(CommitmentError.INVALID_CONFIGURATION, e.reason(), id);
                }
            }
        }
    }

    @Test
    @DisplayName("The seeded set plus the built-in profiles equals the registry §2.3 table plus the §2.2 document names")
    void seededSetMatchesRegistry() {
        String text = registryText();
        Set<String> expected = new TreeSet<>(registryTable(text));
        expected.addAll(reservedDocumentNames(text));

        Set<String> seeded = new TreeSet<>();
        for (CommitmentProfileId id : CommitmentProfile.RESERVED) seeded.add(id.value());
        for (Field f : CommitmentProfiles.class.getDeclaredFields()) {
            if (f.getType() != CommitmentProfile.class) continue;
            try {
                assertTrue(seeded.add(((CommitmentProfile) f.get(null)).id().value()), "built-in also reserved: " + f);
            } catch (IllegalAccessException e) {
                throw new AssertionError(e);
            }
        }
        assertEquals(expected, seeded);
        assertTrue(CommitmentProfile.RESERVED.contains(ProofProtocols.BULLETPROOF_RANGE_BLS12_381_G1_V1.id()));
        assertTrue(CommitmentProfile.RESERVED.contains(ProofProtocols.BULLETPROOF_RANGE_BLS12_381_G1_V1.generatorSetId()));
    }

    @Test
    @DisplayName("ProofProtocols is a closed constant holder; ProofProtocol has no public constructor or factory")
    void holderSurface() {
        Class<?> holder = ProofProtocols.class;
        assertTrue(Modifier.isFinal(holder.getModifiers()));
        for (Constructor<?> c : holder.getDeclaredConstructors()) assertTrue(Modifier.isPrivate(c.getModifiers()));
        Set<String> fields = new TreeSet<>();
        for (Field f : holder.getDeclaredFields()) {
            if (f.isSynthetic()) continue;
            int m = f.getModifiers();
            assertTrue(Modifier.isPublic(m) && Modifier.isStatic(m) && Modifier.isFinal(m), f.toString());
            assertSame(ProofProtocol.class, f.getType(), f.toString());
            fields.add(f.getName());
        }
        assertEquals(Set.of("BULLETPROOF_RANGE_BLS12_381_G1_V1"), fields);
        for (Method m : holder.getDeclaredMethods()) assertFalse(Modifier.isPublic(m.getModifiers()), m.toString());

        assertTrue(Modifier.isFinal(ProofProtocol.class.getModifiers()));
        for (Constructor<?> c : ProofProtocol.class.getDeclaredConstructors()) {
            assertTrue(Modifier.isPrivate(c.getModifiers()), c.toString());
        }
        for (Field f : ProofProtocol.class.getDeclaredFields()) {
            assertFalse(Modifier.isPublic(f.getModifiers()), f.toString());
        }
    }

    @Test
    @DisplayName("Forked JVM: a define of the protocol and generator-set identifiers as the very first action fails, and the descriptor still loads")
    void forkedJvmCannotPreempt() throws IOException, InterruptedException {
        String java = ProcessHandle.current().info().command().orElseThrow();
        String classpath = System.getProperty("java.class.path");
        String output;
        int exitValue;
        // Output goes to a file, so the timeout applies even if the probe hangs.
        Path log = Files.createTempFile("zeroj-probe", ".log");
        try {
            Process process = new ProcessBuilder(java, "-cp", classpath, PreemptionProbe.class.getName())
                    .redirectErrorStream(true).redirectOutput(log.toFile()).start();
            if (!process.waitFor(60, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                fail("probe timed out: " + Files.readString(log, StandardCharsets.UTF_8));
            }
            output = Files.readString(log, StandardCharsets.UTF_8);
            exitValue = process.exitValue();
        } finally {
            Files.deleteIfExists(log);
        }
        assertEquals(0, exitValue, output);
        assertTrue(output.contains("protocol: INVALID_CONFIGURATION"), output);
        assertTrue(output.contains("generators: INVALID_CONFIGURATION"), output);
        assertTrue(output.contains("descriptor: " + PROTOCOL_ID + " " + GENERATORS_ID + " pedersen-bls12-381-g1-v1"),
                output);
    }

    /** The registry document named by the {@code zeroj.registry.spec} system property (build.gradle). */
    private static String registryText() {
        String path = System.getProperty("zeroj.registry.spec");
        assertNotNull(path, "zeroj.registry.spec is not set");
        try {
            return Files.readString(Path.of(path), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    /** First-column identifiers of the §2.3 registry table. */
    private static Set<String> registryTable(String text) {
        String section = between(text, "### 2.3 Registry", "### 2.4");
        Set<String> out = new TreeSet<>();
        // The table ends at the first blank line after its header.
        String table = section.substring(0, section.indexOf("\n\n", section.indexOf("| Identifier")));
        Matcher m = Pattern.compile("(?m)^\\| `([^`]+)` \\|").matcher(table);
        while (m.find()) out.add(m.group(1));
        assertTrue(out.size() >= 10, "parsed " + out);
        return out;
    }

    /** The reserved document names listed in §2.2. */
    private static Set<String> reservedDocumentNames(String text) {
        String section = between(text, "### 2.2 One namespace", "### 2.3");
        int start = section.indexOf("reserved and never admissible as registry entries:");
        assertTrue(start >= 0, "§2.2 reserved-name sentence not found");
        String paragraph = section.substring(start, section.indexOf("\n\n", start));
        Set<String> out = new TreeSet<>();
        Matcher m = Pattern.compile("`([^`]+)`").matcher(paragraph);
        while (m.find()) {
            if (GRAMMAR.matcher(m.group(1)).matches()) out.add(m.group(1));
        }
        assertTrue(out.size() >= 9, "parsed " + out);
        return out;
    }

    private static String between(String text, String from, String to) {
        int a = text.indexOf(from);
        int b = text.indexOf(to, a + from.length());
        assertTrue(a >= 0 && b > a, "section " + from + " not found");
        return text.substring(a, b);
    }

    /**
     * Run in a fresh JVM by {@link #forkedJvmCannotPreempt}. Its first action is a
     * {@link CommitmentProfile#define} of the protocol identifier: nothing in this JVM has touched
     * the registry before.
     */
    static final class PreemptionProbe {
        public static void main(String[] args) {
            System.out.println("protocol: " + attempt(PROTOCOL_ID));
            System.out.println("generators: " + attempt(GENERATORS_ID));
            ProofProtocol p = ProofProtocols.BULLETPROOF_RANGE_BLS12_381_G1_V1;
            System.out.println("descriptor: " + p.id() + " " + p.generatorSetId() + " " + p.consumes().id());
        }

        private static String attempt(String id) {
            try {
                CommitmentProfile.define(CommitmentProfileId.of(id), CommitmentKind.SCALAR,
                        CommitmentGroup.BLS12_381_G1, 48);
                return "DEFINED";
            } catch (CommitmentFormatException e) {
                return e.reason().name();
            }
        }
    }
}
