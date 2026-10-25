package org.zeroj.bls12381.bulletproofs;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 D6/D7, spec §7.5: the exact public surface of {@code org.zeroj.bls12381.bulletproofs}, and
 * the rule that no public or protected member of any class compiled into the package (nested types
 * included) accepts a seed, a nonce, a nonce source or a random source.
 */
class BulletproofApiSurfaceTest {

    private static final String PACKAGE = "org.zeroj.bls12381.bulletproofs";

    private static final Map<Class<?>, Set<String>> ALLOWLIST = Map.of(
            G1RangeProof.class, Set.of(
                    "field static final ProofProtocol PROTOCOL",
                    "static int length(int)",
                    "static G1RangeProof decode(byte[], int)",
                    "int bits()",
                    "byte[] toBytes()",
                    "boolean equals(Object)",
                    "int hashCode()",
                    "String toString()"),
            G1RangeProver.class, Set.of(
                    "static G1RangeProver pureJava()",
                    "static G1RangeProver withProvider(Bls12381Provider)",
                    "Bls12381Provider provider()",
                    "boolean supportsProving()",
                    "G1RangeProof prove(G1PedersenOpening, int, byte[])"),
            G1RangeVerifier.class, Set.of(
                    "static G1RangeVerifier pureJava()",
                    "static G1RangeVerifier withProvider(Bls12381Provider)",
                    "Bls12381Provider provider()",
                    "boolean verify(G1PedersenCommitment, G1RangeProof, int, byte[])",
                    "boolean verify(G1PedersenCommitment, byte[], int, byte[])",
                    "boolean verify(byte[], byte[], int, byte[])"));

    /** Parameter types that would let a caller choose nonces or randomness. */
    private static final Set<Class<?>> FORBIDDEN = Set.of(SecureRandom.class, Random.class, NonceSource.class,
            SystemNonceSource.class);

    @Test
    @DisplayName("Each public type's public/protected members are exactly the reviewed allowlist")
    void exactMembers() {
        for (Map.Entry<Class<?>, Set<String>> e : ALLOWLIST.entrySet()) {
            assertEquals(new TreeSet<>(e.getValue()), exposed(e.getKey()), e.getKey().getSimpleName());
        }
    }

    @Test
    @DisplayName("The three public types are final, not records, not Serializable, with no public or protected constructor")
    void typesAreClosed() {
        for (Class<?> type : ALLOWLIST.keySet()) {
            assertTrue(Modifier.isFinal(type.getModifiers()), type.getName());
            assertFalse(type.isRecord(), type.getName());
            assertFalse(Serializable.class.isAssignableFrom(type), type.getName());
            for (Constructor<?> c : type.getDeclaredConstructors()) assertFalse(isExposed(c), c.toString());
        }
    }

    @Test
    @DisplayName("No other public or protected type exists in the package, nested types included (compiled classes scanned)")
    void noOtherPublicTypes() throws Exception {
        List<String> names = compiledClassNames();
        assertTrue(names.containsAll(List.of(PACKAGE + ".NonceSource", PACKAGE + ".SystemNonceSource",
                PACKAGE + ".RangeTranscript", PACKAGE + ".G1RangeProver$ChallengeTap")), names.toString());
        assertFalse(names.contains(PACKAGE + ".TestNonceProver"), "the test-nonce prover must not be in the main output");
        Set<String> exposedTypes = new TreeSet<>();
        for (String name : names) {
            Class<?> type = Class.forName(name, false, G1RangeProver.class.getClassLoader());
            if (Modifier.isPublic(type.getModifiers()) || Modifier.isProtected(type.getModifiers())) {
                exposedTypes.add(type.getName());
            }
        }
        assertEquals(ALLOWLIST.keySet().stream().map(Class::getName).collect(Collectors.toCollection(TreeSet::new)),
                exposedTypes);
    }

    @Test
    @DisplayName("No public or protected member of any class in the package accepts a nonce source or a random source")
    void noNonceOrRandomParameters() throws Exception {
        for (String name : compiledClassNames()) {
            Class<?> type = Class.forName(name, false, G1RangeProver.class.getClassLoader());
            List<Executable> members = new ArrayList<>(Arrays.asList(type.getDeclaredMethods()));
            members.addAll(Arrays.asList(type.getDeclaredConstructors()));
            for (Executable m : members) {
                if (!isExposed(m) || m.isSynthetic()) continue;
                for (Class<?> p : m.getParameterTypes()) {
                    assertFalse(FORBIDDEN.contains(p), m.toString());
                }
            }
        }
        // Every public way into proving takes exactly an opening, a width and a context: no seed or
        // nonce octets can travel in it.
        for (Method m : G1RangeProver.class.getDeclaredMethods()) {
            if (isExposed(m) && m.getName().equals("prove")) {
                assertEquals("[class org.zeroj.bls12381.pedersen.G1PedersenOpening, int, class [B]",
                        Arrays.toString(m.getParameterTypes()));
            }
        }
    }

    @Test
    @DisplayName("The test-nonce prover is compiled into the testFixtures output, not the main classes")
    void seamIsFenced() throws URISyntaxException {
        Path main = Path.of(G1RangeProver.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        Path fixtures = Path.of(TestNonceProver.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        assertNotEquals(main, fixtures);
        // build/classes/java/testFixtures, or the …-test-fixtures.jar when the build uses jars.
        assertTrue(fixtures.toString().contains("testFixtures") || fixtures.toString().contains("test-fixtures"),
                fixtures.toString());
    }

    // ---- helpers (as in G1PedersenApiSurfaceTest) ----

    private static boolean isExposed(Member member) {
        return Modifier.isPublic(member.getModifiers()) || Modifier.isProtected(member.getModifiers());
    }

    private static Set<String> exposed(Class<?> type) {
        Set<String> out = new TreeSet<>();
        for (Field f : type.getDeclaredFields()) {
            if (isExposed(f) && !f.isSynthetic()) {
                int m = f.getModifiers();
                out.add("field " + (Modifier.isStatic(m) ? "static " : "") + (Modifier.isFinal(m) ? "final " : "")
                        + f.getType().getSimpleName() + " " + f.getName());
            }
        }
        for (Method m : type.getDeclaredMethods()) {
            if (isExposed(m) && !m.isSynthetic() && !m.isBridge()) {
                String params = Arrays.stream(m.getParameterTypes()).map(Class::getSimpleName).collect(Collectors.joining(", "));
                out.add((Modifier.isStatic(m.getModifiers()) ? "static " : "") + m.getReturnType().getSimpleName() + " "
                        + m.getName() + "(" + params + ")");
            }
        }
        for (Constructor<?> c : type.getDeclaredConstructors()) {
            if (isExposed(c) && !c.isSynthetic()) out.add("constructor " + c);
        }
        return out;
    }

    private static List<String> compiledClassNames() throws IOException, URISyntaxException {
        Path location = Path.of(G1RangeProver.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        String dir = PACKAGE.replace('.', '/');
        List<String> names = new ArrayList<>();
        if (Files.isDirectory(location)) {
            try (Stream<Path> files = Files.list(location.resolve(dir))) {
                files.map(p -> p.getFileName().toString()).filter(n -> n.endsWith(".class"))
                        .forEach(n -> names.add(PACKAGE + "." + n.substring(0, n.length() - ".class".length())));
            }
        } else {
            try (JarFile jar = new JarFile(location.toFile())) {
                Enumeration<JarEntry> entries = jar.entries();
                while (entries.hasMoreElements()) {
                    String n = entries.nextElement().getName();
                    if (n.startsWith(dir + "/") && n.endsWith(".class") && n.indexOf('/', dir.length() + 1) < 0) {
                        names.add(n.substring(0, n.length() - ".class".length()).replace('/', '.'));
                    }
                }
            }
        }
        names.removeIf(n -> n.endsWith(".package-info"));
        return names;
    }
}
