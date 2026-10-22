package org.zeroj.bls12381.pedersen;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.commitment.Commitment;
import org.zeroj.bls12381.Bls12381Codecs;

import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code pedersen-bls12-381-g1-v1} §8 "The exact public surface": every public or protected field,
 * method and constructor of the five public types, the closure properties of those types, the
 * absence of any other public type in the package, and the two additions to {@link Bls12381Codecs}.
 */
class G1PedersenApiSurfaceTest {

    private static final String PACKAGE = "org.zeroj.bls12381.pedersen";

    private static final Map<Class<?>, Set<String>> ALLOWLIST = Map.of(
            G1PedersenCommitment.class, Set.of(
                    "field static final CommitmentProfile PROFILE",
                    "field static final CommitmentCodec<G1PedersenCommitment> CODEC",
                    "static G1PedersenCommitment decode(byte[])",
                    "CommitmentProfile profile()",
                    "byte[] toPointBytes()",
                    "G1PedersenCommitment add(G1PedersenCommitment)",
                    "G1PedersenCommitment subtract(G1PedersenCommitment)",
                    "G1PedersenCommitment negate()",
                    "G1PedersenCommitment withPublicDelta(BigInteger, int)",
                    "boolean equals(Object)",
                    "int hashCode()",
                    "String toString()"),
            G1PedersenBytesCommitment.class, Set.of(
                    "field static final CommitmentProfile PROFILE",
                    "field static final CommitmentCodec<G1PedersenBytesCommitment> CODEC",
                    "static G1PedersenBytesCommitment decode(byte[])",
                    "CommitmentProfile profile()",
                    "byte[] toPointBytes()",
                    "boolean equals(Object)",
                    "int hashCode()",
                    "String toString()"),
            G1PedersenOpening.class, Set.of(
                    "static G1PedersenOpening of(BigInteger, BigInteger)",
                    "static G1PedersenOpening decode(byte[])",
                    "byte[] encode()",
                    "BigInteger value()",
                    "BigInteger blinding()",
                    "String toString()"),
            G1PedersenBlinding.class, Set.of(
                    "static byte[] encode(BigInteger)",
                    "static BigInteger decode(byte[])"),
            G1Pedersen.class, Set.of(
                    "static G1Pedersen pureJava()",
                    "static G1Pedersen withProvider(Bls12381Provider)",
                    "Bls12381Provider provider()",
                    "boolean supportsGeneration()",
                    "static BigInteger randomBlinding(SecureRandom)",
                    "G1PedersenCommitment commitScalar(BigInteger, BigInteger)",
                    "boolean verifyScalar(G1PedersenCommitment, BigInteger, BigInteger)",
                    "boolean verifyScalar(G1PedersenCommitment, BigInteger, BigInteger, int)",
                    "G1PedersenBytesCommitment commitBytes(byte[], BigInteger)",
                    "G1PedersenBytesCommitment commitBytes(InputStream, long, BigInteger) throws IOException",
                    "G1PedersenBytesCommitment commitBytesToEnd(InputStream, long, BigInteger) throws IOException",
                    "boolean verifyBytes(G1PedersenBytesCommitment, byte[], BigInteger)",
                    "boolean verifyBytes(G1PedersenBytesCommitment, InputStream, long, BigInteger) throws IOException",
                    "boolean verifyBytesToEnd(G1PedersenBytesCommitment, InputStream, long, BigInteger) throws IOException"));

    @Test
    @DisplayName("Each public type's public/protected fields, methods and constructors are exactly the §8 allowlist")
    void exactMembers() {
        for (Map.Entry<Class<?>, Set<String>> entry : ALLOWLIST.entrySet()) {
            assertEquals(new TreeSet<>(entry.getValue()), exposed(entry.getKey()), entry.getKey().getSimpleName());
        }
    }

    @Test
    @DisplayName("All five types are final, not records, not Serializable, with no public or protected constructor")
    void typesAreClosed() {
        for (Class<?> type : ALLOWLIST.keySet()) {
            assertTrue(Modifier.isPublic(type.getModifiers()), type.getName());
            assertTrue(Modifier.isFinal(type.getModifiers()), type.getName());
            assertFalse(type.isRecord(), type.getName());
            assertFalse(Serializable.class.isAssignableFrom(type), type.getName());
            for (Constructor<?> c : type.getDeclaredConstructors()) {
                assertFalse(isExposed(c), c.toString());
            }
        }
        assertTrue(Commitment.class.isAssignableFrom(G1PedersenCommitment.class));
        assertTrue(Commitment.class.isAssignableFrom(G1PedersenBytesCommitment.class));
    }

    @Test
    @DisplayName("Opening holders do not override equals or hashCode")
    void openingHoldersHaveIdentityEquality() {
        for (Class<?> type : List.of(G1PedersenOpening.class, G1PedersenBlinding.class)) {
            assertThrows(NoSuchMethodException.class, () -> type.getDeclaredMethod("equals", Object.class), type.getName());
            assertThrows(NoSuchMethodException.class, () -> type.getDeclaredMethod("hashCode"), type.getName());
        }
    }

    @Test
    @DisplayName("Commitments hold only the validated point and its encoding; the opening holds only its two scalars")
    void instanceState() {
        for (Class<?> type : List.of(G1PedersenCommitment.class, G1PedersenBytesCommitment.class)) {
            assertEquals(Set.of("private final G1Point point", "private final byte[] encoding"), instanceFields(type), type.getName());
        }
        assertEquals(Set.of("private final BigInteger value", "private final BigInteger blinding"),
                instanceFields(G1PedersenOpening.class));
        assertEquals(Set.of(), instanceFields(G1PedersenBlinding.class));
        assertEquals(Set.of("private final Bls12381Provider provider", "private final boolean generation"),
                instanceFields(G1Pedersen.class));
    }

    @Test
    @DisplayName("No other public or protected type exists in the package (compiled classes scanned)")
    void noOtherPublicTypes() throws Exception {
        List<String> names = compiledClassNames();
        assertTrue(names.containsAll(ALLOWLIST.keySet().stream().map(Class::getName).toList()), names.toString());
        assertTrue(names.containsAll(List.of(PACKAGE + ".G1PedersenStrict", PACKAGE + ".G1PedersenBases",
                PACKAGE + ".G1PedersenBytesHash")), "the scan must see the package-private classes: " + names);
        Set<String> exposedTypes = new TreeSet<>();
        for (String name : names) {
            Class<?> type = Class.forName(name, false, G1Pedersen.class.getClassLoader());
            if (Modifier.isPublic(type.getModifiers()) || Modifier.isProtected(type.getModifiers())) {
                exposedTypes.add(type.getName());
            }
        }
        assertEquals(ALLOWLIST.keySet().stream().map(Class::getName).collect(Collectors.toCollection(TreeSet::new)),
                exposedTypes);
    }

    @Test
    @DisplayName("Bls12381Codecs gained exactly scalarFromBigEndian32 and scalarToBigEndian32")
    void codecAdditions() {
        Set<String> baseline = Set.of(
                "field static final int FP_BYTES",
                "field static final int SCALAR_BYTES",
                "field static final int G1_COMPRESSED_BYTES",
                "field static final int G2_COMPRESSED_BYTES",
                "field static final int G1_UNCOMPRESSED_BYTES",
                "field static final int G2_UNCOMPRESSED_BYTES",
                "static byte[] scalarToLittleEndian32(BigInteger)",
                "static byte[] scalarToLittleEndian32Reduced(BigInteger)",
                "static byte[] g1ToUncompressed(G1Point)",
                "static byte[] g1ToCompressed(G1Point)",
                "static G1Point g1FromUncompressed(byte[])",
                "static G1Point g1FromCompressed(byte[])",
                "static G1Point g1FromCompressedUnchecked(byte[])",
                "static G1Point g1FromUncompressedUnchecked(byte[])",
                "static byte[] g2ToUncompressed(G2Point)",
                "static byte[] g2ToCompressed(G2Point)",
                "static G2Point g2FromUncompressed(byte[])",
                "static G2Point g2FromCompressed(byte[])",
                "static G2Point g2FromCompressedUnchecked(byte[])",
                "static G2Point g2FromUncompressedUnchecked(byte[])",
                "static G1Point requireValid(G1Point)",
                "static G2Point requireValid(G2Point)");
        Set<String> added = Set.of(
                "static BigInteger scalarFromBigEndian32(byte[])",
                "static byte[] scalarToBigEndian32(BigInteger)");
        Set<String> expected = new TreeSet<>(baseline);
        expected.addAll(added);
        assertEquals(expected, exposed(Bls12381Codecs.class));
    }

    // ---- helpers ----

    private static boolean isExposed(Member member) {
        return Modifier.isPublic(member.getModifiers()) || Modifier.isProtected(member.getModifiers());
    }

    /** Public and protected declared members, excluding synthetic and bridge methods. */
    private static Set<String> exposed(Class<?> type) {
        Set<String> out = new TreeSet<>();
        for (Field f : type.getDeclaredFields()) {
            if (isExposed(f) && !f.isSynthetic()) {
                out.add("field " + access(f) + modifiers(f) + simpleGeneric(f.getGenericType().getTypeName()) + " " + f.getName());
            }
        }
        for (Method m : type.getDeclaredMethods()) {
            if (isExposed(m) && !m.isSynthetic() && !m.isBridge()) {
                String params = Arrays.stream(m.getParameterTypes()).map(Class::getSimpleName).collect(Collectors.joining(", "));
                String exceptions = Arrays.stream(m.getExceptionTypes()).map(Class::getSimpleName).collect(Collectors.joining(", "));
                out.add(access(m) + (Modifier.isStatic(m.getModifiers()) ? "static " : "")
                        + m.getReturnType().getSimpleName() + " " + m.getName() + "(" + params + ")"
                        + (exceptions.isEmpty() ? "" : " throws " + exceptions));
            }
        }
        for (Constructor<?> c : type.getDeclaredConstructors()) {
            if (isExposed(c) && !c.isSynthetic()) {
                out.add("constructor " + c);
            }
        }
        return out;
    }

    private static String access(Member member) {
        return Modifier.isProtected(member.getModifiers()) ? "protected " : "";
    }

    private static String modifiers(Field f) {
        int m = f.getModifiers();
        return (Modifier.isStatic(m) ? "static " : "") + (Modifier.isFinal(m) ? "final " : "");
    }

    private static String simpleGeneric(String typeName) {
        return typeName.replaceAll("[a-zA-Z0-9_]+\\.", "");
    }

    private static Set<String> instanceFields(Class<?> type) {
        Set<String> out = new TreeSet<>();
        for (Field f : type.getDeclaredFields()) {
            if (!Modifier.isStatic(f.getModifiers()) && !f.isSynthetic()) {
                out.add(Modifier.toString(f.getModifiers()) + " " + f.getType().getSimpleName() + " " + f.getName());
            }
        }
        return out;
    }

    /** Binary names of every class compiled into the package, from a classes directory or a jar. */
    private static List<String> compiledClassNames() throws IOException, URISyntaxException {
        Path location = Path.of(G1Pedersen.class.getProtectionDomain().getCodeSource().getLocation().toURI());
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
