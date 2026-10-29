package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.commitment.Commitment;

import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code commitment-profiles-v1} §12.2: closure properties of every new type and the exact public
 * surface ADR-0059 M1 adds. A failure here means an unreviewed API change.
 */
class CommitmentProfilesApiSurfaceTest {

    private static final List<Class<?>> NEW_TYPES = List.of(PedersenScalarCommitment.class, PedersenScalarOpening.class,
            PedersenBlinding.class, PedersenVectorBoundPolicy.class, PedersenVectorOpening.class);

    @Test
    @DisplayName("New types are final, not records, not Serializable, with no public or protected constructor")
    void closure() {
        for (Class<?> type : NEW_TYPES) {
            assertTrue(Modifier.isFinal(type.getModifiers()), type.toString());
            assertFalse(type.isRecord(), type.toString());
            assertFalse(Serializable.class.isAssignableFrom(type), type.toString());
            for (Constructor<?> c : type.getDeclaredConstructors()) {
                int m = c.getModifiers();
                assertFalse(Modifier.isPublic(m) || Modifier.isProtected(m), "constructor " + c);
            }
        }
        assertFalse(Modifier.isPublic(PedersenStrict.class.getModifiers()), "strict helpers stay package-private");
    }

    @Test
    @DisplayName("Opening holders (including the internal checked opening) do not override equals or hashCode and redact toString")
    void openingHolders() throws NoSuchMethodException {
        for (Class<?> type : List.of(PedersenScalarOpening.class, PedersenVectorOpening.class,
                PedersenVectorBoundPolicy.CheckedOpening.class)) {
            assertTrue(Modifier.isFinal(type.getModifiers()), type.toString());
            assertFalse(type.isRecord(), type.toString());
            assertFalse(Serializable.class.isAssignableFrom(type), type.toString());
            assertEquals(Object.class, type.getMethod("equals", Object.class).getDeclaringClass(), type + " equals");
            assertEquals(Object.class, type.getMethod("hashCode").getDeclaringClass(), type + " hashCode");
            assertEquals(type, type.getMethod("toString").getDeclaringClass(), type + " toString is redacted");
        }
        assertTrue(PedersenScalarOpening.of(BigInteger.TEN, BigInteger.TWO).toString().contains("redacted"));
    }

    @Test
    @DisplayName("The commitment types hold no scalar")
    void noScalarFields() {
        for (Class<?> type : List.of(PedersenScalarCommitment.class, PedersenBytesCommitment.class, PedersenVectorCommitment.class)) {
            assertTrue(Commitment.class.isAssignableFrom(type), type + " implements Commitment");
            for (Field f : type.getDeclaredFields()) {
                assertFalse(f.getType() == BigInteger.class, "no scalar is retained: " + f);
            }
        }
    }

    @Test
    @DisplayName("Public methods and fields of the new and changed types are exactly the reviewed sets")
    void exactSurface() {
        Map<Class<?>, Set<String>> expected = Map.of(
                PedersenScalarCommitment.class, Set.of("decode[byte[]]", "profile[]", "toPointBytes[]",
                        "add[PedersenScalarCommitment]", "subtract[PedersenScalarCommitment]", "negate[]",
                        "equals[Object]", "hashCode[]", "toString[]", "field PROFILE", "field CODEC"),
                PedersenScalarOpening.class, Set.of("of[BigInteger, BigInteger]", "decode[byte[]]", "encode[]",
                        "value[]", "blinding[]", "toString[]"),
                PedersenBlinding.class, Set.of("encode[BigInteger]", "decode[byte[]]"),
                PedersenVectorBoundPolicy.class, Set.of("schemaWidths[PedersenVectorSchema]",
                        "residueOnly[PedersenVectorSchema]", "widened[PedersenVectorSchema, int]", "schema[]", "toString[]"),
                PedersenVectorOpening.class, Set.of("of[PedersenVectorBoundPolicy, List, BigInteger]",
                        "decode[byte[], PedersenVectorBoundPolicy]", "encode[]", "values[]", "blinding[]", "policy[]",
                        "toString[]"),
                PedersenVectorCommitment.class, Set.of(
                        // unchanged legacy surface
                        "commit[PedersenVectorSchema, List, BigInteger]", "decode[PedersenVectorSchema, byte[]]",
                        "verify[List, BigInteger]", "add[PedersenVectorCommitment]", "subtract[PedersenVectorCommitment]",
                        "schema[]", "point[]", "toBytes[]",
                        // ADR-0059 M1
                        "profile[]", "toPointBytes[]", "codec[PedersenVectorSchema]",
                        "verifyOpening[List, BigInteger, PedersenVectorBoundPolicy]", "field PROFILE"));
        for (Map.Entry<Class<?>, Set<String>> e : expected.entrySet()) {
            assertEquals(new TreeSet<>(e.getValue()), surface(e.getKey()), e.getKey().getSimpleName());
        }
    }

    static Set<String> surface(Class<?> type) {
        Set<String> found = new TreeSet<>();
        for (Method m : type.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers()) && !m.isSynthetic() && !m.isBridge()) {
                found.add(m.getName() + List.of(m.getParameterTypes()).stream().map(Class::getSimpleName).toList());
            }
        }
        for (Field f : type.getDeclaredFields()) {
            if (Modifier.isPublic(f.getModifiers())) found.add("field " + f.getName());
        }
        return found;
    }
}
