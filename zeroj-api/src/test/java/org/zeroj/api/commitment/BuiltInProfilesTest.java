package org.zeroj.api.commitment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ADR-0060 D8 / I8: built-in descriptors are owned by {@code zeroj-api} and cannot be pre-empted. */
class BuiltInProfilesTest {

    private static final String[][] BUILT_INS = {
            {"PEDERSEN_JUBJUB_V1", "pedersen-jubjub-v1", "SCALAR", "JUBJUB", "32"},
            {"PEDERSEN_JUBJUB_BYTES_V1", "pedersen-jubjub-bytes-v1", "BYTES", "JUBJUB", "32"},
            {"PEDERSEN_JUBJUB_VECTOR_V1", "pedersen-jubjub-vector-v1", "VECTOR", "JUBJUB", "32"},
            {"PEDERSEN_BLS12_381_G1_V1", "pedersen-bls12-381-g1-v1", "SCALAR", "BLS12_381_G1", "48"},
            {"PEDERSEN_BLS12_381_G1_BYTES_V1", "pedersen-bls12-381-g1-bytes-v1", "BYTES", "BLS12_381_G1", "48"},
    };

    @Test
    @DisplayName("Each built-in constant has its registry parameters and is one distinct descriptor")
    void parameters() throws ReflectiveOperationException {
        List<CommitmentProfile> seen = new ArrayList<>();
        for (String[] row : BUILT_INS) {
            CommitmentProfile p = (CommitmentProfile) CommitmentProfiles.class.getField(row[0]).get(null);
            assertEquals(row[1], p.id().value(), row[0]);
            assertEquals(CommitmentKind.valueOf(row[2]), p.kind(), row[0]);
            assertEquals(CommitmentGroup.valueOf(row[3]), p.group(), row[0]);
            assertEquals(Integer.parseInt(row[4]), p.pointEncodingLength(), row[0]);
            for (CommitmentProfile other : seen) assertNotSame(other, p);
            seen.add(p);
        }
    }

    @Test
    @DisplayName("define of every built-in identifier is rejected, whatever the other parameters")
    void defineOfBuiltInRejected() {
        for (String[] row : BUILT_INS) {
            for (CommitmentKind kind : CommitmentKind.values()) {
                for (CommitmentGroup group : CommitmentGroup.values()) {
                    CommitmentFormatException e = assertThrows(CommitmentFormatException.class,
                            () -> CommitmentProfile.define(CommitmentProfileId.of(row[1]), kind, group, 48));
                    assertEquals(CommitmentError.INVALID_CONFIGURATION, e.reason());
                }
            }
        }
    }

    @Test
    @DisplayName("CommitmentProfiles is a closed constant holder: exactly the five built-ins, nothing else")
    void holderSurface() {
        Class<?> type = CommitmentProfiles.class;
        assertTrue(Modifier.isFinal(type.getModifiers()));
        for (Constructor<?> c : type.getDeclaredConstructors()) assertTrue(Modifier.isPrivate(c.getModifiers()));
        Set<String> fields = new TreeSet<>();
        for (Field f : type.getDeclaredFields()) {
            if (f.isSynthetic()) continue;
            int m = f.getModifiers();
            assertTrue(Modifier.isPublic(m) && Modifier.isStatic(m) && Modifier.isFinal(m), f.toString());
            assertSame(CommitmentProfile.class, f.getType(), f.toString());
            fields.add(f.getName());
        }
        Set<String> expected = new TreeSet<>();
        for (String[] row : BUILT_INS) expected.add(row[0]);
        assertEquals(expected, fields);
        for (Method m : type.getDeclaredMethods()) assertFalse(Modifier.isPublic(m.getModifiers()), m.toString());
    }

    @Test
    @DisplayName("In a fresh class loader, a define of a built-in identifier as the very first call is rejected and the built-ins stay usable")
    void firstCallerCannotPreempt() throws Exception {
        URL apiClasses = CommitmentProfile.class.getProtectionDomain().getCodeSource().getLocation();
        try (URLClassLoader fresh = new URLClassLoader(new URL[] {apiClasses}, ClassLoader.getPlatformClassLoader())) {
            Class<?> profileType = Class.forName(CommitmentProfile.class.getName(), false, fresh);
            assertNotSame(CommitmentProfile.class, profileType, "the fresh loader defines its own copy");
            Class<?> idType = Class.forName(CommitmentProfileId.class.getName(), false, fresh);
            Class<?> kindType = Class.forName(CommitmentKind.class.getName(), false, fresh);
            Class<?> groupType = Class.forName(CommitmentGroup.class.getName(), false, fresh);
            Object id = idType.getMethod("of", String.class).invoke(null, "pedersen-jubjub-v1");
            Method define = profileType.getMethod("define", idType, kindType, groupType, int.class);

            // define is the first use of CommitmentProfile in this loader: its class initialisation,
            // which registers the built-ins, completes before the define body runs.
            InvocationTargetException e = assertThrows(InvocationTargetException.class, () -> define.invoke(null,
                    id, enumConstant(kindType, "SCALAR"), enumConstant(groupType, "JUBJUB"), 32));
            assertEquals(CommitmentFormatException.class.getName(), e.getCause().getClass().getName());
            assertTrue(e.getCause().getMessage().startsWith("INVALID_CONFIGURATION: "), e.getCause().getMessage());

            Class<?> holder = Class.forName(CommitmentProfiles.class.getName(), true, fresh);
            for (String[] row : BUILT_INS) {
                Object p = holder.getField(row[0]).get(null);
                assertInstanceOf(profileType, p);
                Object pid = profileType.getMethod("id").invoke(p);
                assertEquals(row[1], idType.getMethod("value").invoke(pid));
            }
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Object enumConstant(Class<?> type, String name) {
        return Enum.valueOf((Class) type, name);
    }
}
