package org.zeroj.api.commitment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code commitment-profiles-v1} §12.1 closure rules for the shared contract types. */
class CommitmentApiSurfaceTest {

    private static final List<Class<?>> VALUE_TYPES = List.of(CommitmentProfileId.class, CommitmentProfile.class,
            CommitmentProfiles.class,
            CommitmentEnvelope.class, CommitmentKey.class, CommitmentCheck.class, CommitmentAcceptance.class);

    @Test
    @DisplayName("Value, key, profile and result types are final, not records, not Serializable, with no public constructor")
    void closedTypes() {
        for (Class<?> type : VALUE_TYPES) {
            assertTrue(Modifier.isFinal(type.getModifiers()), type + " is final");
            assertFalse(type.isRecord(), type + " is not a record");
            assertFalse(Serializable.class.isAssignableFrom(type), type + " is not Serializable");
            for (Constructor<?> c : type.getDeclaredConstructors()) {
                int m = c.getModifiers();
                assertFalse(Modifier.isPublic(m) || Modifier.isProtected(m), "constructor " + c);
            }
        }
        assertTrue(Modifier.isFinal(CommitmentFormatException.class.getModifiers()));
        assertTrue(IllegalArgumentException.class.isAssignableFrom(CommitmentFormatException.class));
    }

    @Test
    @DisplayName("CommitmentCheck has no public static method: no caller can fabricate an accepted result")
    void checkHasNoFactory() {
        Set<String> statics = new TreeSet<>();
        Set<String> publics = new TreeSet<>();
        for (Method m : CommitmentCheck.class.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers())) {
                publics.add(m.getName());
                if (Modifier.isStatic(m.getModifiers())) statics.add(m.getName());
            }
        }
        assertEquals(Set.of(), statics);
        assertEquals(new TreeSet<>(Set.of("accepted", "reason", "policyRejected", "toString")), publics);
    }

    @Test
    @DisplayName("The commitment interface carries no arithmetic and no equality contract")
    void commitmentInterface() {
        Set<String> methods = new TreeSet<>();
        for (Method m : Commitment.class.getDeclaredMethods()) methods.add(m.getName());
        assertEquals(new TreeSet<>(Set.of("profile", "toPointBytes")), methods);
    }

    @Test
    @DisplayName("Public static entry points are exactly the reviewed set")
    void entryPoints() {
        assertEquals(Set.of("of"), publicStatics(CommitmentProfileId.class));
        assertEquals(Set.of("define"), publicStatics(CommitmentProfile.class));
        assertEquals(new TreeSet<>(Set.of("encode", "decode")), publicStatics(CommitmentEnvelope.class));
        assertEquals(Set.of("of"), publicStatics(CommitmentKey.class));
        assertEquals(Set.of("accept"), publicStatics(CommitmentAcceptance.class));
    }

    private static Set<String> publicStatics(Class<?> type) {
        Set<String> out = new TreeSet<>();
        for (Method m : type.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers()) && Modifier.isStatic(m.getModifiers())) out.add(m.getName());
        }
        return out;
    }
}
