package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.commitment.CommitmentProfile;
import org.zeroj.api.commitment.CommitmentProfiles;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0060 D8 / I8 / I9: the Jubjub {@code PROFILE} constants are the {@code zeroj-api} built-ins,
 * and defining a built-in identifier before any profile class loads cannot disable them (#99).
 */
class BuiltInProfileAliasTest {

    private static final String[][] ALIASES = {
            {PedersenScalarCommitment.class.getName(), "PEDERSEN_JUBJUB_V1"},
            {PedersenBytesCommitment.class.getName(), "PEDERSEN_JUBJUB_BYTES_V1"},
            {PedersenVectorCommitment.class.getName(), "PEDERSEN_JUBJUB_VECTOR_V1"},
    };

    @Test
    @DisplayName("Each Jubjub PROFILE is the same instance as its CommitmentProfiles constant")
    void aliases() {
        assertSame(CommitmentProfiles.PEDERSEN_JUBJUB_V1, PedersenScalarCommitment.PROFILE);
        assertSame(CommitmentProfiles.PEDERSEN_JUBJUB_BYTES_V1, PedersenBytesCommitment.PROFILE);
        assertSame(CommitmentProfiles.PEDERSEN_JUBJUB_VECTOR_V1, PedersenVectorCommitment.PROFILE);
        assertSame(PedersenScalarCommitment.PROFILE, PedersenScalarCommitment.CODEC.profile());
        assertSame(PedersenBytesCommitment.PROFILE, PedersenBytesCommitment.CODEC.profile());
        assertEquals(JubjubCurve.COMPRESSED_POINT_BYTES, PedersenScalarCommitment.PROFILE.pointEncodingLength());
        assertEquals(JubjubCurve.COMPRESSED_POINT_BYTES, PedersenBytesCommitment.PROFILE.pointEncodingLength());
        assertEquals(JubjubCurve.COMPRESSED_POINT_BYTES, PedersenVectorCommitment.PROFILE.pointEncodingLength());
    }

    @Test
    @DisplayName("#99 regression: define(pedersen-jubjub-v1) before any profile class loads is rejected, and every Jubjub profile still loads")
    void defineFirstCannotDisableProfiles() throws Exception {
        try (URLClassLoader fresh = new URLClassLoader(testClasspath(), ClassLoader.getPlatformClassLoader())) {
            Class<?> profileType = Class.forName(CommitmentProfile.class.getName(), false, fresh);
            assertNotSame(CommitmentProfile.class, profileType, "the fresh loader defines its own zeroj-api copy");
            Class<?> idType = Class.forName("org.zeroj.api.commitment.CommitmentProfileId", false, fresh);
            Class<?> kindType = Class.forName("org.zeroj.api.commitment.CommitmentKind", false, fresh);
            Class<?> groupType = Class.forName("org.zeroj.api.commitment.CommitmentGroup", false, fresh);
            Method define = profileType.getMethod("define", idType, kindType, groupType, int.class);
            for (String id : List.of("pedersen-jubjub-v1", "pedersen-jubjub-bytes-v1", "pedersen-jubjub-vector-v1")) {
                Object profileId = idType.getMethod("of", String.class).invoke(null, id);
                InvocationTargetException e = assertThrows(InvocationTargetException.class, () -> define.invoke(null,
                        profileId, enumConstant(kindType, "SCALAR"), enumConstant(groupType, "JUBJUB"), 32));
                assertEquals("org.zeroj.api.commitment.CommitmentFormatException", e.getCause().getClass().getName());
            }

            Class<?> holder = Class.forName(CommitmentProfiles.class.getName(), true, fresh);
            for (String[] alias : ALIASES) {
                // Initialising the profile class must succeed (before #99 it threw ExceptionInInitializerError).
                Class<?> type = Class.forName(alias[0], true, fresh);
                assertSame(holder.getField(alias[1]).get(null), type.getField("PROFILE").get(null), alias[0]);
            }
        }
    }

    private static URL[] testClasspath() throws Exception {
        List<URL> urls = new ArrayList<>();
        for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
            if (!entry.isEmpty()) urls.add(new File(entry).toURI().toURL());
        }
        assertTrue(urls.size() > 1, "test runtime classpath is visible");
        return urls.toArray(URL[]::new);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Object enumConstant(Class<?> type, String name) {
        return Enum.valueOf((Class) type, name);
    }
}
