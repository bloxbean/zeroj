package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0058 D3: the byte-commitment surface stays exactly as reviewed. The value type cannot be
 * constructed from a raw point except through the validating decoder, carries no arithmetic and
 * no opening, and the hash internals (including the cap seam) are not public.
 */
class PedersenBytesApiSurfaceTest {

    @Test
    @DisplayName("PedersenBytesCommitment is final, not a record, not Serializable, with no public constructor")
    void valueTypeIsClosed() {
        Class<?> type = PedersenBytesCommitment.class;
        assertTrue(Modifier.isFinal(type.getModifiers()));
        assertFalse(type.isRecord());
        assertFalse(Serializable.class.isAssignableFrom(type));
        for (Constructor<?> c : type.getDeclaredConstructors()) {
            int m = c.getModifiers();
            assertFalse(Modifier.isPublic(m) || Modifier.isProtected(m), "constructor " + c);
        }
    }

    @Test
    @DisplayName("PedersenBytesCommitment exposes only decode, profileId, toPointBytes and Object methods")
    void valueTypeMethods() {
        Set<String> publicMethods = new TreeSet<>();
        for (Method m : PedersenBytesCommitment.class.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers())) publicMethods.add(m.getName());
        }
        assertEquals(new TreeSet<>(Set.of("decode", "profileId", "toPointBytes", "equals", "hashCode", "toString")),
                publicMethods);
        for (Field f : PedersenBytesCommitment.class.getDeclaredFields()) {
            if (Modifier.isPublic(f.getModifiers())) {
                assertEquals("PROFILE_ID", f.getName());
            }
            assertFalse(f.getType() == BigInteger.class, "no scalar is retained: " + f);
        }
    }

    @Test
    @DisplayName("The hash mapper and its seams are package-private")
    void internalsArePackagePrivate() {
        Class<?> hash = PedersenBytesHash.class;
        assertFalse(Modifier.isPublic(hash.getModifiers()));
        assertTrue(Modifier.isFinal(hash.getModifiers()));
        for (Method m : hash.getDeclaredMethods()) {
            assertFalse(Modifier.isPublic(m.getModifiers()) || Modifier.isProtected(m.getModifiers()), m.toString());
        }
        for (Constructor<?> c : hash.getDeclaredConstructors()) {
            assertTrue(Modifier.isPrivate(c.getModifiers()), c.toString());
        }
    }

    @Test
    @DisplayName("PedersenCommitment's complete public surface is the reviewed set (no unreviewed additions)")
    void facadeCompleteSurface() {
        Set<String> found = new TreeSet<>();
        for (Method m : PedersenCommitment.class.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers())) {
                found.add(m.getName() + List.of(m.getParameterTypes()).stream().map(Class::getSimpleName).toList());
            }
        }
        for (Field f : PedersenCommitment.class.getDeclaredFields()) {
            if (Modifier.isPublic(f.getModifiers())) found.add("field " + f.getName());
        }
        assertEquals(new TreeSet<>(List.of(
                // pedersen-jubjub-v1 (unchanged)
                "commit[BigInteger, BigInteger]",
                "verify[JubjubPoint, BigInteger, BigInteger]",
                "randomBlinding[SecureRandom]",
                "decode[byte[]]",
                "field H", "field H_DOMAIN_TAG",
                // pedersen-jubjub-bytes-v1 (spec §6.2)
                "commitBytes[byte[], BigInteger]",
                "commitBytes[InputStream, long, BigInteger]",
                "commitBytesToEnd[InputStream, long, BigInteger]",
                "verifyBytes[PedersenBytesCommitment, byte[], BigInteger]",
                "verifyBytes[PedersenBytesCommitment, InputStream, long, BigInteger]",
                "verifyBytesToEnd[PedersenBytesCommitment, InputStream, long, BigInteger]")), found);
    }

    @Test
    @DisplayName("PedersenCommitment gains exactly the six reviewed byte entry points")
    void facadeAdditions() {
        List<String> byteMethods = new ArrayList<>();
        for (Method m : PedersenCommitment.class.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers()) && m.getName().contains("Bytes")) {
                byteMethods.add(m.getName() + List.of(m.getParameterTypes()).stream().map(Class::getSimpleName).toList());
            }
        }
        assertEquals(new TreeSet<>(List.of(
                "commitBytes[byte[], BigInteger]",
                "commitBytes[InputStream, long, BigInteger]",
                "commitBytesToEnd[InputStream, long, BigInteger]",
                "verifyBytes[PedersenBytesCommitment, byte[], BigInteger]",
                "verifyBytes[PedersenBytesCommitment, InputStream, long, BigInteger]",
                "verifyBytesToEnd[PedersenBytesCommitment, InputStream, long, BigInteger]")),
                new TreeSet<>(byteMethods));
    }
}
