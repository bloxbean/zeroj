package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression guard for the invariants that ADR-0052 enforces by type rather than by a runtime
 * check (I2, I14, I16, and "a re-decoded ciphertext cannot be combined or decrypted"). If a
 * safe-layer type gains a public constructor, becomes a record, or a new public method turns
 * a raw ciphertext into an admitted one, these invariants could be bypassed without any other
 * test failing. The ADR-0046 API-surface test follows the same idea.
 */
class ElGamalApiSurfaceTest {

    private static final List<Class<?>> SAFE_TYPES = List.of(
            ElGamalCiphertext.class, VerifiedKeyShare.class, VerifiedDecryptionShare.class,
            ElGamalPublicKey.class, NOfNKeyContext.class, EncryptionStatement.class,
            DleqStatement.class, ElGamalEncryption.class, ElGamalSecretKey.class);

    @Test
    @DisplayName("Safe-layer types are final, not records, and expose no public or protected constructor")
    void noPublicConstructors() {
        for (Class<?> type : SAFE_TYPES) {
            assertTrue(Modifier.isFinal(type.getModifiers()), type + " must be final");
            assertFalse(type.isRecord(), type + " must not be a record (its canonical constructor is public)");
            for (Constructor<?> c : type.getDeclaredConstructors()) {
                int m = c.getModifiers();
                assertFalse(Modifier.isPublic(m) || Modifier.isProtected(m), "constructor " + c);
            }
        }
    }

    @Test
    @DisplayName("ElGamalKeyContext stays sealed to the library's context kinds")
    void contextSealed() {
        assertTrue(ElGamalKeyContext.class.isSealed());
        assertEquals(Set.of(NOfNKeyContext.class),
                Set.of(ElGamalKeyContext.class.getPermittedSubclasses()));
    }

    @Test
    @DisplayName("Only ElGamal.admit turns a raw ciphertext into an admitted one")
    void onlyAdmitAdmits() {
        List<String> found = new ArrayList<>();
        for (Class<?> type : List.of(ElGamal.class, ElGamalCiphertext.class, RawElGamalCiphertext.class,
                NOfNKeyContext.class)) {
            for (Method m : type.getDeclaredMethods()) {
                if (!Modifier.isPublic(m.getModifiers())) continue;
                boolean takesRaw = List.of(m.getParameterTypes()).contains(RawElGamalCiphertext.class);
                if (takesRaw && m.getReturnType() == ElGamalCiphertext.class) {
                    found.add(type.getSimpleName() + "." + m.getName());
                }
            }
        }
        assertEquals(List.of("ElGamal.admit"), found);
    }

    @Test
    @DisplayName("Possession, share and admission entry points require a verifier or a held secret")
    void entryPoints() {
        for (Method m : VerifiedKeyShare.class.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers()) && m.getReturnType() == VerifiedKeyShare.class) {
                List<Class<?>> params = List.of(m.getParameterTypes());
                assertTrue(params.contains(DleqStatementVerifier.class) || params.contains(ElGamalSecretKey.class),
                        "VerifiedKeyShare." + m.getName());
            }
        }
        for (Method m : VerifiedDecryptionShare.class.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers()) && m.getReturnType() == VerifiedDecryptionShare.class) {
                assertTrue(List.of(m.getParameterTypes()).contains(DleqStatementVerifier.class),
                        "VerifiedDecryptionShare." + m.getName());
            }
        }
    }
}
