package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.KDF;
import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Review F4: when HKDF fails part-way through the HPKE key schedule, every secret array ZeroJ
 * owns is still wiped.
 * <ul>
 *   <li>{@link Seam} fails a chosen derivation through {@link Hpke.Hkdf}, on any JDK.</li>
 *   <li>The JCA tests fail it inside a real provider, end to end through SealBase/OpenBase, and
 *       also check that the failure stays a platform fault ({@link IllegalStateException}), never
 *       an input failure. JDKs that accept only signed JCE providers (Oracle JDK and GraalVM)
 *       skip them; OpenJDK builds run them.</li>
 * </ul>
 * Tests in this module run sequentially, and the providers are restored afterwards.
 */
public class HpkeFailureWipeTest { // public: JCA instantiates the nested provider classes reflectively

    /**
     * The HKDF derivations of one SealBase, in order (RFC 9180 §4.1, §5.1): 1 eae_prk, 2
     * shared_secret, 3 psk_id_hash, 4 info_hash, 5 secret, 6 key, 7 base_nonce. 3 and 4 are public.
     */
    private static final String[] LABELS = {"eae_prk", "shared_secret", "psk_id_hash", "info_hash", "secret", "key", "base_nonce"};
    private static final boolean[] SECRET = {true, true, false, false, true, true, true};

    private static Provider real;

    /** Serves HKDF-SHA256 by delegating to SunJCE, failing at derivation {@link #failAt}. */
    public static final class FaultyKdfProvider extends Provider {
        public FaultyKdfProvider() {
            super("ZeroJFaultyKdf", "1", "HKDF fault injection for HpkeFailureWipeTest");
            put("KDF.HKDF-SHA256", FaultyKdf.class.getName());
        }
    }

    /** SunJCE without its KDF services, so a failing HKDF is not retried with SunJCE. */
    public static final class SunJceWithoutKdf extends Provider {
        public SunJceWithoutKdf() {
            super("SunJCE", "1", "SunJCE services except KDF");
            real.forEach((k, v) -> {
                String key = k.toString();
                if (!key.startsWith("KDF.") && !key.startsWith("Alg.Alias.KDF.")) put(k, v);
            });
        }
    }

    public static final class FaultyKdf extends KDFSpi {
        static final List<byte[]> returned = new ArrayList<>();
        static int calls;
        static int failAt;

        public FaultyKdf(KDFParameters parameters) throws InvalidAlgorithmParameterException {
            super(parameters);
        }

        @Override
        protected KDFParameters engineGetParameters() {
            return null;
        }

        @Override
        protected SecretKey engineDeriveKey(String algorithm, AlgorithmParameterSpec spec) throws NoSuchAlgorithmException {
            throw new NoSuchAlgorithmException("not used by Hpke");
        }

        @Override
        protected byte[] engineDeriveData(AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
            if (++calls == failAt) throw new ProviderException("injected HKDF failure at derivation " + calls);
            try {
                byte[] out = KDF.getInstance("HKDF-SHA256", real).deriveData(spec);
                returned.add(out);
                return out;
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private interface Body {
        void run() throws Exception;
    }

    /**
     * Runs {@code body} with the faulty KDF first. When a failure is injected, SunJCE's KDF is
     * hidden so JCA cannot retry with it; with none (the control), the real SunJCE stays for the
     * AEAD. The providers are restored afterwards.
     */
    private static void withFaultyKdf(int failAt, Body body) throws Exception {
        Provider[] all = Security.getProviders();
        int position = -1;
        for (int k = 0; k < all.length; k++) if (all[k].getName().equals("SunJCE")) position = k + 1;
        real = Security.getProvider("SunJCE");
        FaultyKdf.calls = 0;
        FaultyKdf.failAt = failAt;
        FaultyKdf.returned.clear();
        if (failAt != 0) {
            Security.removeProvider("SunJCE");
            Security.insertProviderAt(new SunJceWithoutKdf(), position);
        }
        Security.insertProviderAt(new FaultyKdfProvider(), 1);
        try {
            body.run();
        } finally {
            Security.removeProvider("ZeroJFaultyKdf");
            if (failAt != 0) {
                Security.removeProvider("SunJCE");
                Security.insertProviderAt(real, position);
            }
        }
        assertEquals(real, Security.getProvider("SunJCE"), "SunJCE restored");
    }

    private static void assertSecretsWiped(String when) {
        for (int j = 0; j < FaultyKdf.returned.size(); j++) {
            if (SECRET[j]) {
                assertTrue(X25519Bytes.isAllZero(FaultyKdf.returned.get(j)), LABELS[j] + " retained " + when);
            }
        }
    }

    /** An HKDF over the JDK one that fails at derivation {@code failAt} and records what it returns. */
    private static final class FailingHkdf implements Hpke.Hkdf {
        final List<byte[]> returned = new ArrayList<>();
        final int failAt;
        int calls;

        FailingHkdf(int failAt) {
            this.failAt = failAt;
        }

        private byte[] record(byte[] out) {
            returned.add(out);
            return out;
        }

        @Override
        public byte[] extract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
            if (++calls == failAt) throw new GeneralSecurityException("injected failure at derivation " + calls);
            return record(Hpke.JDK_HKDF.extract(salt, ikm));
        }

        @Override
        public byte[] expand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
            if (++calls == failAt) throw new GeneralSecurityException("injected failure at derivation " + calls);
            return record(Hpke.JDK_HKDF.expand(prk, info, length));
        }
    }

    @Nested
    @DisplayName("Through the Hkdf seam (any JDK)")
    class Seam {

        private final byte[] dh = DkgEncryptedHarness.testKey("wipe.dh");
        private final byte[] sharedSecret = DkgEncryptedHarness.testKey("wipe.shared");

        @Test
        @DisplayName("ExtractAndExpand: a failure expanding shared_secret still wipes eae_prk")
        void extractAndExpand() {
            FailingHkdf hkdf = new FailingHkdf(2);
            assertThrows(GeneralSecurityException.class, () -> Hpke.extractAndExpand(hkdf, dh, new byte[64]));
            assertEquals(1, hkdf.returned.size());
            assertTrue(X25519Bytes.isAllZero(hkdf.returned.get(0)), "eae_prk");
        }

        @Test
        @DisplayName("KeySchedule: a failure at key wipes secret; at base_nonce wipes secret and key")
        void keySchedule() {
            // Derivations: 1 psk_id_hash, 2 info_hash (both public), 3 secret, 4 key, 5 base_nonce.
            FailingHkdf atKey = new FailingHkdf(4);
            assertThrows(GeneralSecurityException.class, () -> Hpke.keySchedule(atKey, sharedSecret, new byte[]{1}));
            assertTrue(X25519Bytes.isAllZero(atKey.returned.get(2)), "secret");
            FailingHkdf atNonce = new FailingHkdf(5);
            assertThrows(GeneralSecurityException.class, () -> Hpke.keySchedule(atNonce, sharedSecret, new byte[]{1}));
            assertTrue(X25519Bytes.isAllZero(atNonce.returned.get(2)), "secret");
            assertTrue(X25519Bytes.isAllZero(atNonce.returned.get(3)), "key");
        }

        @Test
        @DisplayName("KeySchedule control: secret is wiped; key and base_nonce pass to the Context and are wiped by destroy()")
        void control() throws Exception {
            FailingHkdf none = new FailingHkdf(0);
            Hpke.Context context = Hpke.keySchedule(none, sharedSecret, new byte[]{1});
            assertEquals(5, none.returned.size());
            assertTrue(X25519Bytes.isAllZero(none.returned.get(2)), "secret");
            assertFalse(X25519Bytes.isAllZero(none.returned.get(3)), "key belongs to the live context");
            assertArrayEquals(Hpke.keySchedule(Hpke.JDK_HKDF, sharedSecret, new byte[]{1}).key(), context.key(),
                    "the seam computes what the JDK HKDF computes");
            context.destroy();
            assertTrue(X25519Bytes.isAllZero(none.returned.get(3)), "key after destroy");
            assertTrue(X25519Bytes.isAllZero(none.returned.get(4)), "base_nonce after destroy");
        }
    }

    /** Skips the JCA tests on JDKs that refuse unsigned JCE providers. */
    private static void assumeUnsignedProvidersAccepted() {
        boolean accepted;
        try {
            real = Security.getProvider("SunJCE");
            KDF.getInstance("HKDF-SHA256", new FaultyKdfProvider());
            accepted = true;
        } catch (SecurityException | NoSuchAlgorithmException refused) {
            accepted = false;
        }
        assumeTrue(accepted, "this JDK accepts only signed JCE providers");
    }

    @Test
    @DisplayName("SealBase: an HKDF failure after extraction, after key, or at base_nonce leaves no ZeroJ-owned secret unwiped, and stays a platform fault")
    void sealFailures() throws Exception {
        assumeUnsignedProvidersAccepted();
        byte[] skR = DkgEncryptedHarness.testKey("wipe.recipient");
        byte[] skE = DkgEncryptedHarness.testKey("wipe.ephemeral");
        byte[] pkR = X25519Bytes.publicFromPrivate(skR);
        for (int failAt : new int[]{2, 6, 7}) {
            withFaultyKdf(failAt, () -> {
                assertThrows(IllegalStateException.class,
                        () -> Hpke.sealBaseWithEphemeral(skE, pkR, new byte[]{1}, new byte[0], new byte[100]),
                        "a platform fault, never an input failure");
                assertEquals(failAt, FaultyKdf.calls, "the injected derivation was reached");
                assertEquals(failAt - 1, FaultyKdf.returned.size());
                assertSecretsWiped("after a failure at " + LABELS[failAt - 1]);
            });
        }
    }

    @Test
    @DisplayName("OpenBase: an HKDF failure at base_nonce leaves no ZeroJ-owned secret unwiped, and stays a platform fault")
    void openFailure() throws Exception {
        assumeUnsignedProvidersAccepted();
        byte[] skR = DkgEncryptedHarness.testKey("wipe.recipient");
        byte[] pkR = X25519Bytes.publicFromPrivate(skR);
        Hpke.Sealed sealed = Hpke.sealBaseWithEphemeral(DkgEncryptedHarness.testKey("wipe.ephemeral"), pkR,
                new byte[]{1}, new byte[0], new byte[100]);
        withFaultyKdf(7, () -> {
            assertThrows(IllegalStateException.class,
                    () -> Hpke.openBase(sealed.enc(), skR, pkR, new byte[]{1}, new byte[0], sealed.ct()));
            assertSecretsWiped("after a failed open");
        });
    }

    @Test
    @DisplayName("Control: with no failure, the round trip works through the delegating KDF and every secret is wiped afterwards")
    void jcaControl() throws Exception {
        assumeUnsignedProvidersAccepted();
        byte[] skR = DkgEncryptedHarness.testKey("wipe.recipient");
        byte[] pkR = X25519Bytes.publicFromPrivate(skR);
        withFaultyKdf(0, () -> {
            Hpke.Sealed sealed = Hpke.sealBaseWithEphemeral(DkgEncryptedHarness.testKey("wipe.ephemeral"), pkR,
                    new byte[]{1}, new byte[0], new byte[100]);
            assertEquals(7, FaultyKdf.returned.size(), "the faulty KDF served every derivation");
            assertSecretsWiped("after a successful seal");
            assertArrayEquals(new byte[100], Hpke.openBase(sealed.enc(), skR, pkR, new byte[]{1}, new byte[0], sealed.ct()));
        });
    }
}
