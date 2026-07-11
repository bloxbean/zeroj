package com.bloxbean.cardano.zeroj.circuit.lib.ed25519;

import com.bloxbean.cardano.client.crypto.bip32.HdKeyGenerator;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Correctness tests for {@link Bip32Ed25519}, cross-checked against cardano-client-lib's
 * {@code HdKeyGenerator.getChildKeyPair} (the reference CIP-1852 / BIP32-Ed25519 derivation).
 *
 * <p>The circuit's computed child key bytes are read back from the witness (via wire ids) and
 * compared to the reference — a direct byte-for-byte equality check. The cheap hardened and
 * AP-injected soft steps run normally; the full soft step (computing {@code A = kL·B} in-circuit,
 * ~29M constraints) is gated behind {@code -Dzeroj.heavy}.</p>
 */
class Bip32Ed25519Test {

    private final HdKeyGenerator hd = new HdKeyGenerator();

    private static byte[] entropy(long seed) {
        byte[] e = new byte[32];
        new Random(seed).nextBytes(e);
        return e;
    }

    // ------------------------------------------------------------------
    // Hardened step (no scalar mult) vs cardano-client
    // ------------------------------------------------------------------

    @Test
    void hardened_matchesCardanoClient() {
        for (long s : new long[]{1, 2, 3, 4, 5}) {
            var root = hd.getRootKeyPairFromEntropy(entropy(s));
            long hardenedIndex = 1852L;
            var child = hd.getChildKeyPair(root, hardenedIndex, true);
            byte[] kL = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 0, 32);
            byte[] kR = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 32, 64);
            byte[] cc = root.getPrivateKey().getChainCode();
            assertDerivedMatches(kL, kR, cc, null, 0x80000000L + hardenedIndex, child);
        }
    }

    // ------------------------------------------------------------------
    // Soft step (AP injected) vs cardano-client
    // ------------------------------------------------------------------

    @Test
    void soft_withInjectedAp_matchesCardanoClient() {
        for (long s : new long[]{6, 7, 8, 9, 10}) {
            var root = hd.getRootKeyPairFromEntropy(entropy(s));
            var child = hd.getChildKeyPair(root, 0L, false);
            byte[] kL = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 0, 32);
            byte[] kR = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 32, 64);
            byte[] cc = root.getPrivateKey().getChainCode();
            byte[] ap = root.getPublicKey().getKeyData();
            assertDerivedMatches(kL, kR, cc, ap, 0L, child);
        }
    }

    // ------------------------------------------------------------------
    // Hardened step with the child NUMBER as an in-circuit WITNESS (4 LE bytes;
    // the gadget applies the hardening bit in-circuit)
    // ------------------------------------------------------------------

    @Test
    void hardened_variableNumber_matchesCardanoClient_andRejectsHardenedInput() {
        for (long n : new long[]{0L, 1L, 5L, 1000L, 0x7fffffffL}) {
            var root = hd.getRootKeyPairFromEntropy(entropy(40 + n));
            var child = hd.getChildKeyPair(root, n, true); // hardened derive of number n
            byte[] kL = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 0, 32);
            byte[] kR = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 32, 64);
            byte[] cc = root.getPrivateKey().getChainCode();

            int[][] ids = new int[3][];
            var builder = CircuitBuilder.create("bip32-hard-varnum-" + n);
            declareBytes(builder, "kL"); declareBytes(builder, "kR"); declareBytes(builder, "cc");
            for (int i = 0; i < 4; i++) builder.secretVar("num" + i);
            builder.define(api -> {
                Variable[] num = new Variable[4];
                for (int i = 0; i < 4; i++) num[i] = api.var("num" + i);
                var out = Bip32Ed25519.deriveHardened(api,
                        vars(api, "kL"), vars(api, "kR"), vars(api, "cc"), num);
                captureIds(out, ids);
            });
            Map<String, List<BigInteger>> in = new HashMap<>();
            putBytes(in, "kL", kL); putBytes(in, "kR", kR); putBytes(in, "cc", cc);
            for (int i = 0; i < 4; i++)
                in.put("num" + i, List.of(BigInteger.valueOf((n >>> (8 * i)) & 0xff)));
            BigInteger[] w = builder.calculateWitness(in, CurveId.BN254);
            assertChildMatches(w, ids, child);

            // an already-hardened value (MSB >= 0x80) must be rejected — hardening is the gadget's job
            in.put("num3", List.of(BigInteger.valueOf(0x80)));
            assertThrows(RuntimeException.class, () -> builder.calculateWitness(in, CurveId.BN254),
                    "pre-hardened number must violate the range constraint");
        }
        System.out.println("[account witness] variable hardened number validated vs cardano-client + pre-hardened rejected");
    }

    // ------------------------------------------------------------------
    // Soft step with the child index as an in-circuit WITNESS (4 LE bytes)
    // ------------------------------------------------------------------

    @Test
    void soft_variableIndex_matchesCardanoClient_andRejectsHardened() {
        for (long childIndex : new long[]{0L, 1L, 5L, 1000L, 0x7fffffffL}) {
            var root = hd.getRootKeyPairFromEntropy(entropy(20 + childIndex));
            var child = hd.getChildKeyPair(root, childIndex, false);
            byte[] kL = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 0, 32);
            byte[] kR = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 32, 64);
            byte[] cc = root.getPrivateKey().getChainCode();
            byte[] ap = root.getPublicKey().getKeyData();

            int[][] ids = new int[3][];
            var builder = CircuitBuilder.create("bip32-soft-varidx-" + childIndex);
            declareBytes(builder, "kL"); declareBytes(builder, "kR"); declareBytes(builder, "cc");
            declareBytes(builder, "ap");
            for (int i = 0; i < 4; i++) builder.secretVar("idx" + i);
            builder.define(api -> {
                Variable[] idx = new Variable[4];
                for (int i = 0; i < 4; i++) idx[i] = api.var("idx" + i);
                var out = Bip32Ed25519.deriveSoft(api,
                        vars(api, "kL"), vars(api, "kR"), vars(api, "cc"), vars(api, "ap"), idx);
                captureIds(out, ids);
            });
            Map<String, List<BigInteger>> in = new HashMap<>();
            putBytes(in, "kL", kL); putBytes(in, "kR", kR); putBytes(in, "cc", cc); putBytes(in, "ap", ap);
            for (int i = 0; i < 4; i++)
                in.put("idx" + i, List.of(BigInteger.valueOf((childIndex >>> (8 * i)) & 0xff)));
            BigInteger[] w = builder.calculateWitness(in, CurveId.BN254);
            assertChildMatches(w, ids, child);

            // a hardened index (MSB >= 0x80) must be rejected by the soft-index constraint
            in.put("idx3", List.of(BigInteger.valueOf(0x80)));
            assertThrows(RuntimeException.class, () -> builder.calculateWitness(in, CurveId.BN254),
                    "hardened index must violate the soft-index range constraint");
        }
        System.out.println("[role/index witness] variable soft index validated vs cardano-client + hardened rejected");
    }

    // ------------------------------------------------------------------
    // Full soft step computing AP in-circuit (~29M constraints) — heavy, gated
    // ------------------------------------------------------------------

    @Test
    @EnabledIfSystemProperty(named = "zeroj.heavy", matches = "true")
    void soft_computingApInCircuit_matchesCardanoClient() {
        var root = hd.getRootKeyPairFromEntropy(entropy(42));
        var child = hd.getChildKeyPair(root, 0L, false);
        byte[] kL = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 0, 32);
        byte[] kR = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 32, 64);
        byte[] cc = root.getPrivateKey().getChainCode();

        int[][] ids = new int[3][];
        var builder = CircuitBuilder.create("bip32-soft-full");
        declareBytes(builder, "kL"); declareBytes(builder, "kR"); declareBytes(builder, "cc");
        builder.define(api -> {
            var out = Bip32Ed25519.deriveSoftComputingAp(api,
                    vars(api, "kL"), vars(api, "kR"), vars(api, "cc"), 0L);
            captureIds(out, ids);
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "kL", kL); putBytes(in, "kR", kR); putBytes(in, "cc", cc);
        BigInteger[] w = builder.calculateWitness(in, CurveId.BN254);
        assertChildMatches(w, ids, child);
    }

    @Test
    void constraintCount_hardened_reported() {
        var builder = CircuitBuilder.create("bip32-hard-cost");
        declareBytes(builder, "kL"); declareBytes(builder, "kR"); declareBytes(builder, "cc");
        builder.define(api -> Bip32Ed25519.deriveHardened(api,
                vars(api, "kL"), vars(api, "kR"), vars(api, "cc"), 0x80000000L));
        int c = builder.compileR1CS(CurveId.BN254).numConstraints();
        System.out.println("[ADR-0027 M6] BIP32 hardened step constraints = " + c);
        assertTrue(c > 100_000 && c < 3_000_000);
    }

    // ------------------------------------------------------------------
    // shared harness: read circuit-computed child bytes back and compare
    // ------------------------------------------------------------------

    private void assertDerivedMatches(byte[] kL, byte[] kR, byte[] cc, byte[] ap, long childIndex,
                                      com.bloxbean.cardano.client.crypto.bip32.HdKeyPair child) {
        boolean soft = ap != null;
        int[][] ids = new int[3][];
        var builder = CircuitBuilder.create("bip32-" + (soft ? "soft" : "hard") + "-" + childIndex);
        declareBytes(builder, "kL"); declareBytes(builder, "kR"); declareBytes(builder, "cc");
        if (soft) declareBytes(builder, "ap");
        builder.define(api -> {
            Bip32Ed25519.ChildKey out = soft
                    ? Bip32Ed25519.deriveSoft(api, vars(api, "kL"), vars(api, "kR"), vars(api, "cc"), vars(api, "ap"), childIndex)
                    : Bip32Ed25519.deriveHardened(api, vars(api, "kL"), vars(api, "kR"), vars(api, "cc"), childIndex);
            captureIds(out, ids);
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "kL", kL); putBytes(in, "kR", kR); putBytes(in, "cc", cc);
        if (soft) putBytes(in, "ap", ap);
        BigInteger[] w = builder.calculateWitness(in, CurveId.BN254);
        assertChildMatches(w, ids, child);
    }

    private static void assertChildMatches(BigInteger[] w, int[][] ids,
                                           com.bloxbean.cardano.client.crypto.bip32.HdKeyPair child) {
        byte[] exKL = Arrays.copyOfRange(child.getPrivateKey().getKeyData(), 0, 32);
        byte[] exKR = Arrays.copyOfRange(child.getPrivateKey().getKeyData(), 32, 64);
        byte[] exCC = child.getPrivateKey().getChainCode();
        assertArrayEquals(exKL, readBytes(w, ids[0]), "kL' mismatch");
        assertArrayEquals(exKR, readBytes(w, ids[1]), "kR' mismatch");
        assertArrayEquals(exCC, readBytes(w, ids[2]), "chainCode' mismatch");
    }

    private static void captureIds(Bip32Ed25519.ChildKey out, int[][] ids) {
        int[] a = new int[32], b = new int[32], c = new int[32];
        for (int i = 0; i < 32; i++) { a[i] = out.kL()[i].id(); b[i] = out.kR()[i].id(); c[i] = out.chainCode()[i].id(); }
        ids[0] = a; ids[1] = b; ids[2] = c;
    }

    private static byte[] readBytes(BigInteger[] w, int[] wireIds) {
        byte[] out = new byte[wireIds.length];
        for (int i = 0; i < wireIds.length; i++) out[i] = (byte) (w[wireIds[i]].intValue() & 0xff);
        return out;
    }

    private static void declareBytes(CircuitBuilder b, String name) {
        for (int i = 0; i < 32; i++) b.secretVar(name + i);
    }
    private static Variable[] vars(com.bloxbean.cardano.zeroj.circuit.CircuitAPI api, String name) {
        Variable[] v = new Variable[32];
        for (int i = 0; i < 32; i++) v[i] = api.var(name + i);
        return v;
    }
    private static void putBytes(Map<String, List<BigInteger>> in, String name, byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) in.put(name + i, List.of(BigInteger.valueOf(bytes[i] & 0xff)));
    }
}
