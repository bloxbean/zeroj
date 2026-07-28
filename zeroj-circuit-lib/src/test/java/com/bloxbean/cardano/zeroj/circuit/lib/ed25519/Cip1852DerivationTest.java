package com.bloxbean.cardano.zeroj.circuit.lib.ed25519;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyGenerator;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyPair;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSCompiler;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
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
 * M8 end-to-end validation: the composed {@link Cip1852Derivation} circuit reproduces the real
 * Cardano payment key hash of {@code m/1852'/1815'/account'/role/index}, cross-checked against
 * cardano-client-lib's HD derivation + {@code Blake2bUtil.blake2bHash224} (the actual Cardano
 * key-hash implementation).
 *
 * <p>These circuits are large (leaf hash ~30M, full path ~90M constraints), so both are gated
 * behind {@code -Dzeroj.heavy=true} and run via {@code :zeroj-circuit-lib:heavyGadgetTest}.</p>
 */
class Cip1852DerivationTest {

    private final HdKeyGenerator hd = new HdKeyGenerator();

    private static byte[] entropy(long seed) {
        byte[] e = new byte[32];
        new Random(seed).nextBytes(e);
        return e;
    }

    // ------------------------------------------------------------------
    // Leaf public-key-hash: kL_leaf -> blake2b224(encode(kL·B))
    // ------------------------------------------------------------------

    @Test
    @EnabledIfSystemProperty(named = "zeroj.heavy", matches = "true")
    void leafKeyHash_matchesCardanoClient() {
        HdKeyPair leaf = derivePath(entropy(3), 0, 0, 0);
        byte[] leafKL = Arrays.copyOfRange(leaf.getPrivateKey().getKeyData(), 0, 32);
        byte[] expectedPkh = Blake2bUtil.blake2bHash224(leaf.getPublicKey().getKeyData());

        int[][] idHolder = new int[1][];
        var builder = CircuitBuilder.create("leaf-pkh");
        declareBytes(builder, "kL");
        builder.define(api -> {
            Variable[] pkh = Cip1852Derivation.leafKeyHash(api, vars(api, "kL"));
            idHolder[0] = ids(pkh);
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "kL", leafKL);
        BigInteger[] w = builder.calculateWitness(in, CurveId.BN254);
        assertArrayEquals(expectedPkh, read(w, idHolder[0]), "leaf payment key hash mismatch");
        System.out.println("[ADR-0027 M8] leaf key-hash validated vs cardano-client Blake2bUtil");
    }

    // ------------------------------------------------------------------
    // Full path root -> m/1852'/1815'/0'/0/0 -> payment key hash
    // ------------------------------------------------------------------

    @Test
    @EnabledIfSystemProperty(named = "zeroj.heavy", matches = "true")
    void fullPath_paymentKeyHash_matchesCardanoClient() {
        long account = 0, role = 0, index = 0;
        byte[] ent = entropy(11);
        var root = hd.getRootKeyPairFromEntropy(ent);
        HdKeyPair leaf = derivePath(ent, account, role, index);
        byte[] expectedPkh = Blake2bUtil.blake2bHash224(leaf.getPublicKey().getKeyData());

        byte[] kL = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 0, 32);
        byte[] kR = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 32, 64);
        byte[] cc = root.getPrivateKey().getChainCode();

        int[][] idHolder = new int[1][];
        var builder = CircuitBuilder.create("cip1852-full");
        declareBytes(builder, "kL"); declareBytes(builder, "kR"); declareBytes(builder, "cc");
        builder.define(api -> {
            Variable[] pkh = Cip1852Derivation.paymentKeyHash(api,
                    vars(api, "kL"), vars(api, "kR"), vars(api, "cc"), account, role, index);
            idHolder[0] = ids(pkh);
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "kL", kL); putBytes(in, "kR", kR); putBytes(in, "cc", cc);
        BigInteger[] w = builder.calculateWitness(in, CurveId.BN254);
        assertArrayEquals(expectedPkh, read(w, idHolder[0]),
                "full CIP-1852 payment key hash mismatch vs cardano-client");
        System.out.println("[ADR-0027 M8] FULL m/1852'/1815'/0'/0/0 payment key hash validated vs cardano-client");
    }

    // ------------------------------------------------------------------

    @Test
    @EnabledIfSystemProperty(named = "zeroj.heavy", matches = "true")
    void constraintCount_fullPath_reported() {
        System.out.println("[ADR-0028] full CIP-1852 derivation constraints:");
        System.out.println("    windowed + deterministic mul + Fermat inverse = " + fullPathConstraints(false, false));
        System.out.println("    + hint inverse                                = " + fullPathConstraints(false, true));
        System.out.println("    + hint inverse + hint mul                     = " + fullPathConstraints(true, true));
    }

    /**
     * Stable large-compiler regression gate used by ADR-0034 and ADR-0038. Unlike the report
     * above this compiles only the reviewed default configuration, so it can be run after an
     * R1CS compiler change without building all three ~19M+ variants.
     */
    @Test
    @EnabledIfSystemProperty(named = "zeroj.heavy", matches = "true")
    void compiler_defaultProductionPath_constraintPin() {
        // Default/reviewed configuration: deterministic multiplication and hint inverse.
        // Hint multiplication remains explicitly audit-gated in Fe25519.
        int[] counts = fullPathConstraintCounts(false, true, true);
        assertEquals(18_754_215, counts[0],
                "stable default CIP-1852 constraint count");
        assertEquals(counts[1], counts[0],
                "the online resource controller changed the incumbent all-inline row count");
    }

    @Test
    @EnabledIfSystemProperty(named = "zeroj.heavy", matches = "true")
    void fullPath_withHints_stillMatchesCardanoClient() {
        boolean pm = com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519.USE_HINT_MUL;
        boolean pi = com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519.USE_HINT_INVERSE;
        try {
            com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519.USE_HINT_MUL = true;
            com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519.USE_HINT_INVERSE = true;
            fullPath_paymentKeyHash_matchesCardanoClient(); // same assertion, now with both hints on
            System.out.println("[ADR-0028] full derivation with hint mul + hint inverse validated vs cardano-client");
        } finally {
            com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519.USE_HINT_MUL = pm;
            com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519.USE_HINT_INVERSE = pi;
        }
    }

    private static int fullPathConstraints(boolean hintMul, boolean hintInv) {
        return fullPathConstraintCounts(hintMul, hintInv, false)[0];
    }

    private static int[] fullPathConstraintCounts(
            boolean hintMul, boolean hintInv, boolean compareIncumbent) {
        boolean pm = com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519.USE_HINT_MUL;
        boolean pi = com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519.USE_HINT_INVERSE;
        try {
            com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519.USE_HINT_MUL = hintMul;
            com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519.USE_HINT_INVERSE = hintInv;
            var builder = CircuitBuilder.create("cip1852-cost-" + hintMul + "-" + hintInv);
            for (int i = 0; i < 32; i++) builder.secretVar("kL" + i).secretVar("kR" + i).secretVar("cc" + i);
            builder.define(api -> {
                Variable[] kL = new Variable[32], kR = new Variable[32], cc = new Variable[32];
                for (int i = 0; i < 32; i++) { kL[i] = api.var("kL" + i); kR[i] = api.var("kR" + i); cc[i] = api.var("cc" + i); }
                Cip1852Derivation.paymentKeyHash(api, kL, kR, cc, 0, 0, 0);
            });
            int guarded = builder.compileR1CS(CurveId.BN254).numConstraints();
            if (!compareIncumbent) return new int[]{guarded};
            return new int[]{guarded, compileWithIncumbentInlining(builder)};
        } finally {
            com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519.USE_HINT_MUL = pm;
            com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519.USE_HINT_INVERSE = pi;
        }
    }

    /**
     * Test-only reflection bridge to the package-private differential policy. Keeping that
     * policy out of the public DSL API is more important than avoiding reflection in this
     * opt-in 19M-row regression test.
     */
    private static int compileWithIncumbentInlining(CircuitBuilder builder) {
        try {
            var graph = builder.constraintGraph();
            Class<?> policyClass = Class.forName(
                    "com.bloxbean.cardano.zeroj.circuit.r1cs.LinearInliningPolicy");
            var inlineAll = policyClass.getDeclaredMethod(
                    "inlineAll", com.bloxbean.cardano.zeroj.circuit.ConstraintGraph.class);
            inlineAll.setAccessible(true);
            Object policy = inlineAll.invoke(null, graph);

            var compile = R1CSCompiler.class.getDeclaredMethod(
                    "compile",
                    com.bloxbean.cardano.zeroj.circuit.ConstraintGraph.class,
                    FieldConfig.class,
                    policyClass);
            compile.setAccessible(true);
            return ((R1CSConstraintSystem) compile.invoke(
                    null, graph, FieldConfig.BN254, policy)).numConstraints();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("cannot invoke incumbent compiler policy", e);
        }
    }

    private HdKeyPair derivePath(byte[] entropy, long account, long role, long index) {
        var root = hd.getRootKeyPairFromEntropy(entropy);
        var n1 = hd.getChildKeyPair(root, 1852L, true);
        var n2 = hd.getChildKeyPair(n1, 1815L, true);
        var n3 = hd.getChildKeyPair(n2, account, true);
        var n4 = hd.getChildKeyPair(n3, role, false);
        return hd.getChildKeyPair(n4, index, false);
    }

    private static int[] ids(Variable[] v) {
        int[] r = new int[v.length];
        for (int i = 0; i < v.length; i++) r[i] = v[i].id();
        return r;
    }
    private static byte[] read(BigInteger[] w, int[] wireIds) {
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
