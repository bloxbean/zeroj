package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyGenerator;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyPair;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBytes;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Validates the {@link ZkCip1852} annotation adapter against cardano-client-lib through the
 * annotation-DSL surface ({@link ZkBytes} in/out). Heavy (~30M constraints for the leaf hash),
 * gated behind {@code -Dzeroj.heavy} — run via {@code :zeroj-circuit-lib:heavyGadgetTest}.
 */
class ZkCip1852Test {

    private final HdKeyGenerator hd = new HdKeyGenerator();

    @Test
    @EnabledIfSystemProperty(named = "zeroj.heavy", matches = "true")
    void leafKeyHashAdapter_matchesCardanoClient() {
        byte[] ent = new byte[32];
        new Random(1852).nextBytes(ent);
        HdKeyPair leaf = derivePath(ent, 0, 0, 0);
        byte[] leafKL = Arrays.copyOfRange(leaf.getPrivateKey().getKeyData(), 0, 32);
        byte[] expectedPkh = Blake2bUtil.blake2bHash224(leaf.getPublicKey().getKeyData());

        var circuit = CircuitBuilder.create("zk-cip1852-leaf");
        for (int i = 0; i < 32; i++) circuit.secretVar("kL_" + i);
        for (int i = 0; i < 28; i++) circuit.publicVar("pkh_" + i);
        circuit.defineSignals(c -> {
            var zk = new ZkContext(c);
            ZkCip1852.leafKeyHash(zk, ZkBytes.secret(c, "kL", 32)).assertEqual(ZkBytes.publicInput(c, "pkh", 28));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < 32; i++) in.put("kL_" + i, List.of(BigInteger.valueOf(leafKL[i] & 0xff)));
        for (int i = 0; i < 28; i++) in.put("pkh_" + i, List.of(BigInteger.valueOf(expectedPkh[i] & 0xff)));
        assertDoesNotThrow(() -> circuit.calculateWitness(in, CurveId.BN254),
                "ZkCip1852.leafKeyHash must reproduce the Cardano payment key hash");
    }

    private HdKeyPair derivePath(byte[] entropy, long account, long role, long index) {
        var root = hd.getRootKeyPairFromEntropy(entropy);
        var n1 = hd.getChildKeyPair(root, 1852L, true);
        var n2 = hd.getChildKeyPair(n1, 1815L, true);
        var n3 = hd.getChildKeyPair(n2, account, true);
        var n4 = hd.getChildKeyPair(n3, role, false);
        return hd.getChildKeyPair(n4, index, false);
    }
}
