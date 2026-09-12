package org.zeroj.merkle.jmt.poseidon.circuit;

import org.zeroj.circuit.Signal;
import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;

import java.math.BigInteger;
import java.util.Objects;

/** In-circuit 256-bit big-endian key decoding with an explicit scalar-canonicality proof. */
public final class ZkJmtCanonicalKey {
    private static final int[] MODULUS_NIBBLES = modulusNibbles();

    private ZkJmtCanonicalKey() {}

    /**
     * Constrains all 64 nibbles, proves the encoded integer is strictly below the BLS12-381
     * scalar modulus, and returns that exact integer as one field element. The strict comparison
     * prevents {@code x} and {@code x + p} from aliasing inside the circuit field.
     */
    public static ZkField decode(ZkContext zk, ZkArray<ZkUInt> nibbles) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(nibbles, "nibbles");
        if (nibbles.size() != PoseidonJmtProfile.KEY_NIBBLES) {
            throw new IllegalArgumentException("JMT key must contain exactly 64 nibbles");
        }
        Signal equalPrefix = zk.builder().constant(1);
        Signal less = zk.builder().constant(0);
        Signal accumulator = zk.builder().constant(0);
        for (int index = 0; index < nibbles.size(); index++) {
            ZkUInt nibble = Objects.requireNonNull(nibbles.get(index), "nibbles[" + index + "]");
            if (nibble.bits() != 4) {
                throw new IllegalArgumentException("JMT key nibbles must use four bits");
            }
            nibble.assertWellFormed();
            Signal modulusNibble = zk.builder().constant(MODULUS_NIBBLES[index]);
            Signal nibbleEqual = nibble.signal().isEqual(modulusNibble);
            Signal nibbleLess = nibble.signal().lessThan(modulusNibble, 5);
            less = less.or(equalPrefix.and(nibbleLess));
            equalPrefix = equalPrefix.and(nibbleEqual);
            accumulator = accumulator.mul(16).add(nibble.signal());
        }
        zk.builder().assertEqual(less, zk.builder().constant(1));
        return ZkField.wrap(zk, accumulator);
    }

    private static int[] modulusNibbles() {
        String hex = org.zeroj.circuit.FieldConfig.BLS12_381.prime()
                .toString(16);
        hex = "0".repeat(64 - hex.length()) + hex;
        int[] output = new int[64];
        for (int index = 0; index < output.length; index++) {
            output[index] = Character.digit(hex.charAt(index), 16);
        }
        return output;
    }
}
