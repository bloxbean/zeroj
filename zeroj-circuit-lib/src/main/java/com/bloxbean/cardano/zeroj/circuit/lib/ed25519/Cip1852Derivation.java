package com.bloxbean.cardano.zeroj.circuit.lib.ed25519;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.lib.hash.Blake2b;

/**
 * In-circuit CIP-1852 address derivation: from a wallet <b>root</b> extended key, derives the
 * payment key hash of {@code m/1852'/1815'/account'/role/index} exactly as a Cardano wallet does,
 * composing the M1–M6 gadgets end to end.
 *
 * <p>The path is three hardened steps ({@code 1852'}, {@code 1815'}, {@code account'} — no EC op)
 * followed by two soft steps ({@code role}, {@code index} — each a fixed-base scalar mult for the
 * parent public key), then the leaf public key {@code A = kL_leaf·B} and its
 * {@code blake2b-224} hash (the Cardano payment credential).</p>
 *
 * <p>This is the "prove I know the seed/root key behind this address" statement's core: the
 * public output {@code pkh} is the address's payment credential; the witness is the root key.
 * <b>Cost:</b> three in-circuit scalar mults (~29M each) dominate — see ADR-0027 §6.1/M5 on the
 * proving envelope; correctness is validated at the witness level against cardano-client-lib.</p>
 */
public final class Cip1852Derivation {

    private Cip1852Derivation() {}

    /** Purpose 1852' and coin-type 1815' (hardened). */
    private static final long HARDENED = 0x80000000L;
    private static final long PURPOSE = HARDENED + 1852L;
    private static final long COIN = HARDENED + 1815L;

    /**
     * Derive the 28-byte payment key hash for {@code m/1852'/1815'/account'/role/index} from the
     * root extended key. Root {@code kL,kR,chainCode} are 32 little-endian bytes each.
     */
    public static Variable[] paymentKeyHash(CircuitAPI api, Variable[] rootKL, Variable[] rootKR,
                                            Variable[] rootChainCode, long account, long role, long index) {
        Bip32Ed25519.ChildKey n1 = Bip32Ed25519.deriveHardened(api, rootKL, rootKR, rootChainCode, PURPOSE);
        Bip32Ed25519.ChildKey n2 = Bip32Ed25519.deriveHardened(api, n1.kL(), n1.kR(), n1.chainCode(), COIN);
        Bip32Ed25519.ChildKey n3 = Bip32Ed25519.deriveHardened(api, n2.kL(), n2.kR(), n2.chainCode(), HARDENED + account);
        Bip32Ed25519.ChildKey n4 = Bip32Ed25519.deriveSoftComputingAp(api, n3.kL(), n3.kR(), n3.chainCode(), role);
        Bip32Ed25519.ChildKey leaf = Bip32Ed25519.deriveSoftComputingAp(api, n4.kL(), n4.kR(), n4.chainCode(), index);
        return leafKeyHash(api, leaf.kL());
    }

    /** Payment key hash of a leaf: {@code blake2b224(encode(kL·B))}. */
    public static Variable[] leafKeyHash(CircuitAPI api, Variable[] leafKL) {
        Variable[] scalarBits = bytesToBitsLE(api, leafKL);
        Variable[] pubkey = Ed25519Point.scalarMulFixedBaseBWindowed(api, scalarBits, 4).encode(); // 32 bytes
        return Blake2b.hash224(api, pubkey); // 28 bytes
    }

    private static Variable[] bytesToBitsLE(CircuitAPI api, Variable[] bytes) {
        Variable[] bits = new Variable[bytes.length * 8];
        for (int i = 0; i < bytes.length; i++) {
            Variable[] lb = api.toBinary(bytes[i], 8);
            System.arraycopy(lb, 0, bits, i * 8, 8);
        }
        return bits;
    }
}
