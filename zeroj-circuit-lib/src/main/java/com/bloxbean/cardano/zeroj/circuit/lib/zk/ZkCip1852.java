package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBytes;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.lib.ed25519.Cip1852Derivation;

import java.util.Objects;

/**
 * Symbolic CIP-1852 / BIP32-Ed25519 derivation adapter for annotation-based ({@code @ZKCircuit})
 * circuits. Wraps {@link Cip1852Derivation} so a wallet root extended key (three 32-byte
 * {@link ZkBytes}) derives to the 28-byte payment key hash — the account-ownership statement,
 * written concisely in the annotation DSL.
 *
 * <p><b>Cost:</b> the full path is ~90M constraints (three in-circuit Ed25519 scalar mults); see
 * ADR-0027 §6.1 / ADR-0028 on the proving envelope. The adapter is authoring sugar only.</p>
 */
public final class ZkCip1852 {

    private ZkCip1852() {}

    /**
     * Payment key hash of {@code m/1852'/1815'/account'/role/index} derived from the root extended
     * key. {@code rootKL}, {@code rootKR}, {@code rootChainCode} are 32-byte little-endian
     * {@link ZkBytes}; returns the 28-byte payment credential.
     */
    public static ZkBytes paymentKeyHash(ZkContext zk, ZkBytes rootKL, ZkBytes rootKR, ZkBytes rootChainCode,
                                         long account, long role, long index) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(rootKL, "rootKL");
        Objects.requireNonNull(rootKR, "rootKR");
        Objects.requireNonNull(rootChainCode, "rootChainCode");
        return ZkBytesSupport.toZkBytes(zk, Cip1852Derivation.paymentKeyHash(zk.builder().api(),
                ZkBytesSupport.toVariables(zk, rootKL),
                ZkBytesSupport.toVariables(zk, rootKR),
                ZkBytesSupport.toVariables(zk, rootChainCode),
                account, role, index));
    }

    /**
     * {@link #paymentKeyHash(ZkContext, ZkBytes, ZkBytes, ZkBytes, long, long, long)} with the two
     * soft path components as circuit inputs: {@code role} and {@code index} are 4-byte
     * little-endian {@link ZkBytes} (typically {@code @Secret} — the public {@code pkh} already
     * binds the statement, so the path stays private), gadget-constrained to soft indices
     * ({@code < 2^31}).
     */
    public static ZkBytes paymentKeyHash(ZkContext zk, ZkBytes rootKL, ZkBytes rootKR, ZkBytes rootChainCode,
                                         long account, ZkBytes role, ZkBytes index) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(rootKL, "rootKL");
        Objects.requireNonNull(rootKR, "rootKR");
        Objects.requireNonNull(rootChainCode, "rootChainCode");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(index, "index");
        return ZkBytesSupport.toZkBytes(zk, Cip1852Derivation.paymentKeyHash(zk.builder().api(),
                ZkBytesSupport.toVariables(zk, rootKL),
                ZkBytesSupport.toVariables(zk, rootKR),
                ZkBytesSupport.toVariables(zk, rootChainCode),
                account,
                ZkBytesSupport.toVariables(zk, role),
                ZkBytesSupport.toVariables(zk, index)));
    }

    /**
     * Fully path-parameterised variant: {@code account}, {@code role} and {@code index} are all
     * circuit inputs (4-byte little-endian {@link ZkBytes}, values {@code < 2^31}; the account is
     * the plain number — hardening is applied in-circuit). One circuit and one trusted setup
     * cover every {@code m/1852'/1815'/account'/role/index} address of a root key.
     */
    public static ZkBytes paymentKeyHash(ZkContext zk, ZkBytes rootKL, ZkBytes rootKR, ZkBytes rootChainCode,
                                         ZkBytes account, ZkBytes role, ZkBytes index) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(rootKL, "rootKL");
        Objects.requireNonNull(rootKR, "rootKR");
        Objects.requireNonNull(rootChainCode, "rootChainCode");
        Objects.requireNonNull(account, "account");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(index, "index");
        return ZkBytesSupport.toZkBytes(zk, Cip1852Derivation.paymentKeyHash(zk.builder().api(),
                ZkBytesSupport.toVariables(zk, rootKL),
                ZkBytesSupport.toVariables(zk, rootKR),
                ZkBytesSupport.toVariables(zk, rootChainCode),
                ZkBytesSupport.toVariables(zk, account),
                ZkBytesSupport.toVariables(zk, role),
                ZkBytesSupport.toVariables(zk, index)));
    }

    /** Payment key hash of a leaf key: {@code blake2b224(encode(kL·B))}. {@code leafKL} is 32 bytes. */
    public static ZkBytes leafKeyHash(ZkContext zk, ZkBytes leafKL) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(leafKL, "leafKL");
        return ZkBytesSupport.toZkBytes(zk, Cip1852Derivation.leafKeyHash(zk.builder().api(),
                ZkBytesSupport.toVariables(zk, leafKL)));
    }
}
