package com.bloxbean.cardano.zeroj.onchain.julc.bbs.lib;

import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.OnchainLibrary;

import java.math.BigInteger;

/**
 * On-chain BBS {@code hash_to_scalar} for the {@code BLS12381G1-SHA-256} ciphersuite — the crux
 * primitive of an on-chain BBS {@code ProofVerify}. It reproduces RFC 9380
 * {@code expand_message_xmd(SHA-256)} with {@code len = 48}, then {@code OS2IP(uniform) mod r},
 * byte-for-byte with the off-chain {@code CfrgBbsCore.hashToScalar} in {@code zeroj-bbs} — a property
 * the module verifies by differential-testing this class in the Julc VM against a real presentation.
 *
 * <p>This is a fully reusable {@link OnchainLibrary} gadget: it takes only a message and a domain
 * separation tag, so any BBS on-chain validator can compose it for both the message→scalar mapping
 * and the Fiat–Shamir challenge, unchanged. The only baked-in choices are the ones fixed for the whole
 * SHA-256 ciphersuite (SHA-256 expand, {@code len = 48}, the BLS12-381 scalar field order) — which is
 * also the only BBS ciphersuite practical on Plutus, since the VM provides {@code sha2_256} and no
 * SHAKE builtin.</p>
 *
 * <p>Compiled to UPLC by the Julc annotation processor (referenced from a validator). Uses only
 * Plutus builtins: {@code sha2_256}, {@code appendByteString}, {@code xorByteString},
 * {@code sliceByteString}, {@code consByteString}, {@code replicateByte}, {@code byteStringToInteger}.</p>
 */
@OnchainLibrary
public final class BbsHashToScalar {

    private BbsHashToScalar() {}

    /**
     * {@code hash_to_scalar(message, dst)} for the SHA-256 ciphersuite (expand length 48, so
     * {@code ell = 2}). {@code dst} must be at most 255 bytes (BBS DSTs are).
     */
    public static BigInteger hashToScalar(byte[] message, byte[] dst) {
        // dst_prime = dst || I2OSP(len(dst), 1)
        byte[] dstPrime = Builtins.appendByteString(dst,
                Builtins.consByteString(Builtins.lengthOfByteString(dst), Builtins.emptyByteString()));
        byte[] zPad = Builtins.replicateByte(64L, 0L);                 // s_in_bytes = 64 zero bytes
        byte[] lenBytes = twoBytes(0L, 48L);                          // I2OSP(48, 2)

        // b_0 = H(zPad || msg || I2OSP(48,2) || I2OSP(0,1) || dst_prime)
        byte[] b0 = Builtins.sha2_256(cat(cat(cat(cat(zPad, message), lenBytes), oneByte(0L)), dstPrime));
        // b_1 = H(b_0 || I2OSP(1,1) || dst_prime)
        byte[] b1 = Builtins.sha2_256(cat(cat(b0, oneByte(1L)), dstPrime));
        // b_2 = H((b_0 XOR b_1) || I2OSP(2,1) || dst_prime)
        byte[] b2 = Builtins.sha2_256(cat(cat(Builtins.xorByteString(false, b0, b1), oneByte(2L)), dstPrime));

        // uniform = (b_1 || b_2)[0..48] = b_1(32) || b_2[0..16]
        byte[] uniform = cat(b1, Builtins.sliceByteString(0L, 16L, b2));
        return Builtins.byteStringToInteger(true, uniform).mod(scalarFieldOrder());
    }

    private static byte[] cat(byte[] a, byte[] b) {
        return Builtins.appendByteString(a, b);
    }

    private static byte[] oneByte(long b) {
        return Builtins.consByteString(b, Builtins.emptyByteString());
    }

    private static byte[] twoBytes(long hi, long lo) {
        return Builtins.consByteString(hi, oneByte(lo));
    }

    /** BLS12-381 scalar field order r (built from limbs — Julc can't parse a 77-digit literal). */
    private static BigInteger scalarFieldOrder() {
        BigInteger base = BigInteger.valueOf(1000000000000000000L);
        return BigInteger.valueOf(52435L).multiply(base)
                .add(BigInteger.valueOf(875175126190479447L)).multiply(base)
                .add(BigInteger.valueOf(740508185965837690L)).multiply(base)
                .add(BigInteger.valueOf(552500527637822603L)).multiply(base)
                .add(BigInteger.valueOf(658699938581184513L));
    }
}
