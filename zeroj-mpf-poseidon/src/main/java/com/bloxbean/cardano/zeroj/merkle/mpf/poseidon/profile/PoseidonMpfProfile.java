package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParameterFingerprint;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.util.Objects;

/** Cryptographic and persistence identity of {@code zeroj-poseidon-mpf-v1}. */
public final class PoseidonMpfProfile {
    public static final String PROFILE_ID = "zeroj-poseidon-mpf-v1";
    public static final String HASH_ALGORITHM_ID = "zeroj-poseidon-bls12-381-t3-a5-v1";
    public static final int DIGEST_BYTES = 32;
    public static final int KEY_PATH_NIBBLES = DIGEST_BYTES * 2;
    public static final int FIXED_DIGEST_CHUNKS = 3;
    public static final int RAW_BYTES_PER_CHUNK = 31;

    // The numeric values are unchanged from the pre-release implementation.
    public static final BigInteger DOMAIN_BYTES = BigInteger.valueOf(0x5a4d5046L);
    public static final BigInteger DOMAIN_LEAF = BigInteger.valueOf(0x5a4d5047L);
    public static final BigInteger DOMAIN_KEY_PATH = BigInteger.valueOf(0x5a4d5048L);
    public static final BigInteger DOMAIN_KEY_NULLIFIER = BigInteger.valueOf(0x5a4d5049L);
    public static final BigInteger DOMAIN_RAW_BYTES_V1 = BigInteger.valueOf(0x5a4d504aL);

    public static final PoseidonParams PARAMS = PoseidonParamsBLS12_381T3.INSTANCE;
    /** Frozen reviewed v1 parameter identity; changing constants requires a new profile id. */
    public static final String PARAMETER_FINGERPRINT =
            "4bf489f3a231cbdba3e9b8c2d21966e052bf9132b9ddf6529aa3f569297a8fc2";

    static {
        String actual = PoseidonParameterFingerprint.sha256(PARAMS);
        if (!PARAMETER_FINGERPRINT.equals(actual)) {
            throw new ExceptionInInitializerError(
                    "Poseidon MPF v1 parameter fingerprint changed: " + actual);
        }
    }

    private PoseidonMpfProfile() {}

    public static void requireSupported(PoseidonParams params) {
        Objects.requireNonNull(params, "params");
        if (params == PARAMS) return;
        if (!FieldConfig.BLS12_381.equals(params.field())
                || params.t() != 3 || params.alpha() != 5 || params.rf() != 8 || params.rp() != 57) {
            throw new IllegalArgumentException(
                    "Poseidon MPF v1 requires BLS12-381 Poseidon t=3, alpha=5 parameters");
        }
        if (!PARAMETER_FINGERPRINT.equals(PoseidonParameterFingerprint.sha256(params))) {
            throw new IllegalArgumentException("unsupported Poseidon MPF v1 parameter fingerprint");
        }
    }
}
