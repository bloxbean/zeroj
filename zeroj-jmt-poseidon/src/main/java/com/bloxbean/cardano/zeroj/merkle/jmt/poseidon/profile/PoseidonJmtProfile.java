package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParameterFingerprint;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.util.Objects;

/** Cryptographic and persistence identity of {@code zeroj-poseidon-jmt-v1}. */
public final class PoseidonJmtProfile {
    public static final String PROFILE_ID = "zeroj-poseidon-jmt-v1";
    public static final String HASH_ALGORITHM_ID = "zeroj-poseidon-bls12-381-t3-a5-jmt-v1";
    public static final String PROOF_CODEC_ID = "ccl-classic-jmt-proof-cbor-v1";
    public static final int DIGEST_BYTES = 32;
    public static final int KEY_NIBBLES = 64;
    public static final int RADIX = 16;
    public static final int BRANCH_LEVELS = 4;
    public static final int FIXED_DIGEST_CHUNKS = 3;
    public static final int RAW_BYTES_PER_CHUNK = 31;

    // Registry prefix is ASCII "ZJMT" followed by a 16-bit purpose code.
    public static final BigInteger DOMAIN_BYTES = domain(0x0001);
    public static final BigInteger DOMAIN_RAW_BYTES = domain(0x0002);
    public static final BigInteger DOMAIN_EMPTY = domain(0x0003);
    public static final BigInteger DOMAIN_LEAF = domain(0x0004);
    public static final BigInteger DOMAIN_BRANCH_LEVEL_0 = domain(0x0010);
    public static final BigInteger DOMAIN_BRANCH_LEVEL_1 = domain(0x0011);
    public static final BigInteger DOMAIN_BRANCH_LEVEL_2 = domain(0x0012);
    public static final BigInteger DOMAIN_BRANCH_LEVEL_3 = domain(0x0013);
    public static final BigInteger DOMAIN_KEY_PATH = domain(0x0020);
    public static final BigInteger DOMAIN_TRANSITION = domain(0x0030);

    public static final PoseidonParams PARAMS = PoseidonParamsBLS12_381T3.INSTANCE;
    /** Frozen reviewed v1 parameter identity; changing constants requires a new profile id. */
    public static final String PARAMETER_FINGERPRINT =
            "4bf489f3a231cbdba3e9b8c2d21966e052bf9132b9ddf6529aa3f569297a8fc2";

    static {
        String actual = PoseidonParameterFingerprint.sha256(PARAMS);
        if (!PARAMETER_FINGERPRINT.equals(actual)) {
            throw new ExceptionInInitializerError(
                    "Poseidon JMT v1 parameter fingerprint changed: " + actual);
        }
    }

    private static final BigInteger[] BRANCH_DOMAINS = {
            DOMAIN_BRANCH_LEVEL_0,
            DOMAIN_BRANCH_LEVEL_1,
            DOMAIN_BRANCH_LEVEL_2,
            DOMAIN_BRANCH_LEVEL_3
    };

    private PoseidonJmtProfile() {}

    public static BigInteger branchDomain(int level) {
        if (level < 0 || level >= BRANCH_DOMAINS.length) {
            throw new IllegalArgumentException("JMT binary branch level must be in [0, 3]");
        }
        return BRANCH_DOMAINS[level];
    }

    public static void requireSupported(PoseidonParams params) {
        Objects.requireNonNull(params, "params");
        if (params == PARAMS) return;
        if (!FieldConfig.BLS12_381.equals(params.field())
                || params.t() != 3 || params.alpha() != 5 || params.rf() != 8 || params.rp() != 57
                || !PARAMETER_FINGERPRINT.equals(PoseidonParameterFingerprint.sha256(params))) {
            throw new IllegalArgumentException(
                    "Poseidon JMT v1 requires the reviewed BLS12-381 t=3 alpha=5 parameter set");
        }
    }

    private static BigInteger domain(int purpose) {
        return new BigInteger("5a4a4d54" + String.format("%04x", purpose), 16);
    }
}
